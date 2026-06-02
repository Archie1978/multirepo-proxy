// Package nvd implements a vulnerability scanner via the NVD (NIST) API.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"multirepo-proxy/security"
)

const apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Scanner interroge l'API NVD v2 (https://nvd.nist.gov).
// Rate limits: 5 req/30s without key, 50 req/30s with key.
type Scanner struct {
	client   *http.Client
	apiKey   string
	mu       sync.Mutex
	lastCall time.Time
	interval time.Duration // minimum delay between calls
}

// New creates an NVD scanner.
// apiKey is optional (recommended for production).
func New(apiKey string, timeout time.Duration) *Scanner {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	interval := 6 * time.Second // 5 req/30s without key
	if apiKey != "" {
		interval = 700 * time.Millisecond // 50 req/30s with key
	}
	return &Scanner{
		client:   &http.Client{Timeout: timeout},
		apiKey:   apiKey,
		interval: interval,
	}
}

func (s *Scanner) Name() string { return "NVD" }

// Scan searches for CVEs associated with a package in the NVD database.
func (s *Scanner) Scan(ctx context.Context, pkg security.Package) ([]security.Vulnerability, error) {
	s.rateLimit()

	keyword := pkg.Name
	if pkg.Version != "" {
		keyword += " " + pkg.Version
	}

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "20")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("nvd: rate limit (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: status %d", resp.StatusCode)
	}

	var result nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}

	return convertVulns(result.Vulnerabilities), nil
}

// rateLimit waits if necessary to respect NVD API rate limits.
func (s *Scanner) rateLimit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if elapsed := time.Since(s.lastCall); elapsed < s.interval {
		time.Sleep(s.interval - elapsed)
	}
	s.lastCall = time.Now()
}

// ─────────────────────────────────────────────
// Structures API NVD v2
// ─────────────────────────────────────────────

type nvdResponse struct {
	Vulnerabilities []nvdItem `json:"vulnerabilities"`
}

type nvdItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSV3 `json:"cvssMetricV31"`
	V30 []nvdCVSSV3 `json:"cvssMetricV30"`
}

type nvdCVSSV3 struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type nvdReference struct {
	URL string `json:"url"`
}

// ─────────────────────────────────────────────
// Conversion
// ─────────────────────────────────────────────

func convertVulns(items []nvdItem) []security.Vulnerability {
	out := make([]security.Vulnerability, 0, len(items))
	for _, item := range items {
		cve := item.CVE
		vuln := security.Vulnerability{
			ID:     cve.ID,
			Source: "NVD",
		}

		// English description takes priority.
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				vuln.Title = truncate(d.Value, 200)
				vuln.Description = d.Value
				break
			}
		}

		// CVSS v3.1 score, then v3.0.
		metrics := cve.Metrics.V31
		if len(metrics) == 0 {
			metrics = cve.Metrics.V30
		}
		if len(metrics) > 0 {
			d := metrics[0].CVSSData
			vuln.CVSS = d.BaseScore
			vuln.Severity = security.Severity(strings.ToUpper(d.BaseSeverity))
			if vuln.Severity == "" {
				vuln.Severity = security.SeverityFromCVSS(vuln.CVSS)
			}
		} else {
			vuln.Severity = security.SeverityNone
		}

		// References.
		for _, r := range cve.References {
			if r.URL != "" {
				vuln.References = append(vuln.References, r.URL)
			}
		}

		// Publication date.
		if t, err := time.Parse("2006-01-02T15:04:05.000", cve.Published); err == nil {
			vuln.PublishedAt = t
		}

		out = append(out, vuln)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
