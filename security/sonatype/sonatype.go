// Package sonatype implements a vulnerability scanner via the Sonatype OSS Index API.
// Documentation: https://ossindex.sonatype.org/doc/rest
package sonatype

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"multirepo-proxy/security"
)

const apiURL = "https://ossindex.sonatype.org/api/v3/component-report"

// Scanner interroge l'API Sonatype OSS Index via le format Package URL (purl).
// A token is recommended (free at https://ossindex.sonatype.org).
// Limites : 128 req/24h anonyme, 16 req/s avec token.
type Scanner struct {
	client   *http.Client
	token    string
	mu       sync.Mutex
	lastCall time.Time
	interval time.Duration
}

// New creates a Sonatype OSS Index scanner.
// token is optional but strongly recommended to increase quotas.
func New(token string, timeout time.Duration) *Scanner {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// 16 req/s with token → 100ms minimum interval (very comfortable).
	// Without token: 128 req/24h → spacing at 3s to avoid exhausting the quota.
	interval := 3 * time.Second
	if token != "" {
		interval = 100 * time.Millisecond
	}
	return &Scanner{
		client:   &http.Client{Timeout: timeout},
		token:    token,
		interval: interval,
	}
}

func (s *Scanner) Name() string { return "Sonatype" }

// Scan queries OSS Index for a given package using the purl format.
// Packages without a known purl (e.g. docker) are ignored.
func (s *Scanner) Scan(ctx context.Context, pkg security.Package) ([]security.Vulnerability, error) {
	coord := buildPURL(pkg)
	if coord == "" {
		return nil, nil
	}

	s.rateLimit()

	body, _ := json.Marshal(ossRequest{Coordinates: []string{coord}})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sonatype query: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("sonatype: quota exceeded (429) — use a token or space out scans")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("sonatype: invalid token (401)")
	case http.StatusOK:
		// ok
	default:
		return nil, fmt.Errorf("sonatype: status %d", resp.StatusCode)
	}

	var results []ossComponent
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("sonatype decode: %w", err)
	}

	var all []security.Vulnerability
	for _, comp := range results {
		all = append(all, convertVulns(comp.Vulnerabilities)...)
	}
	return all, nil
}

// rateLimit waits if necessary to respect API rate limits.
func (s *Scanner) rateLimit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if elapsed := time.Since(s.lastCall); elapsed < s.interval {
		time.Sleep(s.interval - elapsed)
	}
	s.lastCall = time.Now()
}

// ─────────────────────────────────────────────
// Package URL (purl) — https://github.com/package-url/purl-spec
// ─────────────────────────────────────────────

// purlType maps an ecosystem to the purl type recognized by OSS Index.
// Returns "" for unsupported ecosystems (e.g. docker).
func purlType(eco security.Ecosystem) string {
	switch eco {
	case security.EcosystemGo:
		return "golang"
	case security.EcosystemPyPI:
		return "pypi"
	case security.EcosystemDebian:
		return "deb"
	case security.EcosystemCRAN:
		return "cran"
	case security.EcosystemNPM:
		return "npm"
	default:
		return ""
	}
}

// buildPURL construit le Package URL pour un package.
// Ex : "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
//
//	"pkg:pypi/requests@2.28.0"
//	"pkg:deb/curl@7.74.0"
func buildPURL(pkg security.Package) string {
	t := purlType(pkg.Ecosystem)
	if t == "" || pkg.Name == "" {
		return ""
	}
	// Pour Go, le Name est le chemin de module complet (ex: github.com/foo/bar).
	// Le purl spec encode les slashes dans le namespace/name — on les laisse tels quels
	// car Sonatype OSS Index les accepte directement.
	name := strings.ToLower(pkg.Name) // purl is case-insensitive
	if pkg.Version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", t, name, pkg.Version)
	}
	return fmt.Sprintf("pkg:%s/%s", t, name)
}

// ─────────────────────────────────────────────
// Structures API Sonatype OSS Index v3
// ─────────────────────────────────────────────

type ossRequest struct {
	Coordinates []string `json:"coordinates"`
}

type ossComponent struct {
	Coordinates     string         `json:"coordinates"`
	Description     string         `json:"description"`
	Reference       string         `json:"reference"`
	Vulnerabilities []ossVuln      `json:"vulnerabilities"`
}

type ossVuln struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"displayName"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	CVSSScore          float64  `json:"cvssScore"`
	CVSSVector         string   `json:"cvssVector"`
	CWE                string   `json:"cwe"`
	CVE                string   `json:"cve"`
	Reference          string   `json:"reference"`
	ExternalReferences []string `json:"externalReferences"`
}

// ─────────────────────────────────────────────
// Conversion
// ─────────────────────────────────────────────

func convertVulns(vulns []ossVuln) []security.Vulnerability {
	out := make([]security.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		// Prefer the official CVE as ID if available.
		id := v.CVE
		if id == "" {
			id = v.ID
		}

		// Score is provided directly — use CVSSBaseScore if the vector
		// is available to ensure consistency with other scanners.
		score := v.CVSSScore
		if v.CVSSVector != "" {
			if computed := security.CVSSBaseScore(v.CVSSVector); computed > 0 {
				score = computed
			}
		}

		refs := make([]string, 0, len(v.ExternalReferences)+1)
		if v.Reference != "" {
			refs = append(refs, v.Reference)
		}
		refs = append(refs, v.ExternalReferences...)

		out = append(out, security.Vulnerability{
			ID:          id,
			Source:      "Sonatype",
			Title:       v.Title,
			Description: v.Description,
			CVSS:        score,
			CWE:         v.CWE,
			Severity:    security.SeverityFromCVSS(score),
			References:  refs,
		})
	}
	return out
}
