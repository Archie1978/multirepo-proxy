// Package osv implements a vulnerability scanner via the OSV.dev API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"multirepo-proxy/security"
)

const apiURL = "https://api.osv.dev/v1/query"

// Scanner interroge l'API OSV (https://osv.dev).
type Scanner struct {
	client *http.Client
}

// New creates an OSV scanner with the specified timeout.
func New(timeout time.Duration) *Scanner {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Scanner{client: &http.Client{Timeout: timeout}}
}

func (s *Scanner) Name() string { return "OSV" }

// Scan queries OSV for a given package.
// Packages without a known ecosystem (e.g. docker) are ignored.
func (s *Scanner) Scan(ctx context.Context, pkg security.Package) ([]security.Vulnerability, error) {
	if pkg.Ecosystem == "" {
		return nil, nil
	}

	body, _ := json.Marshal(osvRequest{
		Version: pkg.Version,
		Package: osvPackage{Name: pkg.Name, Ecosystem: string(pkg.Ecosystem)},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: status %d", resp.StatusCode)
	}

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}

	return convertVulns(result.Vulns), nil
}

// ─────────────────────────────────────────────
// Structures API OSV
// ─────────────────────────────────────────────

type osvRequest struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string       `json:"id"`
	Summary   string       `json:"summary"`
	Details   string       `json:"details"`
	Aliases   []string     `json:"aliases"`
	Severity  []osvSev     `json:"severity"`
	Published string       `json:"published"`
	Refs      []osvRef     `json:"references"`
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"` // vecteur CVSS
}

type osvRef struct {
	URL string `json:"url"`
}

// ─────────────────────────────────────────────
// Conversion
// ─────────────────────────────────────────────

func convertVulns(vulns []osvVuln) []security.Vulnerability {
	out := make([]security.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		vuln := security.Vulnerability{
			ID:          v.ID,
			Source:      "OSV",
			Title:       v.Summary,
			Description: v.Details,
		}

		// Alias CVE as the first readable ID.
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				vuln.ID = alias
				break
			}
		}

		// CVSS v3 score (first found).
		for _, sev := range v.Severity {
			if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V3_1" {
				vuln.CVSS = security.CVSSBaseScore(sev.Score)
				vuln.Severity = security.SeverityFromCVSS(vuln.CVSS)
				break
			}
		}
		if vuln.Severity == "" {
			vuln.Severity = security.SeverityNone
		}

		// References
		for _, r := range v.Refs {
			if r.URL != "" {
				vuln.References = append(vuln.References, r.URL)
			}
		}

		// Publication date
		if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
			vuln.PublishedAt = t
		}

		out = append(out, vuln)
	}
	return out
}
