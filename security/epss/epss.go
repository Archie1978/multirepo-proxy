// Package epss enriches vulnerabilities with the EPSS score (Exploit Prediction Scoring System).
// Source: https://www.first.org/epss/ — public API, no key required, no known rate limit.
// The EPSS score is the probability (0–1) that a CVE will be exploited in the next 30 days.
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"multirepo-proxy/security"
)

const apiURL = "https://api.first.org/data/v1/epss"

// Fetcher queries the FIRST.org EPSS API to enrich vulnerabilities.
type Fetcher struct {
	client *http.Client
}

// New creates an EPSS Fetcher with the specified timeout.
func New(timeout time.Duration) *Fetcher {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Fetcher{client: &http.Client{Timeout: timeout}}
}

// Enrich adds EPSS scores to vulnerabilities whose ID is a CVE.
// Non-CVE IDs (GHSA-*, etc.) are silently ignored.
// Returns the error so the caller can log it — enrichment
// is non-blocking: even on failure, the maximally enriched slice is returned.
func (f *Fetcher) Enrich(ctx context.Context, vulns []security.Vulnerability) ([]security.Vulnerability, error) {
	// Collect unique CVE IDs (duplicates across scanners give the same score).
	cveSet := make(map[string]struct{})
	for _, v := range vulns {
		if strings.HasPrefix(v.ID, "CVE-") {
			cveSet[v.ID] = struct{}{}
		}
	}
	if len(cveSet) == 0 {
		return vulns, nil
	}

	ids := make([]string, 0, len(cveSet))
	for id := range cveSet {
		ids = append(ids, id)
	}

	// Use a dedicated context with a fixed timeout to avoid being affected
	// by parent context exhaustion (slow NVD scan, rate-limit…).
	fetchCtx, cancel := context.WithTimeout(context.Background(), f.client.Timeout)
	defer cancel()

	scores, err := f.fetch(fetchCtx, ids)
	if err != nil {
		return vulns, err
	}

	result := make([]security.Vulnerability, len(vulns))
	copy(result, vulns)
	for i, v := range result {
		if s, ok := scores[v.ID]; ok {
			result[i].EPSS = s.score
			result[i].EPSSPercentile = s.percentile
		}
	}
	return result, nil
}

// ─────────────────────────────────────────────
// Appel API EPSS
// ─────────────────────────────────────────────

type epssEntry struct {
	score      float64
	percentile float64
}

func (f *Fetcher) fetch(ctx context.Context, ids []string) (map[string]epssEntry, error) {
	// The FIRST.org API requires literal commas: ?cve=CVE-x,CVE-y
	// url.Values.Encode() encodes them as %2C which causes a 404.
	// Example curl -X GET "https://api.first.org/data/v1/epss?cve=CVE-2021-40438,CVE-2019-16759"
	fullURL := apiURL + "?cve=" + strings.Join(ids, ",")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: status %d", resp.StatusCode)
	}

	var result epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("epss decode: %w", err)
	}

	out := make(map[string]epssEntry, len(result.Data))
	for _, d := range result.Data {
		score, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		out[d.CVE] = epssEntry{score: score, percentile: pct}
	}
	return out, nil
}

// ─────────────────────────────────────────────
// EPSS API v1 response structures
// ─────────────────────────────────────────────

type epssResponse struct {
	Status string     `json:"status"`
	Total  int        `json:"total"`
	Data   []epssData `json:"data"`
}

type epssData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`       // probability as string, e.g. "0.00175"
	Percentile string `json:"percentile"` // ex: "0.53362"
	Date       string `json:"date"`
}
