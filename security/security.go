package security

import (
	"context"
	"math"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────

// Ecosystem identifies the package ecosystem for scanners.
type Ecosystem string

const (
	EcosystemGo     Ecosystem = "Go"
	EcosystemPyPI   Ecosystem = "PyPI"
	EcosystemDebian Ecosystem = "Debian"
	EcosystemCRAN   Ecosystem = "CRAN"
	EcosystemNPM    Ecosystem = "npm"
)

// Package describes a package to be analyzed.
type Package struct {
	Name      string
	Version   string
	Ecosystem Ecosystem
}

// Severity represents the criticality of a vulnerability.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// Vulnerability describes a known vulnerability.
type Vulnerability struct {
	ID             string    `json:"id"`
	Source         string    `json:"source"`
	Severity       Severity  `json:"severity"`
	CVSS           float64   `json:"cvss"`
	CWE            string    `json:"cwe,omitempty"`
	EPSS           float64   `json:"epss,omitempty"`            // exploitation probability (0–1)
	EPSSPercentile float64   `json:"epss_percentile,omitempty"` // percentile among all known CVEs
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	References     []string  `json:"references"`
	PublishedAt    time.Time `json:"published_at,omitempty"`
}

// ─────────────────────────────────────────────
// Scanner interface
// ─────────────────────────────────────────────

// Scanner is the interface implemented by each vulnerability source.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, pkg Package) ([]Vulnerability, error)
}

// ─────────────────────────────────────────────
// MultiScanner — parallel fan-out
// ─────────────────────────────────────────────

// MultiScanner queries multiple scanners in parallel and deduplicates by Source+ID.
type MultiScanner struct {
	scanners []Scanner
}

func NewMultiScanner(scanners ...Scanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

func (m *MultiScanner) Scan(ctx context.Context, pkg Package) ([]Vulnerability, error) {
	type result struct {
		vulns []Vulnerability
	}
	ch := make(chan result, len(m.scanners))
	for _, s := range m.scanners {
		s := s
		go func() {
			v, _ := s.Scan(ctx, pkg)
			ch <- result{v}
		}()
	}
	seen := map[string]bool{}
	var all []Vulnerability
	for range m.scanners {
		r := <-ch
		for _, v := range r.vulns {
			key := v.Source + ":" + v.ID
			if !seen[key] {
				seen[key] = true
				all = append(all, v)
			}
		}
	}
	return all, nil
}

// EcosystemFor returns the ecosystem for a driver type.
func EcosystemFor(repoType string) Ecosystem {
	switch repoType {
	case "go":
		return EcosystemGo
	case "pip":
		return EcosystemPyPI
	case "apt":
		return EcosystemDebian
	case "r":
		return EcosystemCRAN
	case "npm":
		return EcosystemNPM
	default:
		return ""
	}
}

// SeverityFromCVSS returns the severity level based on the CVSS v3 score.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ─────────────────────────────────────────────
// CVSS v3 base score calculator
// ─────────────────────────────────────────────

// CVSSBaseScore computes the CVSS v3.x base score from a vector string.
// Returns 0 if the vector is invalid or not v3.
// Ex: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8
func CVSSBaseScore(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0
	}
	m := make(map[string]string)
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	s := m["S"]

	var pr float64
	if s == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[m["PR"]]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}

	ic := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[m["C"]]
	ii := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[m["I"]]
	ia := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}[m["A"]]

	iscBase := 1 - (1-ic)*(1-ii)*(1-ia)

	var isc float64
	if s == "C" {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		isc = 6.42 * iscBase
	}

	if isc <= 0 {
		return 0
	}

	exploit := 8.22 * av * ac * pr * ui
	var raw float64
	if s == "C" {
		raw = math.Min(1.08*(isc+exploit), 10)
	} else {
		raw = math.Min(isc+exploit, 10)
	}
	return math.Ceil(raw*10) / 10
}
