package goproxy

// GoDriver implements the GOPROXY protocol (Go Module Proxy Protocol).
// https://go.dev/ref/mod#goproxy-protocol
//
// Quarantine policy:
//   .zip   → quarantine (source archive compiled by go build)
//   list   → quarantine (influences version resolution)
//   .info  → direct (JSON {Version, Time} — pure metadata)
//   .mod   → direct (go.mod — text, no executable code)
//   @latest→ direct (redirects to .info)
//
// 503 behavior corrected:
//   The `go` client interprets 503 as a temporary network error
//   and gives up. For quarantined packages, we return 404
//   with an explicit body — the client falls back to the next proxy
//   in GOPROXY (e.g. direct) or fails cleanly with a message.
//   When the package is approved, subsequent requests receive 200.

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"multirepo-proxy/core"
)

type GoDriver struct {
	core.BaseDriver
	upstream string
}

func NewGoDriver(prefix, upstream string) *GoDriver {
	return &GoDriver{
		BaseDriver: core.BaseDriver{RepoName: "go", RepoPrefix: prefix},
		upstream:   strings.TrimRight(upstream, "/"),
	}
}

// ── RepoDriver ────────────────────────────────────────────────────────────────

func (d *GoDriver) Resolve(ctx context.Context, r *http.Request) (*core.Artifact, error) {
	relPath := strings.TrimPrefix(r.URL.Path, d.Prefix())
	upstreamURL := d.upstream + "/" + relPath

	data, ct, err := core.FetchUpstream(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	if ct == "" {
		ct = goContentType(relPath)
	}

	mod, version, _ := parseGoPath(relPath)

	return &core.Artifact{
		CacheKey:    "go/" + relPath,
		RepoType:    "go",
		Name:        mod,
		Version:     version,
		URL:         upstreamURL,
		ContentType: ct,
		Data:        data,
	}, nil
}

func (d *GoDriver) Validate(a *core.Artifact) error {
	switch {
	case strings.HasSuffix(a.CacheKey, "/@v/list"):
		return validateList(a)
	case strings.HasSuffix(a.CacheKey, ".zip"):
		return validateZip(a)
	}
	return nil
}

// validateList verifies that the list file contains at least one valid version.
// Expected format: one semver version per line, e.g.:
//
//	v1.9.0
//	v1.9.1
//	v2.0.0
//
// An empty file or one with no line resembling "v<semver>" is rejected —
// this indicates either a non-existent module or an upstream error response
// that should not be cached.
func validateList(a *core.Artifact) error {
	if len(a.Data) == 0 {
		return fmt.Errorf("list file is empty for module %q", a.Name)
	}
	lines := strings.Split(strings.TrimSpace(string(a.Data)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A Go version always starts with "v" followed by a digit
		if len(line) >= 2 && line[0] == 'v' && line[1] >= '0' && line[1] <= '9' {
			return nil // at least one valid version found
		}
	}
	return fmt.Errorf("list file for module %q contains no valid versions (got: %q)",
		a.Name, truncate(string(a.Data), 120))
}

func validateZip(a *core.Artifact) error {
	if len(a.Data) < 4 {
		return fmt.Errorf("zip too small (%d bytes)", len(a.Data))
	}
	// ZIP magic bytes: PK\x03\x04
	if a.Data[0] != 0x50 || a.Data[1] != 0x4B || a.Data[2] != 0x03 || a.Data[3] != 0x04 {
		return fmt.Errorf("not a valid ZIP (bad magic bytes: %02x%02x%02x%02x)",
			a.Data[0], a.Data[1], a.Data[2], a.Data[3])
	}
	return nil
}

// truncate cuts a string to maxLen characters for error messages.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// QuarantineDecision: only .zip (source archives) → ModeSelf.
//
// list, .info, .mod, @latest → ModeNone (metadata, no executable code).
// list is technically validated (see Validate) but not manually quarantined:
// the client needs it to resolve versions before requesting a .zip.
func (d *GoDriver) QuarantineDecision(a *core.Artifact) core.QuarantineDecision {
	if strings.HasSuffix(a.CacheKey, ".zip") {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	return core.QuarantineDecision{Mode: core.ModeNone}
}

func (d *GoDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *core.Artifact, data []byte) {
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ServePending returns 404 (not 503).
//
// Why 404 and not 503?
//   - 503: the `go` client treats it as a network error and gives up
//     immediately with "dial tcp: connection refused" or similar.
//   - 404 / 410: the `go` client falls back to the next proxy in GOPROXY
//     (e.g. "GOPROXY=http://my-proxy/go/,direct").
//   - By putting "direct" as fallback, the developer can still
//     build while the admin validates. Once approved, the proxy
//     serves the package from cache and "direct" is no longer consulted.
func (d *GoDriver) ServePending(w http.ResponseWriter, r *http.Request, a *core.Artifact) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Quarantine-Status", "pending")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w,
		"module %s@%s is pending approval by an administrator.\n"+
			"Configure GOPROXY=http://this-proxy/go/,direct to use direct as fallback.\n",
		a.Name, a.Version,
	)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseGoPath extracts module, version, kind from a GOPROXY path.
// "github.com/gin-gonic/gin/@v/v1.9.1.zip" → ("github.com/gin-gonic/gin", "v1.9.1", "zip")
func parseGoPath(relPath string) (mod, version, kind string) {
	if idx := strings.Index(relPath, "/@v/"); idx >= 0 {
		mod = relPath[:idx]
		rest := relPath[idx+4:]
		if dot := strings.LastIndex(rest, "."); dot >= 0 {
			version = rest[:dot]
			kind = rest[dot+1:]
		} else {
			version = rest
			kind = "list"
		}
		return
	}
	if idx := strings.Index(relPath, "/@latest"); idx >= 0 {
		mod = relPath[:idx]
		version = "latest"
		kind = "latest"
		return
	}
	mod = relPath
	return
}

func goContentType(relPath string) string {
	switch {
	case strings.HasSuffix(relPath, ".zip"):
		return "application/zip"
	case strings.HasSuffix(relPath, ".mod"):
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(relPath, ".info"), strings.HasSuffix(relPath, "@latest"):
		return "application/json"
	default:
		return "text/plain; charset=utf-8"
	}
}
