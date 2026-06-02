package npm

// NpmDriver proxies the npm registry (https://registry.npmjs.org).
//
// Protocol:
//   GET /npm/:package              → full package metadata JSON (all versions)
//   GET /npm/:package/:version     → single-version metadata JSON
//   GET /npm/@scope/:package       → scoped package metadata
//   GET /npm/:package/-/:file.tgz  → tarball download
//
// Quarantine policy:
//   .tgz (tarballs) → ModeSelf   (compressed source, executed by the runtime)
//   metadata JSON   → ModeNone   (index, no executable code)
//
// URL rewriting:
//   dist.tarball fields in metadata JSON are rewritten to point to the proxy
//   so that npm/yarn/pnpm download tarballs through the quarantine pipeline.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"multirepo-proxy/core"
)

// NpmDriver proxies an npm-compatible registry.
type NpmDriver struct {
	core.BaseDriver
	upstream string
}

func NewNpmDriver(prefix, upstream string) *NpmDriver {
	return &NpmDriver{
		BaseDriver: core.BaseDriver{RepoName: "npm", RepoPrefix: prefix},
		upstream:   strings.TrimRight(upstream, "/"),
	}
}

// ── RepoDriver ────────────────────────────────────────────────────────────────

func (d *NpmDriver) Resolve(ctx context.Context, r *http.Request) (*core.Artifact, error) {
	relPath := strings.TrimPrefix(r.URL.Path, d.Prefix())

	// npm clients send POST requests for security audit endpoints.
	// Return empty responses — the proxy does its own vulnerability scanning.
	if r.Method == http.MethodPost {
		return &core.Artifact{
			CacheKey:    "npm/" + relPath,
			RepoType:    "npm",
			Name:        relPath,
			ContentType: "application/json",
			Data:        []byte(`{}`),
		}, nil
	}

	upstreamURL := d.upstream + "/" + relPath

	data, ct, err := core.FetchUpstream(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}

	isTarball := isTarballPath(relPath)

	if !isTarball {
		if ct == "" {
			ct = "application/json"
		}
		data = d.rewriteTarballs(data, r)
	} else {
		if ct == "" {
			ct = "application/octet-stream"
		}
	}

	name, version := parseNpmPath(relPath)

	return &core.Artifact{
		CacheKey:    "npm/" + relPath,
		RepoType:    "npm",
		Name:        name,
		Version:     version,
		URL:         upstreamURL,
		ContentType: ct,
		Data:        data,
	}, nil
}

func (d *NpmDriver) QuarantineDecision(a *core.Artifact) core.QuarantineDecision {
	if isTarballPath(strings.TrimPrefix(a.CacheKey, "npm/")) {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	return core.QuarantineDecision{Mode: core.ModeNone}
}

func (d *NpmDriver) Validate(a *core.Artifact) error {
	if !isTarballPath(strings.TrimPrefix(a.CacheKey, "npm/")) {
		return nil
	}
	return validateTarball(a)
}

// ServeApproved adds Content-Length for all responses.
func (d *NpmDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *core.Artifact, data []byte) {
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ServePending returns 503 with Retry-After.
// npm retries on 503, unlike pip which needs a 403.
func (d *NpmDriver) ServePending(w http.ResponseWriter, r *http.Request, a *core.Artifact) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w,
		`{"error":"Package %s@%s is pending administrator approval. Retry once approved."}`,
		a.Name, a.Version,
	)
}

// ── rewriteTarballs ───────────────────────────────────────────────────────────

// rewriteTarballs replaces every occurrence of the upstream base URL in the
// JSON metadata with the proxy URL, so npm downloads tarballs through the proxy.
func (d *NpmDriver) rewriteTarballs(data []byte, r *http.Request) []byte {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// proxyBase must NOT end with "/" so the replacement is a strict substitution.
	proxyBase := scheme + "://" + r.Host + strings.TrimRight(d.Prefix(), "/")
	return bytes.ReplaceAll(data, []byte(d.upstream), []byte(proxyBase))
}

// ── validateTarball ───────────────────────────────────────────────────────────

// validateTarball checks gzip magic bytes (npm tarballs are .tar.gz).
func validateTarball(a *core.Artifact) error {
	if len(a.Data) < 2 {
		return fmt.Errorf("tarball too small (%d bytes)", len(a.Data))
	}
	if a.Data[0] != 0x1f || a.Data[1] != 0x8b {
		return fmt.Errorf("not a valid gzip tarball (bad magic: %02x%02x)", a.Data[0], a.Data[1])
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isTarballPath returns true for paths that represent a .tgz download.
// e.g. "express/-/express-4.18.2.tgz" or "@scope/pkg/-/pkg-1.0.0.tgz"
func isTarballPath(relPath string) bool {
	return strings.Contains(relPath, "/-/") && strings.HasSuffix(relPath, ".tgz")
}

// parseNpmPath extracts package name and version from an npm path.
//
//	"express/-/express-4.18.2.tgz" → ("express", "4.18.2")
//	"@scope/pkg/-/pkg-1.0.0.tgz"  → ("@scope/pkg", "1.0.0")
//	"express/4.18.2"               → ("express", "4.18.2")
//	"express"                      → ("express", "")
func parseNpmPath(relPath string) (name, version string) {
	// Tarball: name/-/name-version.tgz
	if idx := strings.Index(relPath, "/-/"); idx >= 0 {
		name = relPath[:idx]
		filename := relPath[idx+3:]
		filename = strings.TrimSuffix(filename, ".tgz")
		// filename is "<pkgbasename>-<version>"; pkgbasename may differ for scoped packages
		pkgBase := name
		if i := strings.LastIndex(pkgBase, "/"); i >= 0 {
			pkgBase = pkgBase[i+1:] // "@scope/pkg" → "pkg"
		}
		if strings.HasPrefix(filename, pkgBase+"-") {
			version = filename[len(pkgBase)+1:]
		}
		return
	}
	// Version metadata: name/version
	parts := strings.SplitN(relPath, "/", 2)
	if len(parts) == 2 && !strings.HasPrefix(parts[0], "@") {
		return parts[0], parts[1]
	}
	// Scoped: @scope/pkg or @scope/pkg/version
	if strings.HasPrefix(relPath, "@") {
		parts2 := strings.SplitN(relPath, "/", 3)
		if len(parts2) >= 2 {
			name = parts2[0] + "/" + parts2[1]
			if len(parts2) == 3 {
				version = parts2[2]
			}
			return
		}
	}
	return relPath, ""
}
