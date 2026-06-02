package cran

// CRAN — Comprehensive R Archive Network
//
// Handled endpoints:
//   GET /cran/src/contrib/<package>_<version>.tar.gz   → source package
//   GET /cran/bin/windows/contrib/<version>/<pkg>.zip  → Windows binary
//   GET /cran/bin/macosx/.../<pkg>.tgz                 → macOS binary
//   GET /cran/src/contrib/PACKAGES                     → text index
//   GET /cran/src/contrib/PACKAGES.gz                  → compressed index
//   GET /cran/src/contrib/PACKAGES.rds                 → R serialized index
//   GET /cran/web/packages/<name>/index.html           → package HTML page
//
// Quarantine policy:
//   - PACKAGES, PACKAGES.gz, PACKAGES.rds → direct (index)
//   - *.tar.gz, *.zip, *.tgz              → quarantine
//
// Validation:
//   1. MD5 / SHA256 cross-check against the PACKAGES index (MD5sum or SHA256 field)
//   2. Verification that the archive is a valid tar.gz (magic bytes)

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"multirepo-proxy/core"
)

// CRANDriver proxies a CRAN mirror.
type CRANDriver struct {
	core.BaseDriver
	upstream string // e.g. "https://cran.r-project.org"
	index    *packagesIndex
}

func NewCRANDriver(prefix, upstream string) *CRANDriver {
	return &CRANDriver{
		BaseDriver: core.BaseDriver{RepoName: "r", RepoPrefix: prefix},
		upstream:   strings.TrimRight(upstream, "/"),
		index:      newPackagesIndex(),
	}
}

// ── RepoDriver ────────────────────────────────────────────────────────────────

func (d *CRANDriver) Resolve(ctx context.Context, r *http.Request) (*core.Artifact, error) {
	relPath := strings.TrimPrefix(r.URL.Path, d.Prefix())
	upstreamURL := d.upstream + "/" + relPath

	data, ct, err := core.FetchUpstream(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	if ct == "" {
		ct = cranContentType(relPath)
	}

	// Silently update the index when a PACKAGES* passes through
	if isPackagesIndex(relPath) {
		compressed := strings.HasSuffix(relPath, ".gz")
		go d.index.load(data, compressed)
	}

	name, version := cranPackageInfo(relPath)

	// Retrieve checksums from the index for validation
	var extra map[string]string
	if name != "" {
		md5sum, sha256sum := d.index.checksumsFor(name, version)
		if md5sum != "" || sha256sum != "" {
			extra = map[string]string{
				"md5":    md5sum,
				"sha256": sha256sum,
			}
		}
	}

	return &core.Artifact{
		CacheKey:    "r/" + relPath,
		RepoType:    "r",
		Name:        name,
		Version:     version,
		URL:         upstreamURL,
		ContentType: ct,
		Data:        data,
		Extra:       extra,
	}, nil
}

func (d *CRANDriver) Validate(a *core.Artifact) error {
	if !isCRANPackage(a.CacheKey) {
		return nil // index or HTML page
	}

	// 1. Verify tar.gz (\x1f\x8b) or zip (PK) magic bytes
	if err := validateArchiveMagic(a); err != nil {
		return err
	}

	// 2. Verify SHA256 if available (takes priority over MD5)
	if expected, ok := a.Extra["sha256"]; ok && expected != "" {
		h := sha256.Sum256(a.Data)
		actual := hex.EncodeToString(h[:])
		if actual != expected {
			return fmt.Errorf("SHA256 mismatch for %s_%s: index=%s got=%s",
				a.Name, a.Version, expected, actual)
		}
		return nil // SHA256 OK — no need to check MD5 too
	}

	// 3. Verify MD5 if available
	if expected, ok := a.Extra["md5"]; ok && expected != "" {
		h := md5.Sum(a.Data) //nolint:gosec
		actual := hex.EncodeToString(h[:])
		if actual != expected {
			return fmt.Errorf("MD5 mismatch for %s_%s: index=%s got=%s",
				a.Name, a.Version, expected, actual)
		}
	}

	return nil
}

// QuarantineDecision: R packages (tar.gz, zip, tgz) → ModeSelf.
// PACKAGES indexes and HTML pages → ModeNone.
func (d *CRANDriver) QuarantineDecision(a *core.Artifact) core.QuarantineDecision {
	if isCRANPackage(a.CacheKey) {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	return core.QuarantineDecision{Mode: core.ModeNone}
}

func (d *CRANDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *core.Artifact, data []byte) {
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Write(data)
}

func (d *CRANDriver) ServePending(w http.ResponseWriter, r *http.Request, a *core.Artifact) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "R package %s_%s pending administrator validation.\n", a.Name, a.Version)
}

// RefreshIndex re-downloads the PACKAGES file from upstream.
// Only called via POST /admin/api/index/refresh?repo=r
func (d *CRANDriver) RefreshIndex(ctx context.Context, contrib string) error {
	if contrib == "" {
		contrib = "src/contrib"
	}
	url := fmt.Sprintf("%s/%s/PACKAGES.gz", d.upstream, contrib)
	data, _, err := core.FetchUpstream(ctx, url)
	if err != nil {
		// Fallback to uncompressed PACKAGES
		url = fmt.Sprintf("%s/%s/PACKAGES", d.upstream, contrib)
		data, _, err = core.FetchUpstream(ctx, url)
		if err != nil {
			return fmt.Errorf("fetch PACKAGES: %w", err)
		}
		return d.index.load(data, false)
	}
	return d.index.load(data, true)
}

// ── packagesIndex — parse the CRAN PACKAGES file ─────────────────────────────
//
// DCF format (Debian Control File), separator = empty line.
// Useful fields:
//
//	Package: <name>
//	Version: <version>
//	MD5sum:  <hash>
//	SHA256:  <hash> (newer mirrors)

type pkgEntry struct {
	md5    string
	sha256 string
}

type packagesIndex struct {
	mu      sync.RWMutex
	entries map[string]*pkgEntry // "name_version" → checksums
}

func newPackagesIndex() *packagesIndex {
	return &packagesIndex{entries: make(map[string]*pkgEntry)}
}

func (idx *packagesIndex) load(data []byte, compressed bool) error {
	var scanner *bufio.Scanner
	if compressed {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer gr.Close()
		scanner = bufio.NewScanner(gr)
	} else {
		scanner = bufio.NewScanner(bytes.NewReader(data))
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	var name, version, md5sum, sha256sum string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "MD5sum: "):
			md5sum = strings.TrimPrefix(line, "MD5sum: ")
		case strings.HasPrefix(line, "SHA256: "):
			sha256sum = strings.TrimPrefix(line, "SHA256: ")
		case line == "":
			if name != "" && version != "" {
				key := name + "_" + version
				idx.entries[key] = &pkgEntry{md5: md5sum, sha256: sha256sum}
				// Also index by name alone for the latest version
				idx.entries[name] = &pkgEntry{md5: md5sum, sha256: sha256sum}
			}
			name, version, md5sum, sha256sum = "", "", "", ""
		}
	}
	// Last block without trailing empty line
	if name != "" && version != "" {
		key := name + "_" + version
		idx.entries[key] = &pkgEntry{md5: md5sum, sha256: sha256sum}
		idx.entries[name] = &pkgEntry{md5: md5sum, sha256: sha256sum}
	}
	return scanner.Err()
}

func (idx *packagesIndex) checksumsFor(name, version string) (md5sum, sha256sum string) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	key := name
	if version != "" {
		key = name + "_" + version
	}
	if e, ok := idx.entries[key]; ok {
		return e.md5, e.sha256
	}
	return "", ""
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// cranPackageInfo extracts the name and version from a CRAN path.
// E.g.: "src/contrib/ggplot2_3.5.1.tar.gz" → ("ggplot2", "3.5.1")
// E.g.: "bin/windows/contrib/4.4/Rcpp_1.0.12.zip" → ("Rcpp", "1.0.12")
func cranPackageInfo(relPath string) (name, version string) {
	parts := strings.Split(relPath, "/")
	filename := parts[len(parts)-1]

	for _, ext := range []string{".tar.gz", ".tgz", ".zip"} {
		if strings.HasSuffix(filename, ext) {
			base := filename[:len(filename)-len(ext)]
			idx := strings.LastIndex(base, "_")
			if idx > 0 {
				return base[:idx], base[idx+1:]
			}
			return base, ""
		}
	}
	return "", ""
}

func isCRANPackage(cacheKey string) bool {
	k := strings.TrimPrefix(cacheKey, "r/")
	return (strings.HasSuffix(k, ".tar.gz") ||
		strings.HasSuffix(k, ".tgz") ||
		strings.HasSuffix(k, ".zip")) &&
		(strings.Contains(k, "/contrib/") || strings.Contains(k, "src/"))
}

func isPackagesIndex(relPath string) bool {
	base := relPath
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		base = relPath[idx+1:]
	}
	return base == "PACKAGES" || base == "PACKAGES.gz" || base == "PACKAGES.rds"
}

func validateArchiveMagic(a *core.Artifact) error {
	if len(a.Data) < 4 {
		return fmt.Errorf("archive too small (%d bytes)", len(a.Data))
	}
	switch {
	case strings.HasSuffix(a.CacheKey, ".tar.gz") || strings.HasSuffix(a.CacheKey, ".tgz"):
		// gzip magic: \x1f\x8b
		if a.Data[0] != 0x1f || a.Data[1] != 0x8b {
			return fmt.Errorf("not a gzip archive (bad magic: %02x%02x)", a.Data[0], a.Data[1])
		}
	case strings.HasSuffix(a.CacheKey, ".zip"):
		// zip magic: PK\x03\x04
		if a.Data[0] != 0x50 || a.Data[1] != 0x4B {
			return fmt.Errorf("not a ZIP archive (bad magic: %02x%02x)", a.Data[0], a.Data[1])
		}
	}
	return nil
}

func cranContentType(relPath string) string {
	switch {
	case strings.HasSuffix(relPath, ".tar.gz"):
		return "application/gzip"
	case strings.HasSuffix(relPath, ".tgz"):
		return "application/gzip"
	case strings.HasSuffix(relPath, ".zip"):
		return "application/zip"
	case strings.HasSuffix(relPath, ".rds"):
		return "application/octet-stream"
	case strings.HasSuffix(relPath, ".html"):
		return "text/html; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}
