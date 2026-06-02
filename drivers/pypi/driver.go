package pypi

// PyPI Simple Repository API (PEP 503)
//
// New architecture — metadata extracted from the wheel itself:
//
//   A .whl is a ZIP containing <name>-<version>.dist-info/METADATA.
//   External .metadata files (PEP 658) are no longer used.
//
//   Flow:
//     1. pip requests GET /pypi/simple/fastapi/
//        → rewritten HTML page (local hrefs), served directly
//
//     2. pip requests GET /pypi/files/fastapi/0.136.3/fastapi-0.136.3-py3-none-any.whl
//        → downloaded from upstream
//        → SHA256 verified (from the #sha256= fragment in the simple page)
//        → METADATA extracted from the ZIP → dependencies parsed
//        → wheel + dependencies quarantined (ModeSelf)
//        → 503 to client
//
//     3. Admin approves the wheel in /admin/
//        → pip re-requests the wheel → 200 from cache
//
//   QuarantineDecision:
//     .whl, .tar.gz, .zip → ModeSelf  (quarantine on the file itself)
//     /simple/**           → ModeNone  (HTML index, always direct)

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"multirepo-proxy/core"
)

// PyPIDriver proxies PyPI (or a PEP 503-compatible mirror).
type PyPIDriver struct {
	core.BaseDriver
	upstream   string
	urlIndex   *urlIndex
	cache      core.CacheStore
	quarantine *core.QuarantineStore
}

func NewPyPIDriver(prefix, upstream string, cache core.CacheStore, q *core.QuarantineStore) *PyPIDriver {
	return &PyPIDriver{
		BaseDriver: core.BaseDriver{RepoName: "pip", RepoPrefix: prefix},
		upstream:   strings.TrimRight(upstream, "/"),
		urlIndex:   newURLIndex(),
		cache:      cache,
		quarantine: q,
	}
}

// ── RepoDriver ────────────────────────────────────────────────────────────────

func (d *PyPIDriver) Resolve(ctx context.Context, r *http.Request) (*core.Artifact, error) {
	relPath := strings.TrimPrefix(r.URL.Path, d.Prefix())
	if isSimplePage(relPath) {
		return d.resolveSimple(ctx, relPath)
	}
	return d.resolveFile(ctx, relPath)
}

func (d *PyPIDriver) resolveSimple(ctx context.Context, relPath string) (*core.Artifact, error) {
	upstreamURL := d.upstream + "/simple/" + strings.TrimPrefix(relPath, "simple/")
	data, ct, err := core.FetchUpstream(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	return &core.Artifact{
		CacheKey:    "pip/" + relPath,
		RepoType:    "pip",
		Name:        simplePagePackageName(relPath),
		URL:         upstreamURL,
		ContentType: ct,
		Data:        []byte(d.rewriteAndIndex(string(data))),
	}, nil
}

func (d *PyPIDriver) resolveFile(ctx context.Context, relPath string) (*core.Artifact, error) {
	filename := lastSegment(relPath)
	cacheKey := "pip/" + relPath
	pkgName, version := parseFilename(filename)

	// Already known (pending or approved) → load from cache
	if d.quarantine.IsPending(cacheKey) || d.quarantine.IsApproved(cacheKey) {
		if data, ct, err := d.cache.Get(cacheKey); err == nil {
			return &core.Artifact{
				CacheKey:    cacheKey,
				RepoType:    "pip",
				Name:        pkgName,
				Version:     version,
				ContentType: ct,
				Data:        data,
			}, nil
		}
	}

	// Find the upstream URL
	upstreamURL, expectedSHA256 := d.urlIndex.get(filename)
	if upstreamURL == "" {
		var err error
		upstreamURL, expectedSHA256, err = d.findURLFromSimple(ctx, filename)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve upstream URL for %q: %w", filename, err)
		}
	}

	data, ct, err := core.FetchUpstream(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	if ct == "" {
		ct = pypiContentType(filename)
	}

	extra := map[string]string{}
	if expectedSHA256 != "" {
		extra["sha256"] = expectedSHA256
	}

	return &core.Artifact{
		CacheKey:    cacheKey,
		RepoType:    "pip",
		Name:        pkgName,
		Version:     version,
		URL:         upstreamURL,
		ContentType: ct,
		Data:        data,
		Extra:       extra,
	}, nil
}

// ── QuarantineDecision ────────────────────────────────────────────────────────

// QuarantineDecision: wheels and sdists are quarantined (ModeSelf).
// /simple/** pages are served directly (ModeNone).
// No more ModeGate, no more external .metadata — everything goes through the wheel itself.
func (d *PyPIDriver) QuarantineDecision(a *core.Artifact) core.QuarantineDecision {
	if isSimplePage(strings.TrimPrefix(a.CacheKey, "pip/")) {
		return core.QuarantineDecision{Mode: core.ModeNone}
	}
	if isPyPIPackageFile(lastSegment(a.CacheKey)) {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	return core.QuarantineDecision{Mode: core.ModeNone}
}

// ── Validate ──────────────────────────────────────────────────────────────────

func (d *PyPIDriver) Validate(a *core.Artifact) error {
	if isSimplePage(strings.TrimPrefix(a.CacheKey, "pip/")) {
		return nil
	}
	if expected, ok := a.Extra["sha256"]; ok && expected != "" {
		if actual := hashSHA256Hex(a.Data); actual != expected {
			return fmt.Errorf("SHA256 mismatch: expected %s got %s", expected, actual)
		}
	}
	return nil
}

// ── OnQuarantine ──────────────────────────────────────────────────────────────

// OnQuarantine is called after the first Enqueue of a wheel.
// Extracts dependencies from the METADATA embedded in the ZIP
// and pre-fetches them into quarantine.
func (d *PyPIDriver) OnQuarantine(a *core.Artifact) {
	if !isPyPIPackageFile(lastSegment(a.CacheKey)) {
		return
	}
	// Extract METADATA from the wheel (ZIP)
	meta, err := extractWheelMetadata(a.Data)
	if err != nil {
		log.Printf("[pypi] cannot extract METADATA from %s: %v", a.CacheKey, err)
		return
	}
	deps := parseDependencies(meta)
	if len(deps) == 0 {
		return
	}
	log.Printf("[pypi] prefetching %d dependencies for %s==%s", len(deps), a.Name, a.Version)
	go d.prefetchDependencies(deps)
}

// ── prefetch ─────────────────────────────────────────────────────────────────

func (d *PyPIDriver) prefetchDependencies(deps []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for _, dep := range deps {
		dep := dep
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := d.prefetchOne(ctx, dep); err != nil {
				log.Printf("[pypi] prefetch %q: %v", dep, err)
			}
		}()
	}
	wg.Wait()
}

func (d *PyPIDriver) prefetchOne(ctx context.Context, depName string) error {
	normalized := normalizeName(depName)

	// Load the simple page to index available files
	pageURL := fmt.Sprintf("%s/simple/%s/", d.upstream, normalized)
	pageData, _, err := core.FetchUpstream(ctx, pageURL)
	if err != nil {
		return fmt.Errorf("fetch simple page: %w", err)
	}
	d.rewriteAndIndex(string(pageData))

	// Select the best wheel
	whlFile, whlURL := d.urlIndex.bestWheel(normalized)
	if whlFile == "" {
		return fmt.Errorf("no suitable wheel for %q", depName)
	}

	pkgName, version := parseFilename(whlFile)
	cacheKey := "pip/files/" + pkgName + "/" + version + "/" + whlFile

	// Already quarantined → skip
	if d.quarantine.IsPending(cacheKey) || d.quarantine.IsApproved(cacheKey) {
		return nil
	}

	// Download
	data, ct, err := core.FetchUpstream(ctx, whlURL)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", whlFile, err)
	}
	if ct == "" {
		ct = pypiContentType(whlFile)
	}

	// Verify SHA256
	if _, sha256 := d.urlIndex.get(whlFile); sha256 != "" {
		if actual := hashSHA256Hex(data); actual != sha256 {
			return fmt.Errorf("SHA256 mismatch for %s", whlFile)
		}
	}

	// Cache
	if err := d.cache.Set(cacheKey, data, ct); err != nil {
		return fmt.Errorf("cache write: %w", err)
	}

	// Enqueue in quarantine
	artifact := &core.Artifact{
		CacheKey:    cacheKey,
		RepoType:    "pip",
		Name:        pkgName,
		Version:     version,
		URL:         whlURL,
		ContentType: ct,
		Data:        data,
	}
	if _, err := d.quarantine.Enqueue(artifact); err != nil {
		return err
	}

	// Recursively trigger sub-dependencies
	if meta, err := extractWheelMetadata(data); err == nil {
		if subDeps := parseDependencies(meta); len(subDeps) > 0 {
			go d.prefetchDependencies(subDeps)
		}
	}

	return nil
}

// ── ServeApproved / ServePending ─────────────────────────────────────────────

func (d *PyPIDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *core.Artifact, data []byte) {
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Write(data)
}

func (d *PyPIDriver) ServePending(w http.ResponseWriter, r *http.Request, a *core.Artifact) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Quarantine-Status", "pending")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusForbidden)

	fmt.Fprintf(w,
		"Package pending administrator validation\n\n"+
			"Package %s==%s has been received and placed in quarantine.\n"+
			"An administrator must approve it before it becomes available.\n\n"+
			"Administration interface: http://<proxy-host>:8222/admin/\n\n"+
			"Re-run pip install once the package has been approved.\n",
		a.Name, a.Version,
	)
}

// ── extractWheelMetadata ──────────────────────────────────────────────────────

// extractWheelMetadata extracts the METADATA file from a wheel (ZIP).
// METADATA is in <name>-<version>.dist-info/METADATA.
func extractWheelMetadata(data []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a valid ZIP: %w", err)
	}
	for _, f := range r.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) == 2 &&
			strings.HasSuffix(parts[0], ".dist-info") &&
			parts[1] == "METADATA" {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(rc); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("METADATA not found in wheel")
}

// ── parseDependencies ─────────────────────────────────────────────────────────

// parseDependencies extracts package names from a METADATA file.
// Field: "Requires-Dist: <name><version_spec> [; extra == '...']"
// Optional extras are ignored.
func parseDependencies(metaData []byte) []string {
	var deps []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(metaData))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Requires-Dist:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "Requires-Dist:"))
		// Ignore optional dependencies (extras)
		if idx := strings.Index(value, ";"); idx >= 0 {
			if strings.Contains(value[idx+1:], "extra ==") {
				continue
			}
			value = strings.TrimSpace(value[:idx])
		}
		name := reDepName.FindString(value)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		deps = append(deps, name)
	}
	return deps
}

var reDepName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?`)

// ── rewriteAndIndex ───────────────────────────────────────────────────────────

var reHref = regexp.MustCompile(`(?i)href="([^"]+)"`)

// reDataAttr removes hash attributes for .metadata (PEP 658 / PEP 691).
// Without them, pip does not verify a hash for the external .metadata
// (which we no longer serve at all).
var reDataAttr = regexp.MustCompile(`(?i)\s*data-(?:dist-info-metadata|core-metadata)="[^"]*"`)

func (d *PyPIDriver) rewriteAndIndex(html string) string {
	// Remove external metadata attributes
	html = reDataAttr.ReplaceAllString(html, "")

	return reHref.ReplaceAllStringFunc(html, func(match string) string {
		m := reHref.FindStringSubmatch(match)
		if len(m) < 2 || !looksLikePyPIFileURL(m[1]) {
			return match
		}
		rawURL, fragment := splitFragment(m[1])
		sha256 := ""
		if strings.HasPrefix(fragment, "sha256=") {
			sha256 = fragment[7:]
		}
		filename := lastSegment(rawURL)
		if filename == "" || !isPyPIPackageFile(filename) {
			return match
		}
		d.urlIndex.set(filename, rawURL, sha256)

		pkgName, version := parseFilename(filename)
		if pkgName == "" {
			return match
		}

		cacheKey := "pip/files/" + pkgName + "/" + version + "/" + filename
		newHref := fmt.Sprintf("%sfiles/%s/%s/%s", d.Prefix(), pkgName, version, filename)

		// Only include the sha256 fragment if the package is already approved —
		// otherwise pip would verify the hash of our 503 response against the real hash.
		if fragment != "" && d.quarantine.IsApproved(cacheKey) {
			newHref += "#" + fragment
		}
		return fmt.Sprintf(`href="%s"`, newHref)
	})
}

// ── findURLFromSimple ─────────────────────────────────────────────────────────

func (d *PyPIDriver) findURLFromSimple(ctx context.Context, filename string) (url, sha256 string, err error) {
	pkgName, _ := parseFilename(filename)
	if pkgName == "" {
		return "", "", fmt.Errorf("cannot determine package name from %q", filename)
	}
	pageURL := fmt.Sprintf("%s/simple/%s/", d.upstream, normalizeName(pkgName))
	data, _, err := core.FetchUpstream(ctx, pageURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch simple page for %q: %w", pkgName, err)
	}
	d.rewriteAndIndex(string(data))
	url, sha256 = d.urlIndex.get(filename)
	if url == "" {
		return "", "", fmt.Errorf("file %q not found in simple page for %q", filename, pkgName)
	}
	return url, sha256, nil
}

// ── urlIndex ──────────────────────────────────────────────────────────────────

type urlEntry struct {
	url    string
	sha256 string
}

type urlIndex struct {
	mu      sync.RWMutex
	entries map[string]urlEntry // filename → entry
	byPkg   map[string][]string // normalized name → filenames
}

func newURLIndex() *urlIndex {
	return &urlIndex{
		entries: make(map[string]urlEntry),
		byPkg:   make(map[string][]string),
	}
}

func (idx *urlIndex) set(filename, url, sha256 string) {
	pkgName, _ := parseFilename(filename)
	norm := normalizeName(pkgName)
	idx.mu.Lock()
	idx.entries[filename] = urlEntry{url: url, sha256: sha256}
	if norm != "" {
		idx.byPkg[norm] = append(idx.byPkg[norm], filename)
	}
	idx.mu.Unlock()
}

func (idx *urlIndex) get(filename string) (url, sha256 string) {
	idx.mu.RLock()
	e := idx.entries[filename]
	idx.mu.RUnlock()
	return e.url, e.sha256
}

func (idx *urlIndex) bestWheel(normName string) (filename, url string) {
	idx.mu.RLock()
	files := idx.byPkg[normName]
	idx.mu.RUnlock()
	best, bestScore := "", -1
	for _, f := range files {
		if !strings.HasSuffix(f, ".whl") {
			continue
		}
		if s := wheelScore(f); s > bestScore {
			bestScore, best = s, f
		}
	}
	if best == "" {
		return "", ""
	}
	u, _ := idx.get(best)
	return best, u
}

func wheelScore(f string) int {
	f = strings.ToLower(f)
	switch {
	case strings.Contains(f, "py3-none-any") || strings.Contains(f, "py2.py3-none-any"):
		return 100
	case strings.Contains(f, "none-any"):
		return 80
	case strings.Contains(f, "cp3"):
		return 60
	default:
		return 10
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isSimplePage(relPath string) bool { return strings.HasPrefix(relPath, "simple/") }

func simplePagePackageName(relPath string) string {
	parts := strings.Split(strings.Trim(relPath, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return relPath
}

func looksLikePyPIFileURL(href string) bool {
	return strings.Contains(href, "pythonhosted.org") || strings.Contains(href, "/packages/")
}

func isPyPIPackageFile(filename string) bool {
	for _, ext := range []string{".whl", ".tar.gz", ".tar.bz2", ".zip", ".egg"} {
		if strings.HasSuffix(filename, ext) {
			return true
		}
	}
	return false
}

func lastSegment(u string) string {
	u = strings.TrimRight(u, "/")
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

func splitFragment(href string) (string, string) {
	if i := strings.Index(href, "#"); i >= 0 {
		return href[:i], href[i+1:]
	}
	return href, ""
}

func normalizeName(name string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-"))
}

func parseFilename(filename string) (name, version string) {
	for _, ext := range []string{".whl", ".tar.gz", ".tar.bz2", ".zip", ".egg"} {
		if strings.HasSuffix(filename, ext) {
			filename = filename[:len(filename)-len(ext)]
			break
		}
	}
	parts := strings.SplitN(filename, "-", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return filename, ""
}

func pypiContentType(filename string) string {
	switch {
	case strings.HasSuffix(filename, ".whl"), strings.HasSuffix(filename, ".zip"):
		return "application/zip"
	case strings.HasSuffix(filename, ".tar.gz"):
		return "application/gzip"
	case strings.HasSuffix(filename, ".tar.bz2"):
		return "application/x-bzip2"
	default:
		return "application/octet-stream"
	}
}
