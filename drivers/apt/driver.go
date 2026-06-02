package apt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"multirepo-proxy/core"
	"multirepo-proxy/drivers/apt/gpg"
)

// AptDriver proxies an apt/Ubuntu repository.
//
// Validation policy:
//   - /dists/** (Release, Packages, InRelease…) → direct, no quarantine
//     (apt itself verifies the GPG signature of the Release via InRelease)
//   - /pool/**/*.deb → full pipeline:
//     1. GPG verification of the embedded signature (_gpgorigin)
//     2. Cross-check MD5 against the Packages index
//     3. Quarantine for manual validation
//
// The Packages index is never refreshed automatically —
// only via RefreshIndex() called from the admin API.
type AptDriver struct {
	core.BaseDriver
	upstream string
	index    *packagesIndex
	verifier *gpg.Verifier // nil if GPG is disabled
}

// Config configures the apt driver.
type Config struct {
	// Prefix: URL prefix handled by this driver, e.g. "/ubuntu/"
	Prefix string

	// Upstream: upstream repository URL, e.g. "http://archive.ubuntu.com/ubuntu"
	Upstream string

	// GPG: GPG verification configuration.
	// If nil, GPG verification is disabled.
	GPG *GPGConfig
}

// GPGConfig configures GPG verification of .deb packages.
type GPGConfig struct {
	// KeyringDir: directory where imported public keys are stored.
	KeyringDir string

	// RejectUnsigned: if true, reject .deb packages without a _gpgorigin signature.
	// If false, unsigned packages pass into quarantine without GPG verification.
	RejectUnsigned bool
}

// NewAptDriver creates an apt driver with the given configuration.
func NewAptDriver(cfg Config) (*AptDriver, error) {
	d := &AptDriver{
		BaseDriver: core.BaseDriver{
			RepoName:   "apt",
			RepoPrefix: cfg.Prefix,
		},
		upstream: strings.TrimRight(cfg.Upstream, "/"),
		index:    newPackagesIndex(),
	}

	if cfg.GPG != nil {
		v, err := gpg.NewVerifier(gpg.Config{
			KeyringDir:     cfg.GPG.KeyringDir,
			RejectUnsigned: cfg.GPG.RejectUnsigned,
		})
		if err != nil {
			return nil, fmt.Errorf("init GPG verifier: %w", err)
		}
		d.verifier = v
	}

	return d, nil
}

// ── RepoDriver ────────────────────────────────────────────────────────────────

func (d *AptDriver) Resolve(ctx context.Context, r *http.Request) (*core.Artifact, error) {
	relPath := strings.TrimPrefix(r.URL.Path, d.Prefix())
	upstreamURL := d.upstream + "/" + relPath

	data, ct, err := core.FetchUpstream(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	if ct == "" {
		ct = detectContentType(relPath)
	}

	// Silently update the index when a Packages.gz passes through
	if strings.HasSuffix(relPath, "Packages.gz") {
		go d.index.load(data, true)
	}

	return &core.Artifact{
		CacheKey:    "apt/" + relPath,
		RepoType:    "apt",
		Name:        debName(relPath),
		Version:     debVersion(relPath),
		URL:         upstreamURL,
		ContentType: ct,
		Data:        data,
	}, nil
}

// Validate performs technical checks before quarantine:
//  1. GPG verification of the _gpgorigin signature (if verifier is configured)
//  2. MD5 verification against the Packages index (if index is available)
//
// If both checks pass, the artifact is technically sound.
// Business validation (do we want this package?) remains with the admin.
func (d *AptDriver) Validate(a *core.Artifact) error {
	if !strings.HasSuffix(a.CacheKey, ".deb") {
		return nil // index and metadata: no validation
	}

	// ── 1. GPG verification ──
	if d.verifier != nil {
		if err := d.verifier.VerifyDeb(a.Data); err != nil {
			if gpg.IsNoSignature(err) {
				// Unsigned package — let it pass into quarantine
				// with a warning prefix in the name for the admin
				a.Name = "[UNSIGNED] " + a.Name
			} else {
				// Invalid signature or unknown key → immediate rejection
				return fmt.Errorf("GPG: %w", err)
			}
		}
	}

	// ── 2. MD5 verification against the Packages index ──
	relPath := strings.TrimPrefix(a.CacheKey, "apt/")
	if expected := d.index.md5For(relPath); expected != "" {
		h := md5.Sum(a.Data) //nolint:gosec
		actual := hex.EncodeToString(h[:])
		if actual != expected {
			return fmt.Errorf("MD5 mismatch for %q: index=%s got=%s (possible tampering)", relPath, expected, actual)
		}
	}

	return nil
}

// QuarantineDecision: .deb packages are quarantined (ModeSelf).
// apt indexes (/dists/) are served directly (ModeNone).
func (d *AptDriver) QuarantineDecision(a *core.Artifact) core.QuarantineDecision {
	if strings.HasSuffix(a.CacheKey, ".deb") {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	return core.QuarantineDecision{Mode: core.ModeNone}
}

func (d *AptDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *core.Artifact, data []byte) {
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Write(data)
}

func (d *AptDriver) ServePending(w http.ResponseWriter, r *http.Request, a *core.Artifact) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "Package %s_%s pending administrator validation.\n", a.Name, a.Version)
}

// ── Admin actions ─────────────────────────────────────────────────────────────

// RefreshIndex re-downloads the Packages.gz from upstream.
// Only called via POST /admin/api/index/refresh — never automatically.
func (d *AptDriver) RefreshIndex(ctx context.Context, distrib, component, arch string) error {
	url := fmt.Sprintf("%s/dists/%s/%s/binary-%s/Packages.gz",
		d.upstream, distrib, component, arch)
	data, _, err := core.FetchUpstream(ctx, url)
	if err != nil {
		return fmt.Errorf("fetch Packages.gz: %w", err)
	}
	return d.index.load(data, true)
}

// AddGPGKey imports a public key into the verifier's keyring.
// Accepts ASCII-armored or binary GPG.
func (d *AptDriver) AddGPGKey(keyData []byte) error {
	if d.verifier == nil {
		return fmt.Errorf("GPG verification is not enabled on this driver")
	}
	return d.verifier.AddKey(keyData)
}

// ListGPGKeys returns the fingerprints of imported keys.
func (d *AptDriver) ListGPGKeys() []string {
	if d.verifier == nil {
		return nil
	}
	return d.verifier.ListKeys()
}

// ── packagesIndex ─────────────────────────────────────────────────────────────

type packagesIndex struct {
	mu      sync.RWMutex
	md5sums map[string]string // relative path → md5
}

func newPackagesIndex() *packagesIndex {
	return &packagesIndex{md5sums: make(map[string]string)}
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

	var filename, sum string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Filename: "):
			filename = strings.TrimPrefix(strings.TrimPrefix(line, "Filename: "), "./")
		case strings.HasPrefix(line, "MD5sum: "):
			sum = strings.TrimPrefix(line, "MD5sum: ")
		case line == "":
			if filename != "" && sum != "" {
				idx.md5sums[filename] = sum
			}
			filename, sum = "", ""
		}
	}
	return scanner.Err()
}

func (idx *packagesIndex) md5For(relPath string) string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.md5sums[relPath]
}

// ── helpers ───────────────────────────────────────────────────────────────────

func detectContentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".deb"):
		return "application/vnd.debian.binary-package"
	case strings.HasSuffix(path, ".gz"):
		return "application/gzip"
	case strings.HasSuffix(path, ".xz"):
		return "application/x-xz"
	default:
		return "text/plain; charset=utf-8"
	}
}

func debName(relPath string) string {
	parts := strings.Split(relPath, "/")
	base := parts[len(parts)-1]
	if i := strings.Index(base, "_"); i > 0 {
		return base[:i]
	}
	return base
}

func debVersion(relPath string) string {
	parts := strings.Split(relPath, "/")
	base := strings.TrimSuffix(parts[len(parts)-1], ".deb")
	segs := strings.Split(base, "_")
	if len(segs) >= 2 {
		return segs[1]
	}
	return ""
}
