package core

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"multirepo-proxy/auth/userctx"
)

// scanWaitTimeout is the maximum duration an HTTP request waits for the
// security scan to complete before returning 202 (manual review).
const scanWaitTimeout = 90 * time.Second

// ─────────────────────────────────────────────
// QuarantineDecision — driver decision on artifact handling
// ─────────────────────────────────────────────

// QuarantineMode describes how the Registry should handle an artifact.
type QuarantineMode int

const (
	// ModeNone: serve directly, without quarantine.
	// E.g.: HTML index, lightweight metadata files.
	ModeNone QuarantineMode = iota

	// ModeSelf: this artifact is itself subject to quarantine.
	// The Registry creates a quarantine entry with its own CacheKey.
	// E.g.: apt .deb, Go .zip, PyPI .whl.metadata.
	ModeSelf

	// ModeGate: this artifact has no quarantine entry of its own,
	// but its access is conditioned on the approval of another artifact
	// identified by GateKey.
	// E.g.: PyPI .whl conditioned on the corresponding .whl.metadata.
	ModeGate
)

// QuarantineDecision is returned by the driver for each artifact.
type QuarantineDecision struct {
	Mode    QuarantineMode
	GateKey string // used only if Mode == ModeGate
}

// ─────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────

// Registry orchestrates all drivers.
// It receives each HTTP request, routes it to the right driver,
// and manages the cache and quarantine transparently.
// The Registry knows no specific file format —
// all business decisions are delegated to the drivers.
type Registry struct {
	drivers       []RepoDriver
	cache         CacheStore
	quarantine    *QuarantineStore
	checkAccess   func(groups []string, repoType string) bool // nil = open access
}

func NewRegistry(cache CacheStore, q *QuarantineStore) *Registry {
	return &Registry{cache: cache, quarantine: q}
}

// SetAccessChecker installs a group-based access checker.
// fn receives the user's groups and the requested repo type;
// it must return true if access is granted.
// If fn is nil (default), all access is allowed.
func (reg *Registry) SetAccessChecker(fn func(groups []string, repoType string) bool) {
	reg.checkAccess = fn
}

func (reg *Registry) Register(d RepoDriver) {
	reg.drivers = append(reg.drivers, d)
	log.Printf("[registry] registered driver %q on prefix %q", d.Name(), d.Prefix())
}

func (reg *Registry) Drivers() []RepoDriver { return reg.drivers }

// ServeHTTP — single entry point for all requests.
func (reg *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	driver := reg.route(r)
	if driver == nil {
		http.Error(w, "no driver for this path", http.StatusNotFound)
		return
	}

	// Group-level access control at the proxy level.
	if reg.checkAccess != nil {
		groups := userctx.Groups(r)
		if !reg.checkAccess(groups, driver.Name()) {
			http.Error(w, "access denied to this repository", http.StatusForbidden)
			return
		}
	}

	ctx := r.Context()

	// Short-circuit: if the artifact is already quarantined and cached,
	// skip an unnecessary upstream download.
	cacheKey := driver.Name() + "/" + strings.TrimPrefix(r.URL.Path, driver.Prefix())
	switch {
	case reg.quarantine.IsApproved(cacheKey):
		if data, ct, err := reg.cache.Get(cacheKey); err == nil {
			req, _ := reg.quarantine.GetByCacheKey(cacheKey)
			driver.ServeApproved(w, r, artifactFromRequest(req, cacheKey, ct), data)
			return
		}
	case reg.quarantine.IsPending(cacheKey):
		if req, err := reg.quarantine.GetByCacheKey(cacheKey); err == nil && reg.cache.Exists(cacheKey) {
			art := artifactFromRequest(req, cacheKey, req.ContentType)
			// Scan already done or no scanners → respond immediately.
			if reg.quarantine.OnEnqueue == nil || reg.quarantine.IsScanDone(req.ID) {
				driver.ServePending(w, r, art)
				return
			}
			// Scan still in progress → wait for decision.
			if reg.waitScan(ctx, req.ID, cacheKey) {
				if data, _, e := reg.cache.Get(cacheKey); e == nil {
					driver.ServeApproved(w, r, art, data)
					return
				}
			}
			driver.ServePending(w, r, art)
			return
		}
	}

	// 1. Resolve the artifact
	artifact, err := driver.Resolve(ctx, r)
	switch err {
	case nil:
		// ok
	case ErrCacheHit:
		return // driver already wrote the response
	case ErrNotFound:
		http.Error(w, "not found upstream", http.StatusNotFound)
		return
	case ErrSkip:
		http.Error(w, "no driver matched", http.StatusNotFound)
		return
	default:
		log.Printf("[registry][%s] resolve error: %v", driver.Name(), err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// 2. Ask the driver for its quarantine decision
	decision := driver.QuarantineDecision(artifact)

	switch decision.Mode {

	case ModeNone:
		// Serve directly — validate then cache
		reg.serveDirectly(w, r, driver, artifact)

	case ModeSelf:
		// This artifact is subject to its own quarantine
		reg.handleSelfQuarantine(w, r, driver, artifact)

	case ModeGate:
		// Access conditioned on approval of another artifact
		reg.handleGateQuarantine(w, r, driver, artifact, decision.GateKey)
	}
}

// handleSelfQuarantine handles an artifact subject to its own quarantine.
func (reg *Registry) handleSelfQuarantine(w http.ResponseWriter, r *http.Request, driver RepoDriver, artifact *Artifact) {
	switch {
	case reg.quarantine.IsApproved(artifact.CacheKey):
		data, _, err := reg.cache.Get(artifact.CacheKey)
		if err != nil {
			reg.serveDirectly(w, r, driver, artifact)
			return
		}
		driver.ServeApproved(w, r, artifact, data)

	case reg.quarantine.IsPending(artifact.CacheKey):
		driver.ServePending(w, r, artifact)

	default:
		// First pass: validate, cache, quarantine.
		if err := driver.Validate(artifact); err != nil {
			log.Printf("[registry][%s] validation failed for %q: %v", driver.Name(), artifact.CacheKey, err)
			http.Error(w, fmt.Sprintf("validation failed: %v", err), http.StatusBadGateway)
			return
		}
		if err := reg.cache.Set(artifact.CacheKey, artifact.Data, artifact.ContentType); err != nil {
			log.Printf("[registry][%s] cache write: %v", driver.Name(), err)
		}

		reqID, err := reg.quarantine.Enqueue(artifact)
		if err != nil {
			log.Printf("[registry][%s] quarantine enqueue: %v", driver.Name(), err)
			driver.ServePending(w, r, artifact)
			return
		}

		if reg.quarantine.IsApproved(artifact.CacheKey) {
			// Enqueue inherited approval from parent (e.g. Docker blob after manifest validation).
			driver.ServeApproved(w, r, artifact, artifact.Data)
			return
		}

		go driver.OnQuarantine(artifact)

		// If scanners are active, wait for the decision before responding.
		if reg.quarantine.OnEnqueue != nil {
			if reg.waitScan(r.Context(), reqID, artifact.CacheKey) {
				if data, _, e := reg.cache.Get(artifact.CacheKey); e == nil {
					driver.ServeApproved(w, r, artifact, data)
					return
				}
			}
		}

		driver.ServePending(w, r, artifact)
	}
}

// waitScan waits for the security scan to complete for reqID.
// Returns true if the package was approved, false otherwise (timeout, error, manual review).
// Subscribes BEFORE checking state to avoid missing the notification.
func (reg *Registry) waitScan(ctx context.Context, reqID, cacheKey string) bool {
	ch, cancel := reg.quarantine.SubscribeByID(reqID)
	defer cancel()

	// Fast-path: decision already made between enqueue and subscription.
	if reg.quarantine.IsApproved(cacheKey) {
		return true
	}
	if reg.quarantine.IsScanDone(reqID) {
		return false
	}

	select {
	case <-ch:
	case <-time.After(scanWaitTimeout):
	case <-ctx.Done():
		return false
	}

	return reg.quarantine.IsApproved(cacheKey)
}

// handleGateQuarantine handles an artifact whose access is conditioned
// on the approval of another artifact (GateKey).
func (reg *Registry) handleGateQuarantine(w http.ResponseWriter, r *http.Request, driver RepoDriver, artifact *Artifact, gateKey string) {
	switch {
	case reg.quarantine.IsApproved(gateKey):
		// Gate artifact approved → serve from cache
		data, _, err := reg.cache.Get(artifact.CacheKey)
		if err != nil {
			// Not yet cached → serve directly and cache
			reg.serveDirectly(w, r, driver, artifact)
			return
		}
		driver.ServeApproved(w, r, artifact, data)

	case reg.quarantine.IsPending(gateKey):
		// Gate pending → block
		driver.ServePending(w, r, artifact)

	default:
		// Gate unknown → cache the artifact and block
		// (the gate will be created by OnQuarantine of the .metadata)
		if err := reg.cache.Set(artifact.CacheKey, artifact.Data, artifact.ContentType); err != nil {
			log.Printf("[registry][%s] cache write: %v", driver.Name(), err)
		}
		driver.ServePending(w, r, artifact)
	}
}

// serveDirectly validates, caches and serves without quarantine.
func (reg *Registry) serveDirectly(w http.ResponseWriter, r *http.Request, driver RepoDriver, artifact *Artifact) {
	if err := driver.Validate(artifact); err != nil {
		http.Error(w, fmt.Sprintf("validation failed: %v", err), http.StatusBadGateway)
		return
	}
	_ = reg.cache.Set(artifact.CacheKey, artifact.Data, artifact.ContentType)
	driver.ServeApproved(w, r, artifact, artifact.Data)
}

func (reg *Registry) route(r *http.Request) RepoDriver {
	for _, d := range reg.drivers {
		if strings.HasPrefix(r.URL.Path, d.Prefix()) {
			return d
		}
	}
	return nil
}

// artifactFromRequest builds a minimal Artifact from a quarantine entry.
// Used for the cache short-circuit (avoids upstream download).
func artifactFromRequest(req *PackageRequest, cacheKey, contentType string) *Artifact {
	if req != nil {
		return &Artifact{
			CacheKey:    req.CacheKey,
			RepoType:    req.RepoType,
			Name:        req.Name,
			Version:     req.Version,
			URL:         req.URL,
			ContentType: contentType,
		}
	}
	return &Artifact{CacheKey: cacheKey, ContentType: contentType}
}
