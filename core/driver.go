package core

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
)

// ─────────────────────────────────────────────
// Artifact
// ─────────────────────────────────────────────

// Artifact represents an artifact downloaded from upstream.
type Artifact struct {
	CacheKey    string
	RepoType    string
	Name        string
	Version     string
	URL         string
	ContentType string
	Data        []byte

	// Extra allows drivers to pass metadata between Resolve and Validate.
	Extra map[string]string

	// RequireHumanReview, if non-empty, forces the artifact to remain in "pending" status
	// and blocks any auto-approval. The value describes the reason (e.g. Cosign error).
	// Set by Validate() when a critical check fails without being fatal.
	RequireHumanReview string
}

// ─────────────────────────────────────────────
// RepoDriver
// ─────────────────────────────────────────────

// RepoDriver is the interface that every driver must implement.
// The Registry calls these methods in order to process each request.
// The Registry is generic — all business decisions live in the driver.
type RepoDriver interface {
	// Name returns the repo identifier ("apt", "go", "pip", "r"…).
	Name() string

	// Prefix returns the URL prefix handled by this driver ("/ubuntu/", "/go/"…).
	Prefix() string

	// Resolve parses the request and returns the Artifact to process.
	// Sentinel errors: ErrCacheHit, ErrNotFound, ErrSkip.
	Resolve(ctx context.Context, r *http.Request) (*Artifact, error)

	// QuarantineDecision returns the quarantine decision for this artifact.
	// This is the only place where the driver expresses its quarantine policy.
	// The Registry executes the decision without knowing file formats.
	//
	//   ModeNone  → serve directly (index, lightweight metadata)
	//   ModeSelf  → quarantine on the artifact's own CacheKey
	//   ModeGate  → access conditioned on approval of decision.GateKey
	QuarantineDecision(a *Artifact) QuarantineDecision

	// Validate checks the artifact's integrity (hash, magic bytes, GPG…).
	// Called before caching. Returns nil if valid.
	Validate(a *Artifact) error

	// OnQuarantine is called after the first successful Enqueue (ModeSelf).
	// Allows asynchronous side effects (dependency prefetch…).
	// The default implementation in BaseDriver does nothing.
	OnQuarantine(a *Artifact)

	// ServeApproved writes the HTTP response for an approved artifact.
	ServeApproved(w http.ResponseWriter, r *http.Request, a *Artifact, data []byte)

	// ServePending writes the HTTP response when the artifact is pending.
	ServePending(w http.ResponseWriter, r *http.Request, a *Artifact)
}

// ─────────────────────────────────────────────
// BaseDriver — default implementations
// ─────────────────────────────────────────────

// BaseDriver provides reusable default implementations.
// Drivers embed it and override only what they need.
type BaseDriver struct {
	RepoName   string
	RepoPrefix string
}

func (b *BaseDriver) Name() string   { return b.RepoName }
func (b *BaseDriver) Prefix() string { return b.RepoPrefix }

// QuarantineDecision default: ModeNone (serve directly).
// Drivers that need quarantine override this method.
func (b *BaseDriver) QuarantineDecision(a *Artifact) QuarantineDecision {
	return QuarantineDecision{Mode: ModeNone}
}

// OnQuarantine default: does nothing.
func (b *BaseDriver) OnQuarantine(a *Artifact) {}

// ServeApproved default: Content-Type + body.
func (b *BaseDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *Artifact, data []byte) {
	w.Header().Set("Content-Type", a.ContentType)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ServePending default: 202 + generic JSON message.
func (b *BaseDriver) ServePending(w http.ResponseWriter, r *http.Request, a *Artifact) {
	fmt.Println("=============================================>Serving pending response for artifact:", a.CacheKey)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"pending","message":"Package pending validation."}`))
}

// FetchUpstream downloads a URL and returns body + content-type.
func FetchUpstream(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, "", driverError("upstream error: " + resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	log.Printf("[fetch] upstream download url=%s bytes=%d content-type=%s", url, len(data), resp.Header.Get("Content-Type"))
	
	return data, resp.Header.Get("Content-Type"), err
}

// ─────────────────────────────────────────────
// Sentinel errors
// ─────────────────────────────────────────────

type driverError string

func (e driverError) Error() string { return string(e) }

const (
	ErrCacheHit = driverError("cache hit")
	ErrSkip     = driverError("skip")
	ErrNotFound = driverError("not found")
)
