package docker

// Docker driver — Distribution Specification v2 (OCI)
//
// Handled endpoints:
//   GET /docker/v2/                                  → version check (ping)
//   GET /docker/v2/<name>/manifests/<ref>             → manifest (tag or digest)
//   GET /docker/v2/<name>/blobs/sha256:<digest>       → binary layer
//   GET /docker/v2/<name>/tags/list                   → tag list
//   HEAD …                                            → same, without body
//
// Quarantine policy:
//   manifests      → ModeSelf   (define the image to run)
//   known blobs    → ModeSelf   (pre-fetched by OnQuarantine, key prefixed by manifest)
//   unknown blobs, ping, tags → ModeNone (fallback)
//
// Linked approval:
//   When a manifest is approved, approveLinked() in QuarantineStore automatically
//   approves all blobs whose cache key starts with the manifest key.
//   Convention: blob key = "<manifest key>/blobs/<digest>"
//   Example:
//     manifest → "docker/v2/library/nginx/manifests/latest"
//     blob     → "docker/v2/library/nginx/manifests/latest/blobs/sha256:abc…"
//
// Validation:
//   blobs     : SHA256 of content compared to the digest in the key (last segment /blobs/<digest>)
//   manifests : Docker-Content-Digest (upstream header) compared to the content
//
// Authentication:
//   Automatic Bearer token (WWW-Authenticate challenge).
//   Optional Username/Password credentials.
//   Tokens cached by scope.
//
// Digest index:
//   digestIndex map[string]string : "sha256:<hex>" → full canonical key
//   Rebuilt from quarantine on startup.
//   Allows finding the correct cache key when the client requests a blob by URL.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"multirepo-proxy/core"
)

// DockerDriver proxies a Docker v2 registry.
type DockerDriver struct {
	core.BaseDriver
	upstream   string
	username   string
	password   string
	cache      core.CacheStore
	quarantine *core.QuarantineStore

	mu     sync.Mutex
	tokens map[string]tokenEntry // scope → cached Bearer token

	blobMu      sync.RWMutex
	digestIndex map[string]string // "sha256:<hex>" → canonical manifest-prefixed key

	manifestMu    sync.RWMutex
	manifestIndex map[string]string // "sha256:<hex>" → canonical sub-manifest-prefixed key

	cosign *cosignVerifier // nil if disabled
}

type tokenEntry struct {
	value  string
	expiry time.Time
}

// Config configures the Docker driver.
type Config struct {
	// Prefix: URL prefix handled by this driver, e.g. "/docker/"
	Prefix string

	// Upstream: upstream registry URL, e.g. "https://registry-1.docker.io"
	Upstream string

	// Username / Password: optional credentials for registries
	// requiring authentication (Docker Hub, GHCR, private registries…).
	Username string
	Password string

	// Cosign: Cosign signature verification configuration.
	Cosign CosignConfig
}

// CosignConfig configures Cosign signature verification for this driver.
type CosignConfig struct {
	Enabled          bool
	PublicKeyFiles   []string // signature is valid if it matches at least one key
	RequireSignature bool
}

func NewDockerDriver(cfg Config, cache core.CacheStore, quarantine *core.QuarantineStore) *DockerDriver {
	d := &DockerDriver{
		BaseDriver:    core.BaseDriver{RepoName: "docker", RepoPrefix: cfg.Prefix},
		upstream:      strings.TrimRight(cfg.Upstream, "/"),
		username:      cfg.Username,
		password:      cfg.Password,
		cache:         cache,
		quarantine:    quarantine,
		tokens:        make(map[string]tokenEntry),
		digestIndex:   make(map[string]string),
		manifestIndex: make(map[string]string),
	}
	if cfg.Cosign.Enabled {
		v, err := newCosignVerifier(cfg.Cosign.PublicKeyFiles, cfg.Cosign.RequireSignature, d.fetchWithAuth)
		if err != nil {
			log.Printf("[docker] cosign: cannot initialize verifier: %v", err)
		} else {
			d.cosign = v
			log.Printf("[docker] cosign: signature verification enabled (keys=%d, require=%v)",
				len(cfg.Cosign.PublicKeyFiles), cfg.Cosign.RequireSignature)
		}
	}
	d.rebuildIndexes()
	return d
}

// rebuildIndexes scans quarantine at startup to rebuild
// digestIndex (blobs) and manifestIndex (sub-manifests of manifest lists).
func (d *DockerDriver) rebuildIndexes() {
	entries, err := d.quarantine.List(nil)
	if err != nil {
		return
	}
	d.blobMu.Lock()
	d.manifestMu.Lock()
	defer d.blobMu.Unlock()
	defer d.manifestMu.Unlock()
	for _, e := range entries {
		k := e.CacheKey
		if !strings.HasPrefix(k, "docker/") {
			continue
		}
		hasManifests := strings.Contains(k, "/manifests/")
		hasBlobs := strings.Contains(k, "/blobs/")
		// Pre-fetched blob: .../manifests/.../blobs/<digest>
		if hasManifests && hasBlobs {
			if idx := strings.LastIndex(k, "/blobs/"); idx >= 0 {
				d.digestIndex[k[idx+7:]] = k
			}
		}
		// Sub-manifest of a manifest list: .../manifests/<tag>/manifests/sha256:...
		if hasManifests && !hasBlobs && strings.Count(k, "/manifests/") >= 2 {
			if idx := strings.LastIndex(k, "/manifests/"); idx >= 0 {
				if digest := k[idx+11:]; strings.HasPrefix(digest, "sha256:") {
					d.manifestIndex[digest] = k
				}
			}
		}
		// Tag manifest (e.g. .../manifests/4.0.6-1): the SHA256 stored in
		// quarantine corresponds to the Docker-Content-Digest → allows resolving
		// digest-based requests to the tag key.
		if hasManifests && !hasBlobs && strings.Count(k, "/manifests/") == 1 && e.SHA256 != "" {
			d.manifestIndex[e.SHA256] = k
		}
	}
}

// ── RepoDriver ────────────────────────────────────────────────────────────────

func (d *DockerDriver) Resolve(ctx context.Context, r *http.Request) (*core.Artifact, error) {
	relPath := strings.TrimPrefix(r.URL.Path, d.Prefix())
	name, version := parseDockerPath(relPath)

	// Ping /v2/ — respond directly without upstream call.
	if isVersionCheck(relPath) {
		return &core.Artifact{
			CacheKey:    "docker/" + relPath,
			RepoType:    "docker",
			ContentType: "application/json",
			Data:        []byte(`{}`),
		}, nil
	}
	// Blobs — use the digest index to find the canonical manifest-prefixed key.
	if isBlob(relPath) {
		digest := extractDigest(relPath)
		d.blobMu.RLock()
		blobKey, known := d.digestIndex[digest]
		d.blobMu.RUnlock()

		if known {
			if data, ct, err := d.cache.Get(blobKey); err == nil {
				blobName, _ := parseDockerPath(strings.TrimPrefix(blobKey, "docker/"))
				return &core.Artifact{
					CacheKey:    blobKey,
					RepoType:    "docker",
					Name:        blobName,
					Version:     digest,
					ContentType: ct,
					Data:        data,
				}, nil
			}
			// Cache miss: re-download and store under the canonical key.
			upURL := blobUpstreamURL(d.upstream, blobKey)
			data, respHeaders, err := d.fetchWithAuth(ctx, upURL, "")
			if err != nil {
				return nil, err
			}
			ct := respHeaders.Get("Content-Type")
			if ct == "" {
				ct = "application/octet-stream"
			}
			blobName, _ := parseDockerPath(strings.TrimPrefix(blobKey, "docker/"))
			return &core.Artifact{
				CacheKey:    blobKey,
				RepoType:    "docker",
				Name:        blobName,
				Version:     digest,
				URL:         upURL,
				ContentType: ct,
				Data:        data,
			}, nil
		}

		// Blob not yet pre-fetched → download directly (ModeNone).
		upURL := d.upstream + "/v2/" + relPath
		data, respHeaders, err := d.fetchWithAuth(ctx, upURL, "")
		if err != nil {
			return nil, err
		}
		ct := respHeaders.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		return &core.Artifact{
			CacheKey:    "docker/" + relPath,
			RepoType:    "docker",
			Name:        name,
			Version:     version,
			URL:         upURL,
			ContentType: ct,
			Data:        data,
		}, nil
	}

	// Known manifests (pending or approved) — load from cache.
	cacheKey := "docker/" + relPath
	if isManifest(relPath) {
		// Digest-based request: check sub-manifest index (multi-arch manifest lists).
		if strings.HasPrefix(version, "sha256:") {
			d.manifestMu.RLock()
			canonicalKey, known := d.manifestIndex[version]
			d.manifestMu.RUnlock()
			if known {
				if data, ct, err := d.cache.Get(canonicalKey); err == nil {
					h := sha256.Sum256(data)
					return &core.Artifact{
						CacheKey:    canonicalKey,
						RepoType:    "docker",
						Name:        name,
						Version:     version,
						ContentType: ct,
						Data:        data,
						Extra:       map[string]string{"digest": "sha256:" + hex.EncodeToString(h[:])},
					}, nil
				}
			}
		}
		if d.quarantine.IsPending(cacheKey) || d.quarantine.IsApproved(cacheKey) {
			if data, ct, err := d.cache.Get(cacheKey); err == nil {
				h := sha256.Sum256(data)
				return &core.Artifact{
					CacheKey:    cacheKey,
					RepoType:    "docker",
					Name:        name,
					Version:     version,
					ContentType: ct,
					Data:        data,
					Extra:       map[string]string{"digest": "sha256:" + hex.EncodeToString(h[:])},
				}, nil
			}
		}
	}

	// Upstream download — content negotiation and Bearer auth.
	accept := strings.Join(r.Header["Accept"], ", ")
	data, respHeaders, err := d.fetchWithAuth(ctx, d.upstream+"/v2/"+relPath, accept)
	if err != nil {
		return nil, err
	}

	ct := respHeaders.Get("Content-Type")
	if ct == "" {
		ct = dockerContentType(relPath)
	}

	extra := map[string]string{}
	if digest := respHeaders.Get("Docker-Content-Digest"); digest != "" {
		extra["digest"] = digest
		// Register digest→key so that subsequent digest-based requests point
		// to the same key (e.g. Docker verifies the manifest by digest after
		// fetching it by tag).
		if strings.HasPrefix(digest, "sha256:") {
			d.manifestMu.Lock()
			if _, exists := d.manifestIndex[digest]; !exists {
				d.manifestIndex[digest] = cacheKey
			}
			d.manifestMu.Unlock()
		}
	}

	return &core.Artifact{
		CacheKey:    cacheKey,
		RepoType:    "docker",
		Name:        name,
		Version:     version,
		URL:         d.upstream + "/" + relPath,
		ContentType: ct,
		Data:        data,
		Extra:       extra,
	}, nil
}

func (d *DockerDriver) Validate(a *core.Artifact) error {
	relPath := strings.TrimPrefix(a.CacheKey, "docker/")

	// Blobs: SHA256 of content must match the digest (last segment after /blobs/).
	if isBlob(relPath) {
		idx := strings.LastIndex(relPath, "/blobs/")
		if idx >= 0 {
			digestPart := relPath[idx+7:]
			if expectedHex, ok := strings.CutPrefix(digestPart, "sha256:"); ok {
				h := sha256.Sum256(a.Data)
				actual := hex.EncodeToString(h[:])
				if actual != expectedHex {
					return fmt.Errorf("blob digest mismatch for %s: expected sha256:%s got sha256:%s",
						a.Name, expectedHex, actual)
				}
			}
		}
		return nil
	}

	// Manifests: Docker-Content-Digest against the content.
	if isManifest(relPath) {
		if expected, ok := a.Extra["digest"]; ok {
			if expectedHex, ok := strings.CutPrefix(expected, "sha256:"); ok {
				h := sha256.Sum256(a.Data)
				actual := hex.EncodeToString(h[:])
				if actual != expectedHex {
					return fmt.Errorf("manifest digest mismatch for %s:%s: expected %s got sha256:%s",
						a.Name, a.Version, expected, actual)
				}
			}
		}

		// Cosign verification: if enabled, verify the image signature.
		// On failure, do not reject the artifact but force human review.
		if d.cosign != nil {
			digest := manifestDigest(a)
			if digest != "" {
				if err := d.cosign.Verify(context.Background(), d.upstream, a.Name, digest); err != nil {
					log.Printf("[docker] cosign: signature verification failed %s@%s: %v", a.Name, digest, err)
					a.RequireHumanReview = fmt.Sprintf("cosign: %v", err)
				}
			}
		}
	}

	return nil
}

// manifestDigest returns the sha256 digest of a manifest, from Extra or computed.
func manifestDigest(a *core.Artifact) string {
	if d, ok := a.Extra["digest"]; ok && strings.HasPrefix(d, "sha256:") {
		return d
	}
	h := sha256.Sum256(a.Data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// QuarantineDecision:
//   - Manifests                         → ModeSelf
//   - Pre-fetched blobs (prefixed key)  → ModeSelf (auto-approved with the manifest)
//   - Unknown blobs, ping, tags         → ModeNone
func (d *DockerDriver) QuarantineDecision(a *core.Artifact) core.QuarantineDecision {
	relPath := strings.TrimPrefix(a.CacheKey, "docker/")
	if isManifest(relPath) {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	// Pre-fetched blobs have a manifest-prefixed key containing "/manifests/".
	if isBlob(relPath) && strings.Contains(relPath, "/manifests/") {
		return core.QuarantineDecision{Mode: core.ModeSelf}
	}
	return core.QuarantineDecision{Mode: core.ModeNone}
}

func (d *DockerDriver) ServeApproved(w http.ResponseWriter, r *http.Request, a *core.Artifact, data []byte) {
	relPath := strings.TrimPrefix(a.CacheKey, "docker/")
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if isVersionCheck(relPath) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	}
	if isManifest(relPath) {
		if digest, ok := a.Extra["digest"]; ok && digest != "" {
			w.Header().Set("Docker-Content-Digest", digest)
		} else {
			h := sha256.Sum256(data)
			w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(h[:]))
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (d *DockerDriver) ServePending(w http.ResponseWriter, r *http.Request, a *core.Artifact) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w,
		`{"errors":[{"code":"DENIED","message":"Image %s:%s pending administrator validation."}]}`+"\n",
		a.Name, a.Version,
	)
}

// OnQuarantine is called after a manifest is quarantined.
// - Manifest list / OCI Index: pre-fetches each platform sub-manifest and its blobs.
// - Simple manifest: pre-fetches blobs (config + layers).
// Everything is stored under the parent manifest key; approveLinked() auto-approves in cascade.
func (d *DockerDriver) OnQuarantine(a *core.Artifact) {
	if !isManifest(strings.TrimPrefix(a.CacheKey, "docker/")) {
		return
	}
	imageName, _ := parseDockerPath(strings.TrimPrefix(a.CacheKey, "docker/"))

	// Manifest list / OCI Image Index → pre-fetch platform sub-manifests.
	if platforms := extractPlatformDigests(a.Data); len(platforms) > 0 {
		log.Printf("[docker] OnQuarantine: manifest list %s → %d platforms", a.CacheKey, len(platforms))
		d.prefetchPlatformManifests(a.CacheKey, imageName, platforms)
		return
	}

	// Simple manifest → pre-fetch blobs.
	blobs := extractManifestBlobs(a.Data)
	if len(blobs) == 0 {
		return
	}
	log.Printf("[docker] OnQuarantine: manifest %s → %d blobs to pre-fetch", a.CacheKey, len(blobs))
	d.prefetchBlobsForManifest(a.CacheKey, imageName, blobs)
}

// prefetchPlatformManifests downloads each platform manifest from a manifest list,
// enqueues them under "<parentKey>/manifests/<digest>", then pre-fetches their blobs.
func (d *DockerDriver) prefetchPlatformManifests(parentKey, imageName string, digests []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)

	for _, digest := range digests {
		subKey := parentKey + "/manifests/" + digest

		if d.quarantine.IsPending(subKey) || d.quarantine.IsApproved(subKey) {
			d.manifestMu.Lock()
			d.manifestIndex[digest] = subKey
			d.manifestMu.Unlock()
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(digest, subKey string) {
			defer func() { <-sem; wg.Done() }()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			upURL := d.upstream + "/v2/" + imageName + "/manifests/" + digest
			data, respHeaders, err := d.fetchWithAuth(ctx, upURL, "")
			if err != nil {
				log.Printf("[docker] prefetch sub-manifest %s: %v", digest[:19], err)
				return
			}
			ct := respHeaders.Get("Content-Type")
			if ct == "" {
				ct = "application/vnd.docker.distribution.manifest.v2+json"
			}
			if err := d.cache.Set(subKey, data, ct); err != nil {
				log.Printf("[docker] cache sub-manifest %s: %v", digest[:19], err)
				return
			}
			if _, err := d.quarantine.Enqueue(&core.Artifact{
				CacheKey:    subKey,
				RepoType:    "docker",
				Name:        imageName,
				Version:     digest,
				URL:         upURL,
				ContentType: ct,
				Data:        data,
			}); err != nil {
				log.Printf("[docker] enqueue sub-manifest %s: %v", digest[:19], err)
				return
			}
			d.manifestMu.Lock()
			d.manifestIndex[digest] = subKey
			d.manifestMu.Unlock()

			blobs := extractManifestBlobs(data)
			if len(blobs) > 0 {
				d.prefetchBlobsForManifest(subKey, imageName, blobs)
			}
			log.Printf("[docker] sub-manifest %s enqueued with %d blobs", digest[:19], len(blobs))
		}(digest, subKey)
	}
	wg.Wait()
}

// prefetchBlobsForManifest downloads and enqueues the blobs of a simple manifest,
// under the key "<manifestKey>/blobs/<digest>".
func (d *DockerDriver) prefetchBlobsForManifest(manifestKey, imageName string, blobs []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)

	for _, digest := range blobs {
		blobKey := manifestKey + "/blobs/" + digest

		if d.quarantine.IsPending(blobKey) || d.quarantine.IsApproved(blobKey) {
			d.blobMu.Lock()
			d.digestIndex[digest] = blobKey
			d.blobMu.Unlock()
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(digest, blobKey string) {
			defer func() { <-sem; wg.Done() }()

			upURL := d.upstream + "/v2/" + imageName + "/blobs/" + digest
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			data, respHeaders, err := d.fetchWithAuth(ctx, upURL, "")
			if err != nil {
				log.Printf("[docker] fetch blob %s: %v", digest[:19], err)
				return
			}
			ct := respHeaders.Get("Content-Type")
			if ct == "" {
				ct = "application/octet-stream"
			}
			if err := d.cache.Set(blobKey, data, ct); err != nil {
				log.Printf("[docker] cache blob %s: %v", digest[:19], err)
				return
			}
			if _, err := d.quarantine.Enqueue(&core.Artifact{
				CacheKey:    blobKey,
				RepoType:    "docker",
				Name:        imageName,
				Version:     digest,
				URL:         upURL,
				ContentType: ct,
				Data:        data,
			}); err != nil {
				log.Printf("[docker] enqueue blob %s: %v", digest[:19], err)
				return
			}
			d.blobMu.Lock()
			d.digestIndex[digest] = blobKey
			d.blobMu.Unlock()
			log.Printf("[docker] blob %s enqueued for %s", digest[:19], manifestKey)
		}(digest, blobKey)
	}
	wg.Wait()
}

// ── Bearer authentication ─────────────────────────────────────────────────────

func (d *DockerDriver) fetchWithAuth(ctx context.Context, url, accept string) ([]byte, http.Header, error) {
	doReq := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return http.DefaultClient.Do(req)
	}

	resp, err := doReq("")
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		params := parseBearerChallenge(strings.TrimPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer "))
		scope := params["scope"]

		token := d.cachedToken(scope)
		if token == "" {
			var expiresIn int
			token, expiresIn, err = d.fetchToken(ctx, params)
			if err != nil {
				return nil, nil, fmt.Errorf("authentication: %w", err)
			}
			if expiresIn <= 0 {
				expiresIn = 300
			}
			d.storeToken(scope, token, time.Duration(expiresIn)*time.Second)
		}

		resp, err = doReq(token)
		if err != nil {
			return nil, nil, err
		}
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, core.ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("upstream error: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	return data, resp.Header, err
}

func (d *DockerDriver) cachedToken(scope string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.tokens[scope]
	if !ok || time.Now().After(entry.expiry) {
		delete(d.tokens, scope)
		return ""
	}
	return entry.value
}

func (d *DockerDriver) storeToken(scope, token string, ttl time.Duration) {
	d.mu.Lock()
	d.tokens[scope] = tokenEntry{value: token, expiry: time.Now().Add(ttl - 10*time.Second)}
	d.mu.Unlock()
}

func (d *DockerDriver) fetchToken(ctx context.Context, params map[string]string) (string, int, error) {
	realm := params["realm"]
	if realm == "" {
		return "", 0, fmt.Errorf("no realm in Bearer challenge")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
	if err != nil {
		return "", 0, err
	}
	q := req.URL.Query()
	if service := params["service"]; service != "" {
		q.Set("service", service)
	}
	if scope := params["scope"]; scope != "" {
		q.Set("scope", scope)
	}
	req.URL.RawQuery = q.Encode()
	if d.username != "" {
		req.SetBasicAuth(d.username, d.password)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", 0, fmt.Errorf("token endpoint: %s", resp.Status)
	}

	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("decode token response: %w", err)
	}
	token := result.Token
	if token == "" {
		token = result.AccessToken
	}
	if token == "" {
		return "", 0, fmt.Errorf("empty token in auth response")
	}
	return token, result.ExpiresIn, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isVersionCheck(relPath string) bool {
	return relPath == "v2/" || relPath == "v2" || relPath == ""
}

// isManifest returns true only for real manifests (not blobs).
func isManifest(relPath string) bool {
	return strings.Contains(relPath, "/manifests/") && !strings.Contains(relPath, "/blobs/")
}

// isBlob returns true for any path containing /blobs/ (standard URL or manifest-prefixed key).
func isBlob(relPath string) bool {
	return strings.Contains(relPath, "/blobs/")
}

// extractDigest extracts the digest from a blob relPath (standard or prefixed).
func extractDigest(relPath string) string {
	idx := strings.LastIndex(relPath, "/blobs/")
	if idx >= 0 {
		return relPath[idx+7:]
	}
	return ""
}

// parseDockerPath extracts the image name and reference from the path.
// "v2/library/nginx/manifests/latest"  → ("library/nginx", "latest")
// "v2/library/nginx/blobs/sha256:abc…" → ("library/nginx", "sha256:abc…")
func parseDockerPath(relPath string) (name, version string) {
	relPath = strings.TrimPrefix(relPath, "v2/")
	for _, sep := range []string{"/manifests/", "/blobs/", "/tags/"} {
		if idx := strings.Index(relPath, sep); idx >= 0 {
			return relPath[:idx], relPath[idx+len(sep):]
		}
	}
	return relPath, ""
}

// blobUpstreamURL reconstructs the upstream URL from a manifest-prefixed blob key.
// "docker/v2/library/nginx/manifests/latest/blobs/sha256:abc"
// → "https://registry/v2/library/nginx/blobs/sha256:abc"
func blobUpstreamURL(upstream, blobKey string) string {
	// Strip "docker/" then optional "v2/" to get "<imageName>/manifests/..."
	relPath := strings.TrimPrefix(blobKey, "docker/")
	relPath = strings.TrimPrefix(relPath, "v2/")
	mIdx := strings.Index(relPath, "/manifests/")
	if mIdx < 0 {
		return upstream + "/v2/" + relPath
	}
	imageName := relPath[:mIdx]
	digest := extractDigest(blobKey)
	return upstream + "/v2/" + imageName + "/blobs/" + digest
}

func dockerContentType(relPath string) string {
	switch {
	case isManifest(relPath):
		return "application/vnd.docker.distribution.manifest.v2+json"
	case isBlob(relPath):
		return "application/octet-stream"
	default:
		return "application/json"
	}
}

// parseBearerChallenge parses "realm=\"…\",service=\"…\",scope=\"…\"".
func parseBearerChallenge(challenge string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(challenge, ",") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		result[strings.TrimSpace(part[:eq])] = strings.Trim(part[eq+1:], `"`)
	}
	return result
}

// extractPlatformDigests returns the digests of sub-manifests from a manifest list / OCI Index.
// Returns nil if this is not a manifest list.
func extractPlatformDigests(data []byte) []string {
	var list struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil
	}
	if !strings.Contains(list.MediaType, "manifest.list") &&
		!strings.Contains(list.MediaType, "image.index") {
		return nil
	}
	var digests []string
	for _, m := range list.Manifests {
		if m.Digest != "" {
			digests = append(digests, m.Digest)
		}
	}
	return digests
}

// extractManifestBlobs parses the JSON of a manifest and returns all referenced digests
// (config + layers). Returns nil for manifest lists (no direct blobs).
func extractManifestBlobs(data []byte) []string {
	var manifest struct {
		MediaType string `json:"mediaType"`
		Config    struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}
	// Manifest list / OCI Image Index → no direct blobs to pre-fetch.
	if strings.Contains(manifest.MediaType, "manifest.list") ||
		strings.Contains(manifest.MediaType, "image.index") {
		return nil
	}
	var digests []string
	if manifest.Config.Digest != "" {
		digests = append(digests, manifest.Config.Digest)
	}
	for _, layer := range manifest.Layers {
		if layer.Digest != "" {
			digests = append(digests, layer.Digest)
		}
	}
	return digests
}
