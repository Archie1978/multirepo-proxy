package core

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// ─────────────────────────────────────────────
// Validator: SHA256
// Verifies that the content digest matches the one expected in the key.
// Used by: Docker (blobs), npm, pip
// ─────────────────────────────────────────────

type SHA256Validator struct{}

func (v *SHA256Validator) Name() string { return "sha256" }

func (v *SHA256Validator) Validate(key string, data []byte, meta Metadata) error {
	parts := strings.Split(key, "/")
	last := parts[len(parts)-1]

	if !strings.HasPrefix(last, "sha256:") {
		return nil
	}

	expected := last
	actual := hashSHA256(data)

	if expected != actual {
		return fmt.Errorf("digest mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// ─────────────────────────────────────────────
// Validator: ContentType
// Verifies that the content-type matches what is expected for this repo type.
// ─────────────────────────────────────────────

type ContentTypeValidator struct {
	AllowedTypes map[string][]string
}

func NewContentTypeValidator() *ContentTypeValidator {
	return &ContentTypeValidator{
		AllowedTypes: map[string][]string{
			"docker/manifests": {
				"application/vnd.docker.distribution.manifest.v2+json",
				"application/vnd.docker.distribution.manifest.list.v2+json",
				"application/vnd.oci.image.manifest.v1+json",
				"application/vnd.oci.image.index.v1+json",
			},
			"docker/blobs": {
				"application/octet-stream",
				"application/vnd.docker.image.rootfs.diff.tar.gzip",
			},
			"npm/packages": {
				"application/json",
			},
			"npm/tarballs": {
				"application/octet-stream",
				"application/gzip",
			},
			"pip/packages": {
				"text/html",
				"application/json",
			},
			"pip/files": {
				"application/octet-stream",
				"application/zip",
				"application/x-tar",
			},
			"r/packages": {
				"application/octet-stream",
				"application/x-gzip",
			},
			"ubuntu/packages": {
				"application/octet-stream",
				"text/plain",
			},
		},
	}
}

func (v *ContentTypeValidator) Name() string { return "content-type" }

func (v *ContentTypeValidator) Validate(key string, data []byte, meta Metadata) error {
	for prefix, allowed := range v.AllowedTypes {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		ct := strings.Split(meta.ContentType, ";")[0]
		ct = strings.TrimSpace(ct)
		for _, a := range allowed {
			if ct == a {
				return nil
			}
		}
		return fmt.Errorf("unexpected content-type %q for key prefix %q (allowed: %v)",
			ct, prefix, allowed)
	}
	return nil
}

// ─────────────────────────────────────────────
// Validator: MinSize
// Rejects suspiciously small artifacts.
// ─────────────────────────────────────────────

type MinSizeValidator struct {
	Rules map[string]int64
}

func NewMinSizeValidator() *MinSizeValidator {
	return &MinSizeValidator{
		Rules: map[string]int64{
			"docker/blobs":     1024,
			"docker/manifests": 200,
			"npm/tarballs":     512,
			"pip/files":        512,
			"r/packages":       1024,
			"ubuntu/packages":  1024,
		},
	}
}

func (v *MinSizeValidator) Name() string { return "min-size" }

func (v *MinSizeValidator) Validate(key string, data []byte, meta Metadata) error {
	for prefix, minSize := range v.Rules {
		if strings.HasPrefix(key, prefix) && meta.Size < minSize {
			return fmt.Errorf("artifact too small: %d bytes (min %d) for %q",
				meta.Size, minSize, key)
		}
	}
	return nil
}

// ─────────────────────────────────────────────
// Validator: MD5 (for apt/Ubuntu)
// ─────────────────────────────────────────────

type MD5Validator struct {
	ExpectedMD5 func(key string) string
}

func (v *MD5Validator) Name() string { return "md5" }

func (v *MD5Validator) Validate(key string, data []byte, meta Metadata) error {
	if v.ExpectedMD5 == nil {
		return nil
	}
	expected := v.ExpectedMD5(key)
	if expected == "" {
		return nil
	}
	h := md5.Sum(data) //nolint:gosec
	actual := hex.EncodeToString(h[:])
	if expected != actual {
		return fmt.Errorf("md5 mismatch for %q: expected %s, got %s", key, expected, actual)
	}
	return nil
}

// ─────────────────────────────────────────────
// Validator: NoErrorPage
// Detects if the cached response is an HTML error page.
// ─────────────────────────────────────────────

type NoErrorPageValidator struct{}

func (v *NoErrorPageValidator) Name() string { return "no-error-page" }

func (v *NoErrorPageValidator) Validate(key string, data []byte, meta Metadata) error {
	if strings.Contains(meta.ContentType, "json") ||
		strings.Contains(meta.ContentType, "text/plain") {
		return nil
	}

	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	snippet := strings.ToLower(strings.TrimSpace(string(data[:limit])))
	if strings.HasPrefix(snippet, "<!doctype html") ||
		strings.HasPrefix(snippet, "<html") {
		return fmt.Errorf("response looks like an HTML error page for key %q", key)
	}
	return nil
}

// ─────────────────────────────────────────────
// ValidatorChain — composite validator
// ─────────────────────────────────────────────

type ValidatorChain struct {
	validators []Validator
	mu         sync.RWMutex
}

func NewValidatorChain(validators ...Validator) *ValidatorChain {
	return &ValidatorChain{validators: validators}
}

func (c *ValidatorChain) Name() string { return "chain" }

func (c *ValidatorChain) Add(v Validator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validators = append(c.validators, v)
}

func (c *ValidatorChain) Remove(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	filtered := c.validators[:0]
	for _, v := range c.validators {
		if v.Name() != name {
			filtered = append(filtered, v)
		}
	}
	c.validators = filtered
}

func (c *ValidatorChain) Validate(key string, data []byte, meta Metadata) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var errs []string
	for _, v := range c.validators {
		if err := v.Validate(key, data, meta); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", v.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
