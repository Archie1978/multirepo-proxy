package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ─────────────────────────────────────────────
// Public interfaces
// ─────────────────────────────────────────────

// CacheStore is the main cache interface.
// Any implementation (disk, memory, Redis…) must satisfy it.
type CacheStore interface {
	// Get returns data, content-type and an error if absent.
	Get(key string) (data []byte, contentType string, err error)

	// Set stores data with its content-type.
	Set(key string, data []byte, contentType string) error

	// Delete removes an entry.
	Delete(key string) error

	// Exists checks for the presence of a key without loading data.
	Exists(key string) bool

	// Stats returns cache metrics.
	Stats() Stats
}

// Validator is the validation interface for a package/artifact.
// Each repo type (Docker, npm, pip, R…) implements its own validation.
type Validator interface {
	// Validate checks integrity and/or conformity of the data.
	// Returns nil if valid, a descriptive error otherwise.
	Validate(key string, data []byte, meta Metadata) error

	// Name returns the validator name (for logs).
	Name() string
}

// ValidatedCacheStore combines CacheStore + automatic validation on write.
type ValidatedCacheStore interface {
	CacheStore

	// SetWithValidation stores only if all validators pass.
	SetWithValidation(key string, data []byte, contentType string) error

	// AddValidator adds a validator to the chain.
	AddValidator(v Validator)

	// RemoveValidator removes a validator by name.
	RemoveValidator(name string)

	// Validators lists the active validators.
	Validators() []string
}

// ─────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────

// Metadata is stored as a sidecar (.meta) alongside each entry.
type Metadata struct {
	Key         string    `json:"key"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"created_at"`
	AccessedAt  time.Time `json:"accessed_at"`
	AccessCount int64     `json:"access_count"`
	Validated   bool      `json:"validated"`
	ValidatedBy []string  `json:"validated_by,omitempty"`
}

// Stats exposes cache metrics.
type Stats struct {
	Entries    int64
	TotalBytes int64
	HitCount   int64
	MissCount  int64
	ErrorCount int64
}

// ValidationError groups errors from multiple validators.
type ValidationError struct {
	Validator string
	Cause     error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("[%s] %v", e.Validator, e.Cause)
}

// ─────────────────────────────────────────────
// DiskStore — disk-based implementation
// ─────────────────────────────────────────────

// DiskStore stores each entry in two files:
//
//	<cacheDir>/<hash>.data  → raw content
//	<cacheDir>/<hash>.meta  → JSON metadata
type DiskStore struct {
	baseDir    string
	mu         sync.RWMutex
	validators []Validator
	stats      Stats
}

// NewDiskStore creates a DiskStore in the given directory.
func NewDiskStore(baseDir string) (*DiskStore, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &DiskStore{baseDir: baseDir}, nil
}

// ── CacheStore ──

func (s *DiskStore) Get(key string) ([]byte, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dataPath, metaPath := s.paths(key)

	meta, err := s.readMeta(metaPath)
	if err != nil {
		s.stats.MissCount++
		return nil, "", fmt.Errorf("cache miss: %w", err)
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		s.stats.MissCount++
		return nil, "", fmt.Errorf("read data: %w", err)
	}

	// Update access stats asynchronously to avoid blocking.
	go s.touchMeta(metaPath, meta)

	s.stats.HitCount++
	return data, meta.ContentType, nil
}

func (s *DiskStore) Set(key string, data []byte, contentType string) error {
	return s.write(key, data, contentType, nil)
}

func (s *DiskStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataPath, metaPath := s.paths(key)
	_ = os.Remove(dataPath)
	_ = os.Remove(metaPath)
	return nil
}

func (s *DiskStore) Exists(key string) bool {
	_, metaPath := s.paths(key)
	_, err := os.Stat(metaPath)
	return err == nil
}

func (s *DiskStore) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// ── ValidatedCacheStore ──

func (s *DiskStore) SetWithValidation(key string, data []byte, contentType string) error {
	s.mu.RLock()
	validators := make([]Validator, len(s.validators))
	copy(validators, s.validators)
	s.mu.RUnlock()

	meta := Metadata{
		Key:         key,
		ContentType: contentType,
		Size:        int64(len(data)),
		SHA256:      hashSHA256(data),
		CreatedAt:   time.Now(),
	}

	var validatedBy []string
	for _, v := range validators {
		if err := v.Validate(key, data, meta); err != nil {
			s.stats.ErrorCount++
			return &ValidationError{Validator: v.Name(), Cause: err}
		}
		validatedBy = append(validatedBy, v.Name())
	}

	meta.Validated = len(validatedBy) > 0
	meta.ValidatedBy = validatedBy

	return s.write(key, data, contentType, &meta)
}

func (s *DiskStore) AddValidator(v Validator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validators = append(s.validators, v)
}

func (s *DiskStore) RemoveValidator(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.validators[:0]
	for _, v := range s.validators {
		if v.Name() != name {
			filtered = append(filtered, v)
		}
	}
	s.validators = filtered
}

func (s *DiskStore) Validators() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, len(s.validators))
	for i, v := range s.validators {
		names[i] = v.Name()
	}
	return names
}

// ── Internals ──

func (s *DiskStore) write(key string, data []byte, contentType string, metaOverride *Metadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataPath, metaPath := s.paths(key)

	// Create subdirectories if needed.
	if err := os.MkdirAll(filepath.Dir(dataPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Atomic write via temporary file.
	tmp, err := os.CreateTemp(filepath.Dir(dataPath), "*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	tmp.Close()

	if err = os.Rename(tmpName, dataPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	// Metadata
	meta := Metadata{
		Key:         key,
		ContentType: contentType,
		Size:        int64(len(data)),
		SHA256:      hashSHA256(data),
		CreatedAt:   time.Now(),
		AccessedAt:  time.Now(),
	}
	if metaOverride != nil {
		meta.Validated = metaOverride.Validated
		meta.ValidatedBy = metaOverride.ValidatedBy
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	if err = os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	s.stats.Entries++
	s.stats.TotalBytes += meta.Size
	return nil
}

func (s *DiskStore) paths(key string) (dataPath, metaPath string) {
	// Hash the key to get a safe filename.
	h := sha256.Sum256([]byte(key))
	hex := hex.EncodeToString(h[:])
	// Shard into subdirectories (first 2 chars) to avoid too many files in one directory.
	sub := filepath.Join(s.baseDir, hex[:2], hex[2:4])
	base := filepath.Join(sub, hex)
	return base + ".data", base + ".meta"
}

func (s *DiskStore) readMeta(metaPath string) (Metadata, error) {
	var meta Metadata
	b, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return meta, fmt.Errorf("not found")
		}
		return meta, err
	}
	return meta, json.Unmarshal(b, &meta)
}

func (s *DiskStore) touchMeta(metaPath string, meta Metadata) {
	meta.AccessedAt = time.Now()
	meta.AccessCount++
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(metaPath, b, 0o644)
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
