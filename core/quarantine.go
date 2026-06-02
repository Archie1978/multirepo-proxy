package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	coredb "multirepo-proxy/core/db"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ─────────────────────────────────────────────
// Status
// ─────────────────────────────────────────────

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// ─────────────────────────────────────────────
// PackageRequest
// ─────────────────────────────────────────────

type PackageRequest struct {
	ID          string     `json:"id"`
	RepoType    string     `json:"repo_type"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	URL         string     `json:"url"`
	CacheKey    string     `json:"cache_key"`
	Size        int64      `json:"size"`
	SHA256      string     `json:"sha256"`
	ContentType string     `json:"content_type"`
	RequestedAt time.Time  `json:"requested_at"`
	RequestedBy string     `json:"requested_by,omitempty"`
	Status      Status     `json:"status"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy  string     `json:"reviewed_by,omitempty"`
	Comment     string     `json:"comment,omitempty"`

	// RequireHumanReview blocks auto-approval and forces a manual decision.
	RequireHumanReview bool   `json:"require_human_review,omitempty"`
	SignatureError     string `json:"signature_error,omitempty"`
}

// ─────────────────────────────────────────────
// SecurityFinding
// ─────────────────────────────────────────────

// SecurityFinding is a vulnerability found for a quarantined artifact.
type SecurityFinding struct {
	ID             string   `json:"id"`
	Source         string   `json:"source"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	CWE            string   `json:"cwe,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	References     []string `json:"references"`
}

// ─────────────────────────────────────────────
// QuarantineStore
// ─────────────────────────────────────────────

// QuarantineStore manages the persistence of quarantined packages via GORM.
// The DB is shared with other components — do not call Close() directly;
// close the underlying *sql.DB from the application entry point.
type QuarantineStore struct {
	db *gorm.DB

	// OnEnqueue is called asynchronously after each new artifact is quarantined.
	OnEnqueue func(req *PackageRequest)

	// internal pub/sub: notifies waiting HTTP requests when a scan is done.
	mu   sync.Mutex
	subs map[string][]chan struct{}
}

// NewQuarantineStore creates a QuarantineStore from the shared GORM connection.
func NewQuarantineStore(db *gorm.DB) *QuarantineStore {
	return &QuarantineStore{db: db, subs: make(map[string][]chan struct{})}
}

// SubscribeByID returns a buffered channel (size 1) notified when the scan for this ID is done.
// The cancel() function must be called if waiting is no longer needed (defer).
func (q *QuarantineStore) SubscribeByID(id string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	q.mu.Lock()
	q.subs[id] = append(q.subs[id], ch)
	q.mu.Unlock()
	cancel := func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		chans := q.subs[id]
		for i, c := range chans {
			if c == ch {
				q.subs[id] = append(chans[:i], chans[i+1:]...)
				return
			}
		}
	}
	return ch, cancel
}

// NotifyScanDone wakes up all HTTP requests waiting for the scan of this ID.
func (q *QuarantineStore) NotifyScanDone(id string) {
	q.mu.Lock()
	chans := q.subs[id]
	delete(q.subs, id)
	q.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// IsScanDone returns true if the scan is complete (done or error) for this requestID.
func (q *QuarantineStore) IsScanDone(requestID string) bool {
	var scan coredb.SecurityScan
	err := q.db.Select("scan_status").Where("request_id = ?", requestID).First(&scan).Error
	if err != nil {
		return false
	}
	return scan.ScanStatus == "done" || scan.ScanStatus == "error"
}

// Close is kept for compatibility with existing code; the shared DB
// is closed by the entry point via sqlDB.Close().
func (q *QuarantineStore) Close() error { return nil }

// ─────────────────────────────────────────────
// Write
// ─────────────────────────────────────────────

// Enqueue inserts an artifact into quarantine and returns its ID.
//   - If already pending or approved, returns the existing ID without modification.
//   - Auto-approved if a parent artifact (prefix key) is already approved.
func (q *QuarantineStore) Enqueue(a *Artifact) (string, error) {
	var existing coredb.Request
	err := q.db.Where("cache_key = ?", a.CacheKey).First(&existing).Error
	if err == nil {
		if existing.Status != string(StatusRejected) {
			return existing.ID, nil // already pending or approved, no regression
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("quarantine enqueue lookup: %w", err)
	}

	status := StatusPending
	if q.hasApprovedParent(a.CacheKey) {
		status = StatusApproved
	}

	id := newID()
	now := time.Now().UTC()
	sha := hashSHA256(a.Data)

	requireHuman := a.RequireHumanReview != ""
	sigErr := a.RequireHumanReview

	row := coredb.Request{
		ID:                 id,
		RepoType:           a.RepoType,
		Name:               a.Name,
		Version:            a.Version,
		URL:                a.URL,
		CacheKey:           a.CacheKey,
		Size:               int64(len(a.Data)),
		SHA256:             sha,
		ContentType:        a.ContentType,
		RequestedAt:        now,
		Status:             string(status),
		RequireHumanReview: requireHuman,
		SignatureError:     sigErr,
	}

	res := q.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "cache_key"}},
		DoUpdates: clause.Assignments(map[string]any{
			"id":           id,
			"status":       string(status),
			"requested_at": now,
		}),
	}).Create(&row)
	if res.Error != nil {
		return "", fmt.Errorf("quarantine enqueue: %w", res.Error)
	}

	if q.OnEnqueue != nil && status == StatusPending {
		pub := rowToPublic(&row)
		go q.OnEnqueue(pub)
	}
	return id, nil
}

// hasApprovedParent returns true if an approved parent artifact exists (strict prefix key).
func (q *QuarantineStore) hasApprovedParent(cacheKey string) bool {
	var count int64
	q.db.Model(&coredb.Request{}).
		Where("status = ? AND ? LIKE (cache_key || '/%')", string(StatusApproved), cacheKey).
		Count(&count)
	return count > 0
}

// Approve approves an artifact and its direct children (same cache_key prefix).
// Returns an error if the artifact is marked RequireHumanReview — auto-approval
// is blocked in that case and only an explicit human action can approve it.
func (q *QuarantineStore) Approve(id, reviewer, comment string) error {
	return q.db.Transaction(func(tx *gorm.DB) error {
		var req coredb.Request
		if err := tx.Where("id = ?", id).First(&req).Error; err != nil {
			return fmt.Errorf("not found: %s", id)
		}
		if req.RequireHumanReview && reviewer == "auto" {
			return fmt.Errorf("auto-approval blocked: human review required (%s)", req.SignatureError)
		}
		if err := transition(tx, id, StatusApproved, reviewer, comment); err != nil {
			return err
		}
		return updateLinked(tx, req.CacheKey, StatusApproved, reviewer, "auto-approved with "+req.CacheKey)
	})
}

// Reject rejects an artifact and its direct children.
func (q *QuarantineStore) Reject(id, reviewer, comment string) error {
	return q.db.Transaction(func(tx *gorm.DB) error {
		if err := transition(tx, id, StatusRejected, reviewer, comment); err != nil {
			return err
		}
		var req coredb.Request
		if err := tx.Where("id = ?", id).First(&req).Error; err != nil {
			return nil
		}
		return updateLinked(tx, req.CacheKey, StatusRejected, reviewer, "auto-rejected with "+req.CacheKey)
	})
}

func transition(tx *gorm.DB, id string, status Status, reviewer, comment string) error {
	return transitionWithAction(tx, id, status, reviewer, comment, string(status))
}

func transitionWithAction(tx *gorm.DB, id string, status Status, reviewer, comment, auditAction string) error {
	now := time.Now().UTC()
	res := tx.Model(&coredb.Request{}).Where("id = ?", id).Updates(map[string]any{
		"status":      string(status),
		"reviewed_at": now,
		"reviewed_by": reviewer,
		"comment":     comment,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("not found: %s", id)
	}
	return tx.Create(&coredb.AuditLog{
		RequestID: id,
		Action:    auditAction,
		Actor:     reviewer,
		Comment:   comment,
	}).Error
}

// Revoke puts an approved artifact back to pending for a new manual review.
func (q *QuarantineStore) Revoke(id, reviewer, comment string) error {
	return q.db.Transaction(func(tx *gorm.DB) error {
		return transitionWithAction(tx, id, StatusPending, reviewer, comment, "revoked")
	})
}

// AuditEntry is an entry in the decision history.
type AuditEntry struct {
	ID        uint      `json:"id"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// GetAuditLog returns the decision history for a package, in chronological order.
func (q *QuarantineStore) GetAuditLog(requestID string) ([]AuditEntry, error) {
	var rows []coredb.AuditLog
	if err := q.db.Where("request_id = ?", requestID).
		Order("created_at asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]AuditEntry, len(rows))
	for i, r := range rows {
		result[i] = AuditEntry{
			ID:        r.ID,
			Action:    r.Action,
			Actor:     r.Actor,
			Comment:   r.Comment,
			CreatedAt: r.CreatedAt,
		}
	}
	return result, nil
}

func updateLinked(tx *gorm.DB, baseKey string, status Status, reviewer, comment string) error {
	now := time.Now().UTC()
	return tx.Model(&coredb.Request{}).
		Where("cache_key LIKE ? AND status = ?", baseKey+"/%", string(StatusPending)).
		Updates(map[string]any{
			"status":      string(status),
			"reviewed_at": now,
			"reviewed_by": reviewer,
			"comment":     comment,
		}).Error
}

// ─────────────────────────────────────────────
// Read
// ─────────────────────────────────────────────

// IsPending returns true if a pending entry exists for this cacheKey.
func (q *QuarantineStore) IsPending(cacheKey string) bool {
	var count int64
	q.db.Model(&coredb.Request{}).
		Where("cache_key = ? AND status = ?", cacheKey, string(StatusPending)).
		Count(&count)
	return count > 0
}

// IsApproved returns true if the entry for this cacheKey is approved.
func (q *QuarantineStore) IsApproved(cacheKey string) bool {
	var count int64
	q.db.Model(&coredb.Request{}).
		Where("cache_key = ? AND status = ?", cacheKey, string(StatusApproved)).
		Count(&count)
	return count > 0
}

// Get returns a PackageRequest by ID.
func (q *QuarantineStore) Get(id string) (*PackageRequest, error) {
	var row coredb.Request
	if err := q.db.Where("id = ?", id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("not found")
		}
		return nil, err
	}
	return rowToPublic(&row), nil
}

// GetByCacheKey returns a PackageRequest by cache_key.
func (q *QuarantineStore) GetByCacheKey(cacheKey string) (*PackageRequest, error) {
	var row coredb.Request
	if err := q.db.Where("cache_key = ?", cacheKey).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("not found")
		}
		return nil, err
	}
	return rowToPublic(&row), nil
}

// List returns entries filtered by status (nil = all), sorted by descending date.
func (q *QuarantineStore) List(status *Status) ([]*PackageRequest, error) {
	var rows []coredb.Request
	query := q.db.Order("requested_at desc")
	if status != nil {
		query = query.Where("status = ?", string(*status))
	}
	if err := query.Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]*PackageRequest, len(rows))
	for i := range rows {
		result[i] = rowToPublic(&rows[i])
	}
	return result, nil
}

// ─────────────────────────────────────────────
// Security
// ─────────────────────────────────────────────

// SetComment updates only the comment of an entry.
func (q *QuarantineStore) SetComment(id, comment string) error {
	return q.db.Model(&coredb.Request{}).Where("id = ?", id).
		Update("comment", comment).Error
}

// SetScanStatus updates the scan status for an artifact.
func (q *QuarantineStore) SetScanStatus(requestID, status, errMsg string) error {
	now := time.Now().UTC()
	return q.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "request_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"scan_status": status,
			"scanned_at":  now,
			"error":       errMsg,
		}),
	}).Create(&coredb.SecurityScan{
		RequestID:  requestID,
		ScanStatus: status,
		ScannedAt:  &now,
		Error:      errMsg,
	}).Error
}

// SaveFindings stores the vulnerabilities found for an artifact (upsert by composite key).
func (q *QuarantineStore) SaveFindings(requestID string, findings []SecurityFinding) error {
	for _, f := range findings {
		refs, _ := json.Marshal(f.References)
		row := coredb.SecurityFinding{
			RequestID:      requestID,
			VulnID:         f.ID,
			Source:         f.Source,
			Severity:       f.Severity,
			CVSS:           f.CVSS,
			Title:          f.Title,
			Description:    f.Description,
			CWE:            f.CWE,
			EPSS:           f.EPSS,
			EPSSPercentile: f.EPSSPercentile,
			Refs:           string(refs),
		}
		err := q.db.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "request_id"}, {Name: "vuln_id"}, {Name: "source"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"severity", "cvss", "title", "description", "cwe", "epss", "epss_percentile", "refs",
			}),
		}).Create(&row).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// GetAllFindings returns all vulnerabilities grouped by request_id.
func (q *QuarantineStore) GetAllFindings() (map[string][]SecurityFinding, error) {
	var rows []coredb.SecurityFinding
	if err := q.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make(map[string][]SecurityFinding, len(rows))
	for _, r := range rows {
		var refs []string
		json.Unmarshal([]byte(r.Refs), &refs) //nolint:errcheck
		result[r.RequestID] = append(result[r.RequestID], SecurityFinding{
			ID:             r.VulnID,
			Source:         r.Source,
			Severity:       r.Severity,
			CVSS:           r.CVSS,
			Title:          r.Title,
			Description:    r.Description,
			CWE:            r.CWE,
			EPSS:           r.EPSS,
			EPSSPercentile: r.EPSSPercentile,
			References:     refs,
		})
	}
	return result, nil
}

// ListNeedingScan returns packages without a successful scan:
// absent from security_scans, interrupted ("scanning") or errored ("error").
func (q *QuarantineStore) ListNeedingScan() ([]*PackageRequest, error) {
	var rows []coredb.Request
	err := q.db.
		Joins("LEFT JOIN security_scans ON security_scans.request_id = requests.id").
		Where("security_scans.request_id IS NULL OR security_scans.scan_status IN ?",
			[]string{"scanning", "error"}).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]*PackageRequest, len(rows))
	for i := range rows {
		result[i] = rowToPublic(&rows[i])
	}
	return result, nil
}

// GetScanStatuses returns the scan statuses for all artifacts.
func (q *QuarantineStore) GetScanStatuses() (map[string]string, error) {
	var rows []coredb.SecurityScan
	if err := q.db.Select("request_id, scan_status").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make(map[string]string, len(rows))
	for _, r := range rows {
		result[r.RequestID] = r.ScanStatus
	}
	return result, nil
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func rowToPublic(r *coredb.Request) *PackageRequest {
	req := &PackageRequest{
		ID:                 r.ID,
		RepoType:           r.RepoType,
		Name:               r.Name,
		Version:            r.Version,
		URL:                r.URL,
		CacheKey:           r.CacheKey,
		Size:               r.Size,
		SHA256:             r.SHA256,
		ContentType:        r.ContentType,
		RequestedAt:        r.RequestedAt,
		RequestedBy:        r.RequestedBy,
		Status:             Status(r.Status),
		ReviewedBy:         r.ReviewedBy,
		Comment:            r.Comment,
		RequireHumanReview: r.RequireHumanReview,
		SignatureError:     r.SignatureError,
	}
	if r.ReviewedAt != nil {
		t := *r.ReviewedAt
		req.ReviewedAt = &t
	}
	return req
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

func hashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// IsDockerChildKey is used by the admin API to filter the display.
// Exposed here to avoid duplication.
func IsDockerChildKey(cacheKey string) bool {
	return strings.Contains(cacheKey, "/blobs/") || strings.Count(cacheKey, "/manifests/") > 1
}
