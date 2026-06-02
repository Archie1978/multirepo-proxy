// Package db exposes the shared GORM connection and all application models.
// A single SQLite database is used by all components (quarantine, security, authentication).
// It is configured for multi-instance access:
//   - WAL mode       → concurrent readers without blocking the writer
//   - busy_timeout 5s → writes wait instead of failing
//   - MaxOpenConns 1 → serializes access within the same process
package db

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	gormsqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ─────────────────────────────────────────────
// Models
// ─────────────────────────────────────────────

// Request represents a quarantined package.
// The Scan and Findings fields allow GORM preloading via Preload.
type Request struct {
	ID          string     `gorm:"column:id;primaryKey"`
	RepoType    string     `gorm:"column:repo_type;not null"`
	Name        string     `gorm:"column:name;not null"`
	Version     string     `gorm:"column:version;default:''"`
	URL         string     `gorm:"column:url;default:''"`
	CacheKey    string     `gorm:"column:cache_key;uniqueIndex;not null"`
	Size        int64      `gorm:"column:size;default:0"`
	SHA256      string     `gorm:"column:sha256;default:''"`
	ContentType string     `gorm:"column:content_type;default:''"`
	RequestedAt time.Time  `gorm:"column:requested_at;not null;autoCreateTime:false"`
	RequestedBy string     `gorm:"column:requested_by;default:''"`
	Status      string     `gorm:"column:status;index;default:'pending'"`
	ReviewedAt  *time.Time `gorm:"column:reviewed_at"`
	ReviewedBy  string     `gorm:"column:reviewed_by;default:''"`
	Comment     string     `gorm:"column:comment;default:''"`

	// RequireHumanReview is set to true when a critical check fails
	// (e.g. invalid/missing Cosign signature). Prevents any auto-approval.
	RequireHumanReview bool   `gorm:"column:require_human_review;default:false"`
	SignatureError     string `gorm:"column:signature_error;default:''"`

	// Security relations linked by foreign key request_id → id
	Scan     *SecurityScan     `gorm:"foreignKey:RequestID;references:ID"`
	Findings []SecurityFinding `gorm:"foreignKey:RequestID;references:ID"`
}

func (Request) TableName() string { return "requests" }

// SecurityScan stores the status of the last vulnerability scan of a Request.
type SecurityScan struct {
	RequestID  string     `gorm:"column:request_id;primaryKey"`
	ScanStatus string     `gorm:"column:scan_status;default:'pending'"`
	ScannedAt  *time.Time `gorm:"column:scanned_at"`
	Error      string     `gorm:"column:error;default:''"`
}

func (SecurityScan) TableName() string { return "security_scans" }

// SecurityFinding is a vulnerability found for a Request.
// Composite key (request_id, vuln_id, source) — multiple sources can report the same CVE.
type SecurityFinding struct {
	RequestID      string  `gorm:"column:request_id;primaryKey;index:idx_findings_req"`
	VulnID         string  `gorm:"column:vuln_id;primaryKey"`
	Source         string  `gorm:"column:source;primaryKey"`
	Severity       string  `gorm:"column:severity;default:''"`
	CVSS           float64 `gorm:"column:cvss;default:0"`
	Title          string  `gorm:"column:title;default:''"`
	Description    string  `gorm:"column:description;default:''"`
	CWE            string  `gorm:"column:cwe;default:''"`
	EPSS           float64 `gorm:"column:epss;default:0"`
	EPSSPercentile float64 `gorm:"column:epss_percentile;default:0"`
	// Refs is a JSON list of reference URLs.
	Refs string `gorm:"column:refs;default:'[]'"`
}

func (SecurityFinding) TableName() string { return "security_findings" }

// User is a user for HTTP Basic authentication.
type User struct {
	Username     string    `gorm:"column:username;primaryKey"`
	PasswordHash string    `gorm:"column:password_hash;not null"`
	Groups       string    `gorm:"column:groups;default:''"`
	Enabled      bool      `gorm:"column:enabled;default:true"`
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime:true"`
}

func (User) TableName() string { return "users" }

// Rule defines an auto-quarantine rule for a repository type.
// RepoType = "*" applies to all repositories.
// RuleType: "cvss_max", "epss_max", "cvss_sum", "cvss_epss_sum".
type Rule struct {
	ID        uint      `gorm:"column:id;primaryKey;autoIncrement"`
	RepoType  string    `gorm:"column:repo_type;not null;default:'*'"`
	RuleType  string    `gorm:"column:rule_type;not null"`
	Threshold float64   `gorm:"column:threshold;not null"`
	Enabled   bool      `gorm:"column:enabled;default:true"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime:true"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:true"`
}

func (Rule) TableName() string { return "rules" }

// AuditLog traces each status change of a package (approve, reject, revoke…).
type AuditLog struct {
	ID        uint      `gorm:"column:id;primaryKey;autoIncrement"`
	RequestID string    `gorm:"column:request_id;not null;index"`
	Action    string    `gorm:"column:action;not null"` // "approved", "rejected", "revoked"
	Actor     string    `gorm:"column:actor;default:''"`
	Comment   string    `gorm:"column:comment;default:''"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime:true"`
}

func (AuditLog) TableName() string { return "audit_log" }

// Group defines a set of permissions associated with a role.
// Repos is a JSON array of allowed repository types (e.g. ["apt","r"] or ["*"]).
type Group struct {
	Name            string    `gorm:"column:name;primaryKey"`
	Repos           string    `gorm:"column:repos;default:'[]'"`
	CanApprove      bool      `gorm:"column:can_approve;default:false"`
	CanManage       bool      `gorm:"column:can_manage;default:false"`
	CanRefreshIndex bool      `gorm:"column:can_refresh_index;default:false"`
	CreatedAt       time.Time `gorm:"column:created_at;autoCreateTime:true"`
	UpdatedAt       time.Time `gorm:"column:updated_at;autoUpdateTime:true"`
}

func (Group) TableName() string { return "groups" }

// ─────────────────────────────────────────────
// Open
// ─────────────────────────────────────────────

// OpenAuth opens (or creates) the SQLite database dedicated to authentication data
// (users, groups, rules). Does not include quarantine or security tables,
// keeping the database lightweight and enabling separate backups.
func OpenAuth(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("auth db: create directory: %w", err)
	}

	dsn := fmt.Sprintf(
		"file:%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=on",
		path,
	)

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Silent),
		DisableForeignKeyConstraintWhenMigrating: true,
		NowFunc:                                  func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, fmt.Errorf("auth db: open %q: %w", path, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("auth db: get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	if err := db.AutoMigrate(&User{}, &Group{}, &Rule{}); err != nil {
		return nil, fmt.Errorf("auth db: migration: %w", err)
	}

	return db, nil
}

// Open opens (or creates) the main SQLite database (quarantine + security + auth) and runs GORM migrations.
// Call sqlDB.Close() on the underlying *sql.DB to release resources on shutdown.
func Open(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("db: create directory: %w", err)
	}

	// WAL + busy_timeout for inter-process concurrency.
	dsn := fmt.Sprintf(
		"file:%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=on",
		path,
	)

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Silent),
		DisableForeignKeyConstraintWhenMigrating: true,
		NowFunc:                                  func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, fmt.Errorf("db: open %q: %w", path, err)
	}

	// MaxOpenConns(1): serializes writes within the same process.
	// WAL handles inter-process concurrency via busy_timeout.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("db: get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	if err := db.AutoMigrate(
		&Request{},
		&SecurityScan{},
		&SecurityFinding{},
		&User{},
		&Rule{},
		&AuditLog{},
		&Group{},
	); err != nil {
		return nil, fmt.Errorf("db: migration: %w", err)
	}

	return db, nil
}
