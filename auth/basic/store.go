package basic

import (
	"bufio"
	"crypto/sha1" //nolint:gosec
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	coredb "multirepo-proxy/core/db"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserStore verifies credentials from a source.
type UserStore interface {
	Verify(username, password string) (bool, error)
}

// ─── htpasswd ───────────────────────────────────────────────────────────────

// HtpasswdStore reads credentials from an Apache htpasswd file.
// Supported formats: bcrypt ($2y$/$2a$/$2b$), SHA-1 ({SHA}) and plain text (not recommended).
type HtpasswdStore struct {
	Path string
}

func (s *HtpasswdStore) Verify(username, password string) (bool, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return false, fmt.Errorf("htpasswd: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, hash, ok := strings.Cut(line, ":")
		if !ok || user != username {
			continue
		}
		return verifyHash(password, hash), nil
	}
	return false, nil
}

func verifyHash(password, hash string) bool {
	switch {
	case strings.HasPrefix(hash, "$2y$") ||
		strings.HasPrefix(hash, "$2a$") ||
		strings.HasPrefix(hash, "$2b$"):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil

	case strings.HasPrefix(hash, "{SHA}"):
		h := sha1.Sum([]byte(password)) //nolint:gosec
		return "{SHA}"+base64.StdEncoding.EncodeToString(h[:]) == hash

	default:
		return hash == password
	}
}

// ─── DBStore (GORM) ─────────────────────────────────────────────────────────

// UserInfo groups a user's information (public view, without password).
type UserInfo struct {
	Username    string    `json:"username"`
	Groups      []string  `json:"groups"`
	IsAnonymous bool      `json:"is_anonymous"` // true if password_hash == "" (no password)
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// DBStore verifies and manages credentials in the shared GORM database (users table).
type DBStore struct {
	db *gorm.DB
}

// NewDBStore creates a DBStore and initializes the default admin user if the table is empty.
func NewDBStore(db *gorm.DB) *DBStore {
	s := &DBStore{db: db}
	s.ensureDefaultAdmin()
	return s
}

// ensureDefaultAdmin creates admin/admin on the first database open.
func (s *DBStore) ensureDefaultAdmin() {
	var count int64
	s.db.Model(&coredb.User{}).Count(&count)
	if count > 0 {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	s.db.Create(&coredb.User{
		Username:     "admin",
		PasswordHash: string(hash),
		Groups:       "admin",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	})
	log.Println("[auth] database created — default user: admin / admin  " +
		"⚠ CHANGE THIS PASSWORD: multirepo-proxy user passwd admin")
}

// Verify verifies a user's credentials.
// Returns false if the user is disabled.
// For anonymous users (empty password_hash), only an empty password is accepted.
func (s *DBStore) Verify(username, password string) (bool, error) {
	var user coredb.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		if strings.Contains(err.Error(), "record not found") {
			return false, nil
		}
		return false, err
	}
	if !user.Enabled {
		return false, nil
	}
	if user.PasswordHash == "" {
		// User without password: access only if the provided password is empty.
		return password == "", nil
	}
	return verifyHash(password, user.PasswordHash), nil
}

// HasAnonymous returns true if an "anonymous" user without a password exists in the database.
func (s *DBStore) HasAnonymous() bool {
	var count int64
	s.db.Model(&coredb.User{}).Where("username = ? AND password_hash = ?", "anonymous", "").Count(&count)
	return count > 0
}

// AddUser inserts or updates a user with a bcrypt hash.
func (s *DBStore) AddUser(username, password string, groups ...string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := coredb.User{
		Username:     username,
		PasswordHash: string(hash),
		Groups:       strings.Join(groups, ","),
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	return s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "username"}},
		DoUpdates: clause.Assignments(map[string]any{
			"password_hash": user.PasswordHash,
			"groups":        user.Groups,
		}),
	}).Create(&user).Error
}

// SetEnabled enables or disables a user.
func (s *DBStore) SetEnabled(username string, enabled bool) error {
	return s.db.Model(&coredb.User{}).Where("username = ?", username).
		Update("enabled", enabled).Error
}

// AddUserAnonymous creates or updates a user without a password.
// This account is used as a fallback when no credentials are provided.
func (s *DBStore) AddUserAnonymous(username string, groups ...string) error {
	user := coredb.User{
		Username:     username,
		PasswordHash: "", // no password
		Groups:       strings.Join(groups, ","),
		CreatedAt:    time.Now().UTC(),
	}
	return s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "username"}},
		DoUpdates: clause.Assignments(map[string]any{
			"password_hash": "",
			"groups":        user.Groups,
		}),
	}).Create(&user).Error
}

// UpdateGroups updates only a user's groups (without touching the password).
func (s *DBStore) UpdateGroups(username string, groups ...string) error {
	return s.db.Model(&coredb.User{}).Where("username = ?", username).
		Update("groups", strings.Join(groups, ",")).Error
}

// RemoveUser deletes a user.
func (s *DBStore) RemoveUser(username string) error {
	return s.db.Where("username = ?", username).Delete(&coredb.User{}).Error
}

// ListUsers returns all users sorted by name.
func (s *DBStore) ListUsers() ([]UserInfo, error) {
	var users []coredb.User
	if err := s.db.Order("username").Find(&users).Error; err != nil {
		return nil, err
	}
	result := make([]UserInfo, len(users))
	for i, u := range users {
		info := UserInfo{
			Username:    u.Username,
			IsAnonymous: u.PasswordHash == "",
			Enabled:     u.Enabled,
			CreatedAt:   u.CreatedAt,
		}
		if u.Groups != "" {
			info.Groups = strings.Split(u.Groups, ",")
		} else {
			info.Groups = []string{}
		}
		result[i] = info
	}
	return result, nil
}

// GetGroups returns a user's groups from the database.
// Returns nil if the user does not exist or has no groups.
func (s *DBStore) GetGroups(username string) []string {
	var user coredb.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil
	}
	if user.Groups == "" {
		return nil
	}
	return strings.Split(user.Groups, ",")
}

// Close is kept for compatibility; the shared DB is closed by the entry point.
func (s *DBStore) Close() error { return nil }
