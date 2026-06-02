package core

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	coredb "multirepo-proxy/core/db"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ─────────────────────────────────────────────
// GroupRecord — public representation of a group
// ─────────────────────────────────────────────

// GroupRecord is the JSON view of a permission group.
type GroupRecord struct {
	Name            string    `json:"name"`
	Repos           []string  `json:"repos"`             // ["*"] = all, ["apt","r"] = filter
	CanApprove      bool      `json:"can_approve"`       // approve/reject/revoke
	CanManage       bool      `json:"can_manage"`        // manage groups + auto rules
	CanRefreshIndex bool      `json:"can_refresh_index"` // trigger apt/CRAN index refresh
	CreatedAt       time.Time `json:"created_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}

// ─────────────────────────────────────────────
// Permissions — effective rights resolution
// ─────────────────────────────────────────────

// Permissions represents the effective rights of a user
// calculated by taking the union of all their groups.
type Permissions struct {
	IsAdmin         bool            // "admin" group → implicit superadmin
	AllRepos        bool            // access to all repos
	Repos           map[string]bool // specifically allowed repos
	CanApprove      bool
	CanManage       bool
	CanRefreshIndex bool
}

// AllowsRepo returns true if this repo is accessible.
func (p *Permissions) AllowsRepo(repoType string) bool {
	if p.IsAdmin || p.AllRepos {
		return true
	}
	return p.Repos[repoType]
}

// superadminPerms is the singleton returned for admin or without authentication.
var superadminPerms = &Permissions{
	IsAdmin:         true,
	AllRepos:        true,
	CanApprove:      true,
	CanManage:       true,
	CanRefreshIndex: true,
}

// ─────────────────────────────────────────────
// GroupStore
// ─────────────────────────────────────────────

type GroupStore struct {
	db *gorm.DB
}

func NewGroupStore(db *gorm.DB) *GroupStore {
	return &GroupStore{db: db}
}

// List returns all groups sorted by name.
func (s *GroupStore) List() ([]*GroupRecord, error) {
	var rows []coredb.Group
	if err := s.db.Order("name").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*GroupRecord, 0, len(rows))
	for _, r := range rows {
		g, err := fromDBGroup(r)
		if err != nil {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

// Get returns a group by name.
func (s *GroupStore) Get(name string) (*GroupRecord, error) {
	var row coredb.Group
	if err := s.db.Where("name = ?", name).First(&row).Error; err != nil {
		return nil, fmt.Errorf("group %q not found", name)
	}
	return fromDBGroup(row)
}

// Create inserts a new group. Returns an error if the name already exists.
func (s *GroupStore) Create(g *GroupRecord) error {
	row, err := toDBGroup(g)
	if err != nil {
		return err
	}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
}

// Update updates an existing group.
func (s *GroupStore) Update(g *GroupRecord) error {
	row, err := toDBGroup(g)
	if err != nil {
		return err
	}
	return s.db.Save(&row).Error
}

// Delete removes a group by name.
func (s *GroupStore) Delete(name string) error {
	return s.db.Where("name = ?", name).Delete(&coredb.Group{}).Error
}

// ResolvePerms computes the effective permissions for a set of groups.
// If "admin" is in the list → implicit superadmin, all rights.
// If the list is empty → no rights (authentication is required but the user has no group).
// noAuth == true → superadmin (provider "none").
func (s *GroupStore) ResolvePerms(groups []string, noAuth bool) *Permissions {
	if noAuth {
		return superadminPerms
	}
	for _, g := range groups {
		if g == "admin" {
			return superadminPerms
		}
	}

	p := &Permissions{Repos: make(map[string]bool)}
	for _, name := range groups {
		rec, err := s.Get(name)
		if err != nil {
			log.Printf("[auth] group %q not found in database — create it in the Groups tab", name)
			continue
		}
		if rec.CanApprove {
			p.CanApprove = true
		}
		if rec.CanManage {
			p.CanManage = true
		}
		if rec.CanRefreshIndex {
			p.CanRefreshIndex = true
		}
		for _, repo := range rec.Repos {
			if repo == "*" {
				p.AllRepos = true
			} else {
				p.Repos[repo] = true
			}
		}
	}
	return p
}

// ─────────────────────────────────────────────
// DB ↔ GroupRecord conversions
// ─────────────────────────────────────────────

func fromDBGroup(row coredb.Group) (*GroupRecord, error) {
	var repos []string
	if row.Repos != "" && row.Repos != "null" {
		if err := json.Unmarshal([]byte(row.Repos), &repos); err != nil {
			return nil, fmt.Errorf("invalid repos JSON for %q: %w", row.Name, err)
		}
	}
	if repos == nil {
		repos = []string{}
	}
	return &GroupRecord{
		Name:            row.Name,
		Repos:           repos,
		CanApprove:      row.CanApprove,
		CanManage:       row.CanManage,
		CanRefreshIndex: row.CanRefreshIndex,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}, nil
}

func toDBGroup(g *GroupRecord) (coredb.Group, error) {
	repos := g.Repos
	if repos == nil {
		repos = []string{}
	}
	b, err := json.Marshal(repos)
	if err != nil {
		return coredb.Group{}, fmt.Errorf("cannot serialize repos: %w", err)
	}
	return coredb.Group{
		Name:            g.Name,
		Repos:           string(b),
		CanApprove:      g.CanApprove,
		CanManage:       g.CanManage,
		CanRefreshIndex: g.CanRefreshIndex,
	}, nil
}
