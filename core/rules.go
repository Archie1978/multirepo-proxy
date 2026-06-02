package core

import (
	"fmt"

	coredb "multirepo-proxy/core/db"

	"gorm.io/gorm"
)

const (
	RuleCVSSMax     = "cvss_max"
	RuleEPSSMax     = "epss_max"
	RuleCVSSSum     = "cvss_sum"
	RuleCVSSEPSSSum = "cvss_epss_sum"
)

// RuleRecord is the public view of a rule (JSON API + evaluation).
type RuleRecord struct {
	ID        uint    `json:"id"`
	RepoType  string  `json:"repo_type"`
	RuleType  string  `json:"rule_type"`
	Threshold float64 `json:"threshold"`
	Enabled   bool    `json:"enabled"`
}

// EvalResult describes the result of evaluating rules for a package.
type EvalResult struct {
	// HasRules indicates that active rules exist for this repo_type.
	// When false, the package stays pending (manual review required).
	HasRules  bool
	Triggered []string // descriptions of triggered rules; empty = all passed
}

// RuleStore manages the persistence and evaluation of auto-quarantine rules.
type RuleStore struct {
	db *gorm.DB
}

func NewRuleStore(db *gorm.DB) *RuleStore { return &RuleStore{db: db} }

// List returns all rules sorted by ascending id.
func (s *RuleStore) List() ([]*RuleRecord, error) {
	var rows []coredb.Rule
	if err := s.db.Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]*RuleRecord, len(rows))
	for i, r := range rows {
		result[i] = rowToRule(&r)
	}
	return result, nil
}

// Create inserts a new rule and sets r.ID.
func (s *RuleStore) Create(r *RuleRecord) error {
	row := coredb.Rule{
		RepoType:  r.RepoType,
		RuleType:  r.RuleType,
		Threshold: r.Threshold,
		Enabled:   r.Enabled,
	}
	if err := s.db.Create(&row).Error; err != nil {
		return err
	}
	r.ID = row.ID
	return nil
}

// Update updates all fields of an existing rule.
func (s *RuleStore) Update(r *RuleRecord) error {
	return s.db.Model(&coredb.Rule{}).Where("id = ?", r.ID).
		Updates(map[string]any{
			"repo_type":  r.RepoType,
			"rule_type":  r.RuleType,
			"threshold":  r.Threshold,
			"enabled":    r.Enabled,
		}).Error
}

// Delete removes a rule by id.
func (s *RuleStore) Delete(id uint) error {
	return s.db.Delete(&coredb.Rule{}, id).Error
}

// Evaluate checks the active rules for repoType against the provided findings.
//
//   - HasRules=false → no rules → leave pending (manual review)
//   - HasRules=true, Triggered=[] → all passed → auto-approval
//   - HasRules=true, Triggered≠[] → at least one triggered → stay pending
func (s *RuleStore) Evaluate(repoType string, findings []SecurityFinding) (EvalResult, error) {
	var rows []coredb.Rule
	err := s.db.
		Where("enabled = ? AND (repo_type = ? OR repo_type = ?)", true, repoType, "*").
		Find(&rows).Error
	if err != nil {
		return EvalResult{}, err
	}
	if len(rows) == 0 {
		return EvalResult{HasRules: false}, nil
	}

	res := EvalResult{HasRules: true}
	for _, rule := range rows {
		if msg := checkRule(rule, findings); msg != "" {
			res.Triggered = append(res.Triggered, msg)
		}
	}
	return res, nil
}

// checkRule returns a message if the rule is triggered, "" otherwise.
func checkRule(rule coredb.Rule, findings []SecurityFinding) string {
	switch rule.RuleType {
	case RuleCVSSMax:
		for _, f := range findings {
			if f.CVSS > rule.Threshold {
				return fmt.Sprintf("CVSS %.1f > threshold %.1f (%s)", f.CVSS, rule.Threshold, f.ID)
			}
		}

	case RuleEPSSMax:
		for _, f := range findings {
			if f.EPSS > rule.Threshold {
				return fmt.Sprintf("EPSS %.4f > threshold %.4f (%s)", f.EPSS, rule.Threshold, f.ID)
			}
		}

	case RuleCVSSSum:
		// Deduplicate by CVE (max CVSS per ID to avoid double-counting from multiple sources).
		best := map[string]float64{}
		for _, f := range findings {
			if f.CVSS > best[f.ID] {
				best[f.ID] = f.CVSS
			}
		}
		var sum float64
		for _, v := range best {
			sum += v
		}
		if sum > rule.Threshold {
			return fmt.Sprintf("Σ CVSS %.2f > threshold %.2f", sum, rule.Threshold)
		}

	case RuleCVSSEPSSSum:
		// Σ(CVSS×EPSS) per unique CVE.
		best := map[string]float64{}
		for _, f := range findings {
			if s := f.CVSS * f.EPSS; s > best[f.ID] {
				best[f.ID] = s
			}
		}
		var sum float64
		for _, v := range best {
			sum += v
		}
		if sum > rule.Threshold {
			return fmt.Sprintf("Σ CVSS×EPSS %.4f > threshold %.4f", sum, rule.Threshold)
		}
	}
	return ""
}

func rowToRule(r *coredb.Rule) *RuleRecord {
	return &RuleRecord{
		ID:        r.ID,
		RepoType:  r.RepoType,
		RuleType:  r.RuleType,
		Threshold: r.Threshold,
		Enabled:   r.Enabled,
	}
}
