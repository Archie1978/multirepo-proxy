package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"multirepo-proxy/auth/basic"
	"multirepo-proxy/auth/userctx"
	"multirepo-proxy/core"
	aptdriver "multirepo-proxy/drivers/apt"
	"multirepo-proxy/drivers/cran"
	"multirepo-proxy/logs"
)

// AdminAPI exposes the REST management endpoints.
// It registers on a dedicated ServeMux (apiMux) that only receives
// /admin/api/* requests — isolated from the main registry.
type AdminAPI struct {
	Quarantine *core.QuarantineStore
	Rules      *core.RuleStore
	Groups     *core.GroupStore
	Users      *basic.DBStore
	AptDriver  *aptdriver.AptDriver
	CRANDriver *cran.CRANDriver

	log logs.Logger
	mux *http.ServeMux
}

// enrichedRequest enriches PackageRequest with security scan results.
type enrichedRequest struct {
	*core.PackageRequest
	ScanStatus      string                 `json:"scan_status"`
	Vulnerabilities []core.SecurityFinding `json:"vulnerabilities"`
}

// NewAdminAPI creates the API and registers all its routes.
func NewAdminAPI(q *core.QuarantineStore, rules *core.RuleStore, groups *core.GroupStore, users *basic.DBStore, apt *aptdriver.AptDriver, cranDrv *cran.CRANDriver, logger logs.Logger) *AdminAPI {
	a := &AdminAPI{
		Quarantine: q,
		Rules:      rules,
		Groups:     groups,
		Users:      users,
		AptDriver:  apt,
		CRANDriver: cranDrv,
		log:        logger,
		mux:        http.NewServeMux(),
	}
	a.mux.HandleFunc("/admin/api/requests", a.listRequests)
	a.mux.HandleFunc("/admin/api/requests/", a.handleRequest)
	a.mux.HandleFunc("/admin/api/requests/history/", a.requestHistory)
	a.mux.HandleFunc("/admin/api/rules", a.handleRules)
	a.mux.HandleFunc("/admin/api/rules/", a.handleRule)
	a.mux.HandleFunc("/admin/api/index/refresh", a.refreshIndex)
	a.mux.HandleFunc("/admin/api/gpg/keys", a.manageGPGKeys)
	a.mux.HandleFunc("/admin/api/groups", a.handleGroups)
	a.mux.HandleFunc("/admin/api/groups/", a.handleGroup)
	a.mux.HandleFunc("/admin/api/users", a.handleUsers)
	a.mux.HandleFunc("/admin/api/users/", a.handleUser)
	a.mux.HandleFunc("/admin/api/me", a.handleMe)
	return a
}

// ServeHTTP delegates to the internal mux — allows using AdminAPI
// directly as an http.Handler.
func (a *AdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// ── Permission helpers ─────────────────────────────────────────────────────────

// perms resolves the effective permissions of the current user.
// If no username is present (provider "none"), implicit superadmin.
func (a *AdminAPI) perms(r *http.Request) *core.Permissions {
	username := userctx.Username(r)
	noAuth := username == ""
	groups := userctx.Groups(r)
	return a.Groups.ResolvePerms(groups, noAuth)
}

func forbidden(w http.ResponseWriter) {
	http.Error(w, "access denied", http.StatusForbidden)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// GET /admin/api/me → effective permissions of the current user
func (a *AdminAPI) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := a.perms(r)
	username := userctx.Username(r)
	groups := userctx.Groups(r)
	if groups == nil {
		groups = []string{}
	}

	repos := []string{}
	if p.AllRepos || p.IsAdmin {
		repos = []string{"*"}
	} else {
		for repo := range p.Repos {
			repos = append(repos, repo)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"username": username,
		"groups":   groups,
		"permissions": map[string]any{
			"is_admin":          p.IsAdmin,
			"repos":             repos,
			"all_repos":         p.AllRepos || p.IsAdmin,
			"can_approve":       p.CanApprove,
			"can_manage":        p.CanManage,
			"can_refresh_index": p.CanRefreshIndex,
		},
	})
}

// GET /admin/api/requests?status=pending&repo=apt
func (a *AdminAPI) listRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statusStr := r.URL.Query().Get("status")
	repoFilter := r.URL.Query().Get("repo")

	var filter *core.Status
	if statusStr != "" {
		s := core.Status(statusStr)
		filter = &s
	}

	list, err := a.Quarantine.List(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Filter by repo requested in query string.
	if repoFilter != "" {
		filtered := make([]*core.PackageRequest, 0, len(list))
		for _, req := range list {
			if req.RepoType == repoFilter {
				filtered = append(filtered, req)
			}
		}
		list = filtered
	}

	// For Docker: only show the root manifest (not blobs or sub-manifests).
	{
		filtered := make([]*core.PackageRequest, 0, len(list))
		for _, req := range list {
			if req.RepoType == "docker" && isDockerChildKey(req.CacheKey) {
				continue
			}
			filtered = append(filtered, req)
		}
		list = filtered
	}

	// Filter according to repos allowed for the current user.
	p := a.perms(r)
	if !p.AllRepos && !p.IsAdmin {
		filtered := make([]*core.PackageRequest, 0, len(list))
		for _, req := range list {
			if p.Repos[req.RepoType] {
				filtered = append(filtered, req)
			}
		}
		list = filtered
	}

	if list == nil {
		list = []*core.PackageRequest{}
	}

	// Enrich with security data.
	allFindings, err := a.Quarantine.GetAllFindings()
	if err != nil {
		a.log.Warn("security findings unavailable", logs.Err(err))
	}
	scanStatuses, err := a.Quarantine.GetScanStatuses()
	if err != nil {
		a.log.Warn("security scan statuses unavailable", logs.Err(err))
	}

	enriched := make([]enrichedRequest, 0, len(list))
	for _, req := range list {
		findings := allFindings[req.ID]
		if findings == nil {
			findings = []core.SecurityFinding{}
		}
		status := scanStatuses[req.ID]
		if status == "" {
			status = "pending"
		}
		enriched = append(enriched, enrichedRequest{
			PackageRequest:  req,
			ScanStatus:      status,
			Vulnerabilities: findings,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enriched)
}

// POST /admin/api/requests/{id}/approve  body: {"comment":"..."}
// POST /admin/api/requests/{id}/reject   body: {"comment":"..."}
// POST /admin/api/requests/{id}/revoke   body: {"comment":"..."}
func (a *AdminAPI) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Path: /admin/api/requests/{id}/{action}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "expected /admin/api/requests/{id}/{approve|reject|revoke}", http.StatusBadRequest)
		return
	}
	id, action := parts[3], parts[4]

	if !a.perms(r).CanApprove {
		forbidden(w)
		return
	}

	var body struct {
		Comment string `json:"comment"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	reviewer := userctx.Username(r)
	if reviewer == "" {
		reviewer = r.RemoteAddr
	}

	var err error
	switch action {
	case "approve":
		err = a.Quarantine.Approve(id, reviewer, body.Comment)
	case "reject":
		err = a.Quarantine.Reject(id, reviewer, body.Comment)
	case "revoke":
		err = a.Quarantine.Revoke(id, reviewer, body.Comment)
	default:
		http.Error(w, "unknown action: "+action, http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	req, _ := a.Quarantine.Get(id)

	fields := []logs.Field{
		logs.String("action", action),
		logs.String("reviewer", reviewer),
		logs.String("package_id", id),
	}
	if req != nil {
		fields = append(fields,
			logs.String("repo", req.RepoType),
			logs.String("name", req.Name),
			logs.String("version", req.Version),
		)
	}
	if body.Comment != "" {
		fields = append(fields, logs.String("comment", body.Comment))
	}
	a.log.Info("package decision", fields...)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// POST /admin/api/index/refresh?repo=apt&distrib=jammy&component=main&arch=amd64
// POST /admin/api/index/refresh?repo=r&contrib=src/contrib
func (a *AdminAPI) refreshIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !a.perms(r).CanRefreshIndex {
		forbidden(w)
		return
	}

	q := r.URL.Query()
	repo := q.Get("repo")

	switch repo {
	case "apt", "":
		distrib := q.Get("distrib")
		if distrib == "" {
			distrib = "jammy"
		}
		component := q.Get("component")
		if component == "" {
			component = "main"
		}
		arch := q.Get("arch")
		if arch == "" {
			arch = "amd64"
		}
		if err := a.AptDriver.RefreshIndex(r.Context(), distrib, component, arch); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case "r":
		contrib := q.Get("contrib")
		if err := a.CRANDriver.RefreshIndex(r.Context(), contrib); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "unknown repo: "+repo+" (supported: apt, r)", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// GET  /admin/api/rules → list all rules
// POST /admin/api/rules → create a rule
func (a *AdminAPI) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := a.Rules.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rules == nil {
			rules = []*core.RuleRecord{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		if !a.perms(r).CanManage {
			forbidden(w)
			return
		}
		var rule core.RuleRecord
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.Rules.Create(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go a.rescanPending()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rule)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// PUT    /admin/api/rules/{id} → update a rule
// DELETE /admin/api/rules/{id} → delete a rule
func (a *AdminAPI) handleRule(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	id64, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	id := uint(id64)

	if !a.perms(r).CanManage {
		forbidden(w)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var rule core.RuleRecord
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rule.ID = id
		if err := a.Rules.Update(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go a.rescanPending()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rule)

	case http.MethodDelete:
		if err := a.Rules.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go a.rescanPending()
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET  /admin/api/groups       → list all groups
// POST /admin/api/groups       → create a group
func (a *AdminAPI) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		groups, err := a.Groups.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if groups == nil {
			groups = []*core.GroupRecord{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)

	case http.MethodPost:
		if !a.perms(r).CanManage {
			forbidden(w)
			return
		}
		var g core.GroupRecord
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if g.Name == "" {
			http.Error(w, "group name is required", http.StatusBadRequest)
			return
		}
		if g.Name == "admin" {
			http.Error(w, "the \"admin\" group is reserved and cannot be created here", http.StatusBadRequest)
			return
		}
		if err := a.Groups.Create(&g); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(g)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// PUT    /admin/api/groups/{name} → update a group
// DELETE /admin/api/groups/{name} → delete a group
func (a *AdminAPI) handleGroup(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	name := parts[3]

	if !a.perms(r).CanManage {
		forbidden(w)
		return
	}
	if name == "admin" {
		http.Error(w, "the \"admin\" group is reserved and cannot be modified here", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var g core.GroupRecord
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		g.Name = name
		if err := a.Groups.Update(&g); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(g)

	case http.MethodDelete:
		if err := a.Groups.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// isDockerChildKey returns true for Docker blobs and sub-manifests
// that are managed in cascade and should not appear directly in the UI.
func isDockerChildKey(cacheKey string) bool {
	return strings.Contains(cacheKey, "/blobs/") || strings.Count(cacheKey, "/manifests/") > 1
}

// GET /admin/api/requests/history/{id} → decision history for a package
func (a *AdminAPI) requestHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	id := parts[4]
	entries, err := a.Quarantine.GetAuditLog(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []core.AuditEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// GET  /admin/api/users       → list all users
// POST /admin/api/users       → create a user (with or without password)
func (a *AdminAPI) handleUsers(w http.ResponseWriter, r *http.Request) {
	if a.Users == nil {
		http.Error(w, "user management not available (provider != basic)", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := a.Users.ListUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		if !a.perms(r).CanManage {
			forbidden(w)
			return
		}
		var body struct {
			Username string   `json:"username"`
			Password string   `json:"password"` // empty → anonymous user
			Groups   []string `json:"groups"`
			Enabled  *bool    `json:"enabled"`  // nil → true by default
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Username == "" {
			http.Error(w, "username required", http.StatusBadRequest)
			return
		}
		var err error
		if body.Password == "" {
			err = a.Users.AddUserAnonymous(body.Username, body.Groups...)
		} else {
			err = a.Users.AddUser(body.Username, body.Password, body.Groups...)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Apply enabled status if explicitly provided and different from true.
		if body.Enabled != nil && !*body.Enabled {
			if err := a.Users.SetEnabled(body.Username, false); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"username": body.Username})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// PUT    /admin/api/users/{name}          → update groups
// PUT    /admin/api/users/{name}/password → change password
// DELETE /admin/api/users/{name}          → delete
func (a *AdminAPI) handleUser(w http.ResponseWriter, r *http.Request) {
	if a.Users == nil {
		http.Error(w, "user management not available (provider != basic)", http.StatusNotImplemented)
		return
	}
	if !a.perms(r).CanManage {
		forbidden(w)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /admin/api/users/{name}           → parts[3] = name
	// /admin/api/users/{name}/password  → parts[3] = name, parts[4] = "password"
	if len(parts) < 4 {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}
	name := parts[3]
	sub := ""
	if len(parts) >= 5 {
		sub = parts[4]
	}

	switch {
	case r.Method == http.MethodDelete && sub == "":
		if name == "admin" {
			http.Error(w, "the \"admin\" user cannot be deleted", http.StatusBadRequest)
			return
		}
		if err := a.Users.RemoveUser(name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut && sub == "":
		var body struct {
			Groups []string `json:"groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.Users.UpdateGroups(name, body.Groups...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut && sub == "password":
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Password == "" {
			http.Error(w, "password cannot be empty", http.StatusBadRequest)
			return
		}
		// Reuse AddUser with upsert — updates only the hash
		if err := a.Users.AddUser(name, body.Password); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut && sub == "enabled":
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.Users.SetEnabled(name, body.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET  /admin/api/gpg/keys → list imported fingerprints
// POST /admin/api/gpg/keys → import a key (body = ASCII-armored or binary GPG)
func (a *AdminAPI) manageGPGKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := a.AptDriver.ListGPGKeys()
		if keys == nil {
			keys = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})

	case http.MethodPost:
		if !a.perms(r).CanManage {
			forbidden(w)
			return
		}
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		if n == 0 {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}
		if err := a.AptDriver.AddGPGKey(buf[:n]); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"key imported"}`))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// rescanPending re-evaluates all pending packages against the current rules
// and auto-approves those that now pass. Runs asynchronously after any rule mutation.
func (a *AdminAPI) rescanPending() {
	status := core.StatusPending
	pending, err := a.Quarantine.List(&status)
	if err != nil {
		a.log.Warn("rescanPending: list pending", logs.Err(err))
		return
	}
	allFindings, err := a.Quarantine.GetAllFindings()
	if err != nil {
		a.log.Warn("rescanPending: get findings", logs.Err(err))
		return
	}
	for _, pkg := range pending {
		result, err := a.Rules.Evaluate(pkg.RepoType, allFindings[pkg.ID])
		if err != nil {
			a.log.Warn("rescanPending: evaluate", logs.Err(err))
			continue
		}
		if result.HasRules && len(result.Triggered) == 0 {
			if err := a.Quarantine.Approve(pkg.ID, "auto", "auto-approved after rule update"); err != nil {
				a.log.Warn("rescanPending: approve", logs.Err(err))
			}
		}
	}
}
