package basic

import (
	"fmt"
	"net/http"

	"multirepo-proxy/auth/userctx"
	"multirepo-proxy/config"
	"gorm.io/gorm"
)

// BasicAuth implements HTTP Basic authentication (RFC 7617).
// Verifies credentials in order: htpasswd file → shared GORM database.
// If no credentials are provided and an "anonymous" user (without a password)
// exists in the database, the request is handled with the anonymous identity.
type BasicAuth struct {
	realm   string
	stores  []UserStore
	dbStore *DBStore // nil if no DB; used for anonymous fallback
}

// New creates a BasicAuth from the configuration and shared GORM connection.
// At least one source (htpasswd_file or db) must be available.
func New(cfg config.BasicAuthConfig, db *gorm.DB) (*BasicAuth, error) {
	ba := &BasicAuth{realm: cfg.Realm}
	if ba.realm == "" {
		ba.realm = "multirepo-proxy admin"
	}

	if cfg.HtpasswdFile != "" {
		ba.stores = append(ba.stores, &HtpasswdStore{Path: cfg.HtpasswdFile})
	}
	if db != nil {
		dbStore := NewDBStore(db)
		ba.stores = append(ba.stores, dbStore)
		ba.dbStore = dbStore
	}
	if len(ba.stores) == 0 {
		return nil, fmt.Errorf("basic auth: no source configured (htpasswd_file or db required)")
	}
	return ba, nil
}

// Middleware verifies credentials on each request.
// If no credentials are provided and an "anonymous" user without a password
// exists in the database, the request continues with the "anonymous" identity.
// Returns 401 + WWW-Authenticate if absent or invalid and no anonymous user.
func (ba *BasicAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			verified, err := ba.verify(username, password)
			if err == nil && verified {
				next.ServeHTTP(w, userctx.WithUsername(r, username))
				return
			}
		}

		// Fallback: if no credentials provided and an anonymous user exists.
		if !ok && ba.dbStore != nil && ba.dbStore.HasAnonymous() {
			next.ServeHTTP(w, userctx.WithUsername(r, "anonymous"))
			return
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, ba.realm))
		http.Error(w, "Authentication required", http.StatusUnauthorized)
	})
}

// RegisterRoutes — no additional endpoints for basic auth.
func (ba *BasicAuth) RegisterRoutes(_ *http.ServeMux) {}

// verify iterates through stores in order until a match is found.
func (ba *BasicAuth) verify(username, password string) (bool, error) {
	for _, store := range ba.stores {
		ok, err := store.Verify(username, password)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
