package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"multirepo-proxy/auth/basic"
	"multirepo-proxy/auth/bruteforce"
	authldap "multirepo-proxy/auth/ldap"
	authoidc "multirepo-proxy/auth/oidc"
	"multirepo-proxy/auth/userctx"
	"multirepo-proxy/config"
	coredb "multirepo-proxy/core/db"

	"gorm.io/gorm"
)

// Authenticator protects HTTP handlers with an authentication layer.
type Authenticator interface {
	Middleware(next http.Handler) http.Handler
	RegisterRoutes(mux *http.ServeMux)
}

// NewFromConfig builds the Authenticator described by cfg.
// db is the shared GORM connection — used by the "basic" provider and for group resolution.
// Returns a no-op authenticator when provider is "none" or "".
// When brute_force.enabled is true, 401 responses increment a per-IP counter;
// after MaxFailures failures the IP is blocked for BlockDuration.
func NewFromConfig(cfg config.AuthConfig, db *gorm.DB) (Authenticator, error) {
	var inner Authenticator
	var err error

	switch cfg.Provider {
	case "", "none":
		return &noneAuth{}, nil

	case "basic":
		inner, err = basic.New(cfg.Basic, db)

	case "ldap":
		ldapAuth, ldapErr := authldap.New(cfg.LDAP)
		if ldapErr != nil {
			return nil, ldapErr
		}
		// DB fallback: tries local credentials if LDAP rejects.
		if cfg.LocalUsers && db != nil {
			dbStore := basic.NewDBStore(db)
			inner = &ldapWithLocalFallback{ldap: ldapAuth, dbStore: dbStore, realm: cfg.LDAP.Realm}
		} else {
			inner = ldapAuth
		}

	case "oidc":
		secret := cfg.SessionSecret
		if secret == "" {
			b := make([]byte, 32)
			rand.Read(b) //nolint:errcheck
			secret = hex.EncodeToString(b)
			log.Println("[auth] WARNING: auth.session_secret not configured — " +
				"sessions will not survive server restarts")
		}
		oidcAuth, oidcErr := authoidc.New(cfg.OIDC, secret)
		if oidcErr != nil {
			return nil, oidcErr
		}
		// DB fallback: accepts Authorization: Basic from the DB without OIDC redirect.
		if cfg.LocalUsers && db != nil {
			localBasic, localErr := basic.New(cfg.Basic, db)
			if localErr != nil {
				return nil, localErr
			}
			inner = &oidcWithLocalFallback{oidc: oidcAuth, localBasic: localBasic}
		} else {
			inner = oidcAuth
		}

	default:
		return nil, fmt.Errorf("unknown auth provider %q (supported: none, basic, ldap, oidc)", cfg.Provider)
	}

	if err != nil {
		return nil, err
	}

	bf := cfg.BruteForce
	if bf.Enabled {
		maxFailures := bf.MaxFailures
		if maxFailures <= 0 {
			maxFailures = 3
		}
		blockDur := 5 * time.Minute
		if bf.BlockDuration != "" {
			d, err := time.ParseDuration(bf.BlockDuration)
			if err != nil {
				return nil, fmt.Errorf("invalid auth.brute_force.block_duration %q: %w", bf.BlockDuration, err)
			}
			blockDur = d
		}

		log.Printf("[auth] brute-force protection enabled: block after %d failures for %s",
			maxFailures, blockDur)

		inner = &bruteForceAuth{
			inner:   inner,
			tracker: bruteforce.New(maxFailures, blockDur),
		}
	}

	// Enriches the context with groups from the DB after successful authentication.
	if db != nil {
		return &groupEnrichAuth{inner: inner, db: db}, nil
	}
	return inner, nil
}

// ─────────────────────────────────────────────
// groupEnrichAuth — injects groups into the context
// ─────────────────────────────────────────────

// groupEnrichAuth is a transparent wrapper that, after successful authentication,
// queries the DB to load the user's groups and injects them into the context.
type groupEnrichAuth struct {
	inner Authenticator
	db    *gorm.DB
}

func (g *groupEnrichAuth) RegisterRoutes(mux *http.ServeMux) { g.inner.RegisterRoutes(mux) }

func (g *groupEnrichAuth) Middleware(next http.Handler) http.Handler {
	// Intercept "next" to enrich the request with groups before calling it.
	// If the provider (e.g. LDAP with group_base_dn) already resolved groups, do not overwrite.
	enriched := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := userctx.Username(r)
		if username != "" && !userctx.GroupsResolved(r) {
			groups := lookupGroupsFromDB(g.db, username)
			r = userctx.WithIdentity(r, username, groups)
		}
		next.ServeHTTP(w, r)
	})
	return g.inner.Middleware(enriched)
}

// lookupGroupsFromDB reads a user's groups from the users table.
func lookupGroupsFromDB(db *gorm.DB, username string) []string {
	var u coredb.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		log.Printf("[auth] user %q not found in local database — no groups assigned", username)
		return nil
	}
	if u.Groups == "" {
		log.Printf("[auth] user %q found but has no assigned groups", username)
		return nil
	}
	gs := strings.Split(u.Groups, ",")
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		if t := strings.TrimSpace(g); t != "" {
			out = append(out, t)
		}
	}
	log.Printf("[auth] DB groups for %q: %v", username, out)
	return out
}

// ─────────────────────────────────────────────
// bruteForceAuth
// ─────────────────────────────────────────────

type bruteForceAuth struct {
	inner   Authenticator
	tracker *bruteforce.Tracker
}

func (b *bruteForceAuth) RegisterRoutes(mux *http.ServeMux) { b.inner.RegisterRoutes(mux) }

func (b *bruteForceAuth) Middleware(next http.Handler) http.Handler {
	protected := b.inner.Middleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := bruteforce.ExtractIP(r)

		if blocked, remaining := b.tracker.IsBlocked(ip); blocked {
			log.Printf("[auth] IP %s blocked — %s remaining", ip, remaining.Round(time.Second))
			b.tracker.Deny(w, remaining)
			return
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		protected.ServeHTTP(rec, r)

		if rec.status == http.StatusUnauthorized {
			b.tracker.RecordFailure(ip)
			if blocked, remaining := b.tracker.IsBlocked(ip); blocked {
				log.Printf("[auth] IP %s quarantined after %d failures (%s)",
					ip, b.tracker.Failures(ip), remaining.Round(time.Second))
			}
		} else if rec.status < 400 {
			b.tracker.RecordSuccess(ip)
		}
	})
}

// ─────────────────────────────────────────────
// statusRecorder
// ─────────────────────────────────────────────

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// ─────────────────────────────────────────────
// noneAuth
// ─────────────────────────────────────────────

type noneAuth struct{}

func (n *noneAuth) Middleware(next http.Handler) http.Handler { return next }
func (n *noneAuth) RegisterRoutes(_ *http.ServeMux)           {}

// ─────────────────────────────────────────────
// ldapWithLocalFallback
// ─────────────────────────────────────────────

// ldapWithLocalFallback tries LDAP first, then the local database if LDAP rejects.
// Both use HTTP Basic Auth, so no buffering is needed:
// credentials are verified at the application level before calling next.
type ldapWithLocalFallback struct {
	ldap    *authldap.LDAPAuth
	dbStore *basic.DBStore
	realm   string
}

func (l *ldapWithLocalFallback) RegisterRoutes(mux *http.ServeMux) { l.ldap.RegisterRoutes(mux) }

func (l *ldapWithLocalFallback) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && password != "" {
			// LDAP attempt.
			if userDN, err := l.ldap.Authenticate(username, password); err == nil {
				req := l.ldap.BuildRequest(r, username, userDN)
				next.ServeHTTP(w, req)
				return
			}
			// Fallback: local database.
			if ok2, _ := l.dbStore.Verify(username, password); ok2 {
				log.Printf("[auth] DB fallback accepted for %q", username)
				next.ServeHTTP(w, userctx.WithUsername(r, username))
				return
			}
		}
		realm := l.realm
		if realm == "" {
			realm = "multirepo-proxy admin"
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, realm))
		http.Error(w, "Authentication required", http.StatusUnauthorized)
	})
}

// ─────────────────────────────────────────────
// oidcWithLocalFallback
// ─────────────────────────────────────────────

// oidcWithLocalFallback routes requests based on the presence of a Basic Auth header:
//   - Authorization: Basic present → authenticate via local database (no OIDC redirect)
//   - No Basic Auth               → normal OIDC flow (redirect to provider)
type oidcWithLocalFallback struct {
	oidc       Authenticator
	localBasic Authenticator
}

func (o *oidcWithLocalFallback) RegisterRoutes(mux *http.ServeMux) { o.oidc.RegisterRoutes(mux) }

func (o *oidcWithLocalFallback) Middleware(next http.Handler) http.Handler {
	oidcMid := o.oidc.Middleware(next)
	localMid := o.localBasic.Middleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hasBasic := r.BasicAuth()
		if hasBasic {
			localMid.ServeHTTP(w, r)
		} else {
			oidcMid.ServeHTTP(w, r)
		}
	})
}
