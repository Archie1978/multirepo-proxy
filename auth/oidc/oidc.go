package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"multirepo-proxy/auth/userctx"
	"multirepo-proxy/config"
)

// OIDCAuth implements OpenID Connect authentication.
//
// Flow:
//  1. Unauthenticated request → redirect to /admin/auth/login
//  2. /admin/auth/login       → state cookie + redirect to provider
//  3. /admin/auth/callback    → state verification, code exchange, session cookie
//  4. /admin/auth/logout      → delete session cookie + redirect /admin/
type OIDCAuth struct {
	oauth2Cfg *oauth2.Config
	verifier  *gooidc.IDTokenVerifier
	secret    string
	ttl       time.Duration
}

// New initializes OIDCAuth by contacting the provider for its discovery.
func New(cfg config.OIDCAuthConfig, sessionSecret string) (*OIDCAuth, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer not configured")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: client_id not configured")
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: redirect_url not configured")
	}

	provider, err := gooidc.NewProvider(context.Background(), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: provider discovery for %q: %w", cfg.Issuer, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}

	ttl := time.Duration(cfg.SessionTTL) * time.Hour
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}

	return &OIDCAuth{
		oauth2Cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		secret:   sessionSecret,
		ttl:      ttl,
	}, nil
}

// Middleware verifies the session cookie. Redirects to /admin/auth/login if absent or expired.
func (o *OIDCAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := o.sessionFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/admin/auth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, userctx.WithUsername(r, session.Email))
	})
}

// RegisterRoutes registers the three OIDC endpoints on the provided mux.
func (o *OIDCAuth) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/auth/login", o.handleLogin)
	mux.HandleFunc("/admin/auth/callback", o.handleCallback)
	mux.HandleFunc("/admin/auth/logout", o.handleLogout)
}

// handleLogin generates a random state, stores it in a cookie, and redirects to the provider.
func (o *OIDCAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomHex(16)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/admin/auth/callback",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, o.oauth2Cfg.AuthCodeURL(state), http.StatusFound)
}

// handleCallback receives the authorization code, verifies the state, exchanges the code,
// validates the ID token and sets the session cookie.
func (o *OIDCAuth) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify anti-CSRF state
	stateCk, err := r.Cookie(stateCookie)
	if err != nil || stateCk.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid OIDC state", http.StatusBadRequest)
		return
	}
	// Invalidate the state cookie
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Path: "/admin/auth/callback", MaxAge: -1})

	// Exchange the code for tokens
	token, err := o.oauth2Cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("[oidc] code exchange: %v", err)
		http.Error(w, "OIDC authentication failed", http.StatusInternalServerError)
		return
	}

	// Verify the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "id_token absent from response", http.StatusInternalServerError)
		return
	}
	idToken, err := o.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("[oidc] id_token verification: %v", err)
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	// Extract claims
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("[oidc] claims: %v", err)
	}

	// Set the signed session cookie
	sess := Session{
		Sub:    idToken.Subject,
		Email:  claims.Email,
		Expiry: time.Now().Add(o.ttl),
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.encode(o.secret),
		Path:     "/admin/",
		MaxAge:   int(o.ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/admin/", http.StatusFound)
}

// handleLogout deletes the session cookie and redirects to /admin/.
func (o *OIDCAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookie,
		Value:   "",
		Path:    "/admin/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
	http.Redirect(w, r, "/admin/", http.StatusFound)
}

func (o *OIDCAuth) sessionFromRequest(r *http.Request) (*Session, error) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, err
	}
	return decodeSession(ck.Value, o.secret)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
