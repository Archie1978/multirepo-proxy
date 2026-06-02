// Package userctx stores and reads the authenticated identity (username + groups) in the HTTP context.
// It is used by all authentication middlewares to propagate identity
// to handlers without relying on HTTP headers (which can be forged).
package userctx

import (
	"context"
	"net/http"
)

type ctxKey struct{}

type identity struct {
	username string
	groups   []string
}

// WithUsername returns a copy of r with the username in its context (empty groups).
// Kept for compatibility with providers that do not yet handle groups.
func WithUsername(r *http.Request, username string) *http.Request {
	return WithIdentity(r, username, nil)
}

// WithIdentity returns a copy of r with the complete identity (username + groups).
func WithIdentity(r *http.Request, username string, groups []string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, identity{username, groups}))
}

// Username reads the authenticated username from the request context.
// Returns "" if no user is present (provider "none" or unauthenticated request).
func Username(r *http.Request) string {
	id, _ := r.Context().Value(ctxKey{}).(identity)
	return id.username
}

// Groups reads the authenticated user's groups from the context.
// Returns nil if no user is present or if groups have not yet been resolved.
func Groups(r *http.Request) []string {
	id, _ := r.Context().Value(ctxKey{}).(identity)
	return id.groups
}

// GroupsResolved indicates whether groups have already been resolved by an authentication provider.
// Returns true if WithIdentity was called with a non-nil slice (even empty),
// false if only WithUsername was called (groups not yet determined).
// Allows groupEnrichAuth to not overwrite groups already set (e.g. from LDAP).
func GroupsResolved(r *http.Request) bool {
	id, ok := r.Context().Value(ctxKey{}).(identity)
	return ok && id.groups != nil
}
