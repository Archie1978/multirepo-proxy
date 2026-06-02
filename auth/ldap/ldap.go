package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"multirepo-proxy/auth/userctx"
	"multirepo-proxy/config"
)

// LDAPAuth implements HTTP Basic authentication verified against an LDAP directory.
//
// Per-request flow:
//  1. Extract credentials via HTTP Basic Auth (RFC 7617)
//  2. Connect to the LDAP server (LDAP or LDAPS)
//  3. Bind with the service account to search for the user's DN
//  4. Bind as the user with the provided password
//  5. If group_base_dn is configured: search LDAP groups and map to local groups
type LDAPAuth struct {
	url           string
	bindDN        string
	bindPassword  string
	baseDN        string
	userFilter    string
	realm         string
	tlsSkipVerify bool
	timeout       time.Duration

	// Group resolution — active only if groupBaseDN is non-empty.
	groupBaseDN    string
	groupFilter    string
	groupAttribute string
	groupMapping   map[string]string
}

// New creates an LDAPAuth from the configuration.
func New(cfg config.LDAPAuthConfig) (*LDAPAuth, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("ldap: url not configured")
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldap: base_dn not configured")
	}

	filter := cfg.UserFilter
	if filter == "" {
		filter = "(uid=%s)"
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "multirepo-proxy admin"
	}

	timeout := 5 * time.Second
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("ldap: invalid timeout %q: %w", cfg.Timeout, err)
		}
		timeout = d
	}

	groupFilter := cfg.GroupFilter
	if groupFilter == "" {
		groupFilter = "(member=%s)"
	}
	groupAttribute := cfg.GroupAttribute
	if groupAttribute == "" {
		groupAttribute = "cn"
	}

	return &LDAPAuth{
		url:            cfg.URL,
		bindDN:         cfg.BindDN,
		bindPassword:   cfg.BindPassword,
		baseDN:         cfg.BaseDN,
		userFilter:     filter,
		realm:          realm,
		tlsSkipVerify:  cfg.TLSSkipVerify,
		timeout:        timeout,
		groupBaseDN:    cfg.GroupBaseDN,
		groupFilter:    groupFilter,
		groupAttribute: groupAttribute,
		groupMapping:   cfg.GroupMapping,
	}, nil
}

// Middleware verifies HTTP Basic credentials against the LDAP directory.
// If group_base_dn is configured, LDAP groups are resolved and mapped to local groups.
// Returns 401 + WWW-Authenticate if absent or invalid.
func (la *LDAPAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && password != "" {
			userDN, err := la.Authenticate(username, password)
			if err == nil {
				var req *http.Request
				if la.groupBaseDN != "" {
					groups := la.resolveGroups(username, userDN)
					req = userctx.WithIdentity(r, username, groups)
				} else {
					req = userctx.WithUsername(r, username)
				}
				next.ServeHTTP(w, req)
				return
			}
			log.Printf("[ldap] authentication failed for %q: %v", username, err)
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, la.realm))
		http.Error(w, "Authentication required", http.StatusUnauthorized)
	})
}

// RegisterRoutes — no additional endpoints for LDAP.
func (la *LDAPAuth) RegisterRoutes(_ *http.ServeMux) {}

// BuildRequest returns a copy of r enriched with the user's identity.
// If group_base_dn is configured, LDAP groups are resolved and injected.
// Public to allow building composite authenticators.
func (la *LDAPAuth) BuildRequest(r *http.Request, username, userDN string) *http.Request {
	if la.groupBaseDN != "" {
		groups := la.resolveGroups(username, userDN)
		return userctx.WithIdentity(r, username, groups)
	}
	return userctx.WithUsername(r, username)
}

// Authenticate opens an LDAP connection, searches for the user's DN,
// then verifies the password. Returns the DN on success.
// Public to allow building composite authenticators (DB fallback).
func (la *LDAPAuth) Authenticate(username, password string) (string, error) {
	conn, err := la.dial()
	if err != nil {
		return "", fmt.Errorf("LDAP connection: %w", err)
	}
	defer conn.Close()

	// Bind with service account for the search.
	if la.bindDN != "" {
		if err := conn.Bind(la.bindDN, la.bindPassword); err != nil {
			return "", fmt.Errorf("service account bind: %w", err)
		}
	}

	// Search for the user's DN.
	filter := fmt.Sprintf(la.userFilter, goldap.EscapeFilter(username))
	req := goldap.NewSearchRequest(
		la.baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		1,
		int(la.timeout.Seconds()),
		false,
		filter,
		[]string{"dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("user %q not found in directory", username)
	}

	userDN := res.Entries[0].DN

	// Bind as the user to verify the password.
	if err := conn.Bind(userDN, password); err != nil {
		return "", fmt.Errorf("invalid password")
	}
	return userDN, nil
}

// resolveGroups opens a dedicated connection to search for the user's groups,
// then maps them to local group names via groupMapping.
// %s in groupFilter is replaced by the user's DN.
// %u in groupFilter is replaced by the username (uid).
// Always returns a non-nil slice (possibly empty) to signal that resolution occurred.
func (la *LDAPAuth) resolveGroups(username, userDN string) []string {
	conn, err := la.dial()
	if err != nil {
		log.Printf("[ldap] connection for groups failed: %v", err)
		return []string{}
	}
	defer conn.Close()

	if la.bindDN != "" {
		if err := conn.Bind(la.bindDN, la.bindPassword); err != nil {
			log.Printf("[ldap] service bind for groups failed: %v", err)
			return []string{}
		}
	}

	filter := strings.ReplaceAll(la.groupFilter, "%s", goldap.EscapeFilter(userDN))
	filter = strings.ReplaceAll(filter, "%u", goldap.EscapeFilter(username))

	req := goldap.NewSearchRequest(
		la.groupBaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,
		int(la.timeout.Seconds()),
		false,
		filter,
		[]string{la.groupAttribute},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		log.Printf("[ldap] group search failed for %q: %v", username, err)
		return []string{}
	}

	groups := []string{}
	for _, entry := range res.Entries {
		ldapGroupName := entry.GetAttributeValue(la.groupAttribute)
		if len(la.groupMapping) == 0 {
			// No mapping configured: LDAP name = local name directly.
			groups = append(groups, ldapGroupName)
		} else if localGroup, ok := la.groupMapping[ldapGroupName]; ok {
			groups = append(groups, localGroup)
		} else {
			log.Printf("[ldap] LDAP group %q ignored (not in group_mapping)", ldapGroupName)
		}
	}

	log.Printf("[ldap] resolved groups for %q: %v", username, groups)
	return groups
}

// dial opens a connection to the LDAP server respecting the scheme (ldap/ldaps).
func (la *LDAPAuth) dial() (*goldap.Conn, error) {
	goldap.DefaultTimeout = la.timeout

	tlsCfg := &tls.Config{InsecureSkipVerify: la.tlsSkipVerify} //nolint:gosec

	conn, err := goldap.DialURL(la.url, goldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
