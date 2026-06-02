package cmd

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"multirepo-proxy/config"
)

// applyProxyTransport configures http.DefaultTransport and http.DefaultClient
// with the outbound proxy described in cfg.
// Called once at startup, before drivers are created.
// All drivers use http.DefaultClient (or http.DefaultTransport),
// so this single configuration point is sufficient.
func applyProxyTransport(cfg config.ProxyConfig) {
	if cfg.HTTP == "" && cfg.HTTPS == "" {
		return // no proxy configured, keep the default transport
	}

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = proxyFunc(cfg)
	http.DefaultTransport = base
	http.DefaultClient = &http.Client{Transport: base}
}

// proxyFunc returns the proxy selection function compatible with net/http.
// It respects the no_proxy list, selects the URL based on the request scheme,
// and injects credentials into the URL if provided.
func proxyFunc(cfg config.ProxyConfig) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if matchesNoProxy(req.URL.Host, cfg.NoProxy) {
			return nil, nil
		}

		var raw string
		if req.URL.Scheme == "https" && cfg.HTTPS != "" {
			raw = cfg.HTTPS
		} else if cfg.HTTP != "" {
			raw = cfg.HTTP
		}
		if raw == "" {
			return nil, nil
		}

		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		if cfg.Username != "" {
			u.User = url.UserPassword(cfg.Username, cfg.Password)
		}
		return u, nil
	}
}

// matchesNoProxy returns true if host is excluded from the proxy.
// Accepted syntax (same format as the NO_PROXY environment variable):
//   - "*"           → exclude everything
//   - "localhost"   → exact host
//   - ".corp.local" → all subdomains of corp.local
//   - "corp.local"  → corp.local and its subdomains
//   - "10.0.0.1"    → exact IP
func matchesNoProxy(host, noProxy string) bool {
	if noProxy == "" {
		return false
	}

	// Strip optional port ("host:port" → "host")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	for _, entry := range strings.Split(noProxy, ",") {
		pattern := strings.ToLower(strings.TrimSpace(entry))
		if pattern == "" {
			continue
		}
		if pattern == "*" {
			return true
		}
		// Exact match
		if host == pattern {
			return true
		}
		// Suffix match:
		//   ".corp.local" → hosts ending with ".corp.local"
		//   "corp.local"  → same + corp.local itself
		suffix := pattern
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
