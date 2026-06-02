package api

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed ui.html
var adminUIBytes []byte

//go:embed favicon.ico
var faviconBytes []byte

// AdminUIHandler sert l'interface web d'administration.
// Any request under /admin/ that is not /admin/api/ receives the HTML.
type AdminUIHandler struct {
	API http.Handler // handler pour /admin/api/*
}

// ServeFavicon writes the embedded favicon.ico.
func ServeFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(faviconBytes)
}

func (h *AdminUIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/admin/api/") {
		if h.API != nil {
			h.API.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(adminUIBytes)
}
