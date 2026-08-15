//go:build with_netbird

package clashapi

import (
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/sagernet/sing-box/experimental/netbird_integration"
)

// netbirdRouter exposes netbird engine state under /netbird/*.
// Returns nil when the netbird integration is not compiled in.
func netbirdRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/peers", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, netbird_integration.PeerStatuses())
	})
	r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		port := r.URL.Query().Get("port")
		if host == "" || port == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, netbird_integration.TestResult{Error: "host and port required"})
			return
		}
		render.JSON(w, r, netbird_integration.TestOverlay(
			net.JoinHostPort(host, port),
			5*time.Second,
		))
	})
	return r
}
