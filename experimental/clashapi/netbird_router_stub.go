//go:build !with_netbird

package clashapi

import "net/http"

// netbirdRouter returns nil when netbird is not compiled in — the caller
// skips mounting /netbird entirely.
func netbirdRouter() http.Handler { return nil }
