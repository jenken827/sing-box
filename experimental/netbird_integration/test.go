//go:build with_netbird

package netbird_integration

import (
	"context"
	"time"
)

// TestResult is the outcome of an overlay reachability probe, served by
// the Clash API /netbird/test endpoint.
type TestResult struct {
	Reachable bool   `json:"reachable"`
	RTTMs     int64  `json:"rtt_ms"`
	Error     string `json:"error,omitempty"`
}

// TestOverlay dials hostport through the netbird engine (client.DialContext
// → wgnetstack → overlay tunnel). This is the only path that reaches overlay
// peers on Android, where the app's own sockets bypass the VpnService TUN
// (addDisallowedApplication) and the overlay CIDR has no kernel route.
func TestOverlay(hostport string, timeout time.Duration) TestResult {
	client := GetClient()
	if client == nil {
		return TestResult{Error: "netbird engine not running"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t0 := time.Now()
	conn, err := client.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return TestResult{Error: err.Error()}
	}
	_ = conn.Close()
	return TestResult{Reachable: true, RTTMs: time.Since(t0).Milliseconds()}
}
