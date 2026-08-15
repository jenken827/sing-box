//go:build !with_netbird

package netbird_integration

import "time"

// TestResult is the stub representation when netbird is not compiled in.
type TestResult struct {
	Reachable bool   `json:"reachable"`
	RTTMs     int64  `json:"rtt_ms"`
	Error     string `json:"error,omitempty"`
}

// TestOverlay is a no-op stub when netbird is not compiled in.
func TestOverlay(hostport string, timeout time.Duration) TestResult {
	return TestResult{Error: "netbird not compiled in"}
}
