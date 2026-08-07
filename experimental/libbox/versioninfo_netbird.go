// experimental/libbox/versioninfo_netbird.go
//go:build with_netbird

package libbox

import netbirdversion "github.com/netbirdio/netbird/version"

// netbirdBuildCommit is the netbird repo HEAD at build time, injected via
// ldflags -X. NetbirdCommit() reads the main module's BuildInfo (which is
// sing-box), so the real netbird revision must be injected explicitly.
var netbirdBuildCommit = ""

// NetbirdVersion returns the netbird engine version (upstream tag, e.g. "v0.76.0").
func NetbirdVersion() string {
	return netbirdversion.NetbirdVersion()
}

// NetbirdCommit returns the netbird repo HEAD (12 chars) injected at build
// time, or "" when not injected.
func NetbirdCommit() string {
	rev := netbirdBuildCommit
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev
}
