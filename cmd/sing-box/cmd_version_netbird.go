// cmd/sing-box/cmd_version_netbird.go
//go:build with_netbird

package main

import netbirdversion "github.com/netbirdio/netbird/version"

// netbirdBuildCommit is the netbird repo HEAD at build time, injected via
// ldflags -X (NetbirdCommit() can't see it — it reads the main module's
// BuildInfo, which is sing-box). Empty when not injected.
var netbirdBuildCommit = ""

// netbirdVersionLine returns the netbird engine version line for
// `sing-box version` output, or "" when built without netbird.
func netbirdVersionLine() string {
	commit := netbirdBuildCommit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit != "" {
		return "Netbird: " + netbirdversion.NetbirdVersion() + " (" + commit + ")\n"
	}
	return "Netbird: " + netbirdversion.NetbirdVersion() + "\n"
}
