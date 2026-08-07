// experimental/libbox/versioninfo.go
//go:build !with_netbird

package libbox

// NetbirdVersion returns "N/A" when built without the netbird integration.
func NetbirdVersion() string {
	return "N/A"
}

// NetbirdCommit returns "" when built without the netbird integration.
func NetbirdCommit() string {
	return ""
}
