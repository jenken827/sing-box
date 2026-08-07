// cmd/sing-box/cmd_version_stub.go
//go:build !with_netbird

package main

// netbirdVersionLine returns "" when built without the netbird integration.
func netbirdVersionLine() string {
	return ""
}
