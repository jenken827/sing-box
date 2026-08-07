// experimental/monitor/context.go
package monitor

import "context"

type dialMetaKey struct{}
type skipMonitorKey struct{}

// DialMeta carries connection metadata from the router down to the dialer hooks.
type DialMeta struct {
	ConnID       string // unique per-connection ID (e.g. "google.com-1234567890")
	TargetDomain string // original target domain (e.g. "google.com")
	OutboundTag  string // outbound tag (e.g. "direct", "my-vless")
	ProcessPath  string // process path (e.g. "C:\Program Files\chrome.exe"), from find_process
}

// ContextWithDialMeta attaches dial metadata to the context.
// Should be called in the router right before the outbound dials.
func ContextWithDialMeta(ctx context.Context, meta *DialMeta) context.Context {
	return context.WithValue(ctx, dialMetaKey{}, meta)
}

// DialMetaFromContext retrieves DialMeta from context.
// Returns nil if not set (e.g. DNS-initiated or legacy paths).
func DialMetaFromContext(ctx context.Context) *DialMeta {
	v, _ := ctx.Value(dialMetaKey{}).(*DialMeta)
	return v
}

// ContextWithSkipMonitor marks the context so TCP/TLS hooks skip recording.
// Used by the DNS module to prevent DoH transport connections from being tracked.
func ContextWithSkipMonitor(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipMonitorKey{}, true)
}

// ShouldSkipMonitor returns true if the context is marked to skip monitor recording.
func ShouldSkipMonitor(ctx context.Context) bool {
	v, _ := ctx.Value(skipMonitorKey{}).(bool)
	return v
}
