// No build tags — accessible in all builds
package netbird_integration

// NetbirdOutboundOptions is the configuration type for the netbird outbound.
// It has no fields since the outbound routes through the netbird netstack tunnel
// without additional configuration.
type NetbirdOutboundOptions struct{}
