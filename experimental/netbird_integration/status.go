//go:build with_netbird

package netbird_integration

import (
	nbembed "github.com/netbirdio/netbird/client/embed"
)

// PeerStatus is a wire-ready view of one netbird peer's connection state,
// served by the Clash API /netbird/peers endpoint.
type PeerStatus = nbembed.PeerStatusInfo

// PeerStatuses returns the current connection state of every netbird peer.
// Returns nil when the embed client is not available (engine not started).
func PeerStatuses() []PeerStatus {
	client := GetClient()
	if client == nil {
		return nil
	}
	return client.PeerStatuses()
}
