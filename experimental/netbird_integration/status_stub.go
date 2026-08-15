//go:build !with_netbird

package netbird_integration

// PeerStatus is the stub representation when netbird is not compiled in.
type PeerStatus struct {
	IP         string `json:"ip"`
	FQDN       string `json:"fqdn"`
	ConnStatus string `json:"conn_status"`
	Relayed    bool   `json:"relayed"`
}

// PeerStatuses is a no-op stub when netbird is not compiled in.
func PeerStatuses() []PeerStatus { return nil }
