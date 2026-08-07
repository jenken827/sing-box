//go:build with_netbird

package netbird_integration

import (
	"context"
	"net/netip"
	"time"

	nbembed "github.com/netbirdio/netbird/client/embed"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// WaitSyncResponse polls GetLatestSyncResponse until a non-nil response
// is available, or until the context is cancelled.
func WaitSyncResponse(ctx context.Context, client *nbembed.Client) (*mgmProto.SyncResponse, error) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
			resp, err := client.GetLatestSyncResponse()
			if err != nil {
				// sync persistence might not be enabled yet
				continue
			}
			if resp != nil {
				return resp, nil
			}
		}
	}
}

// ExtractDomainsFromSync extracts custom domain names from the netbird
// SyncResponse DNS configuration. Returns domains from both NameServerGroups
// and CustomZones.
func ExtractDomainsFromSync(resp *mgmProto.SyncResponse) []string {
	if resp == nil {
		return nil
	}
	dnsCfg := resp.GetNetworkMap().GetDNSConfig()
	if dnsCfg == nil {
		return nil
	}

	seen := make(map[string]bool)
	var domains []string

	// Collect from NameServerGroups
	for _, nsg := range dnsCfg.GetNameServerGroups() {
		if nsg == nil {
			continue
		}
		for _, d := range nsg.GetDomains() {
			if d != "" && !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}

	// Collect from CustomZones
	for _, cz := range dnsCfg.GetCustomZones() {
		if cz == nil {
			continue
		}
		d := cz.GetDomain()
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}

	return domains
}

// ExtractNetworkCIDR extracts the account's IPv4 overlay subnet (e.g.
// "100.121.0.0/16") from the netbird SyncResponse.
//
// Priority:
//  1. NetworkMapEnvelope.full.network.net_cidr — exact prefix from the
//     component-based wire format.
//  2. NetworkMap.peerConfig.address masked to the netbird subnet size (/16).
//     The legacy wire format doesn't ship the prefix, but every account
//     network is a /16 inside 100.64.0.0/10, so the containing /16 of the
//     peer's own address is the network prefix.
//
// Returns "" when neither source is available (caller falls back to the
// netbird default 100.121.0.0/16).
func ExtractNetworkCIDR(resp *mgmProto.SyncResponse) string {
	if resp == nil {
		return ""
	}
	if env := resp.GetNetworkMapEnvelope(); env != nil {
		if full := env.GetFull(); full != nil {
			if net := full.GetNetwork(); net != nil {
				if cidr := net.GetNetCidr(); cidr != "" {
					return cidr
				}
			}
		}
	}
	if peer := resp.GetNetworkMap().GetPeerConfig(); peer != nil {
		if addr := peer.GetAddress(); addr != "" {
			if ip, err := netip.ParseAddr(addr); err == nil && ip.Is4() {
				return netip.PrefixFrom(ip, 16).Masked().String()
			}
		}
	}
	return ""
}
