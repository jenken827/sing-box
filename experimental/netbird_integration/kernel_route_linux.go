//go:build with_netbird && linux

package netbird_integration

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Kernel-TUN route constants. The rule priority must be numerically LOWER
// than sing-tun's rule index (default 9000) so overlay traffic is matched
// here first and never reaches the sing-box TUN stack. 2022 is sing-tun's
// route table, so a dedicated table avoids any collision.
const (
	kernelRoutePriority = 2000
	kernelRouteTable    = 10021
	kernelIfaceName     = "wt0"
)

var defaultNetworkCIDR = "100.121.0.0/16"

// SetupKernelRoute installs the single static route that sends the netbird
// overlay CIDR straight to the netbird kernel TUN (wt0), bypassing the
// sing-box TUN stack (Route A). It must be called after the netbird engine
// has created wt0; the sing-box TUN may be up or down since our rule
// (priority 2000) always precedes sing-tun's (9000).
//
// Returns a cleanup function that removes the route and rule.
// networkCIDR may be "" — falls back to the netbird default 100.121.0.0/16.
func SetupKernelRoute(networkCIDR string) (func(), error) {
	prefix, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		prefix, err = netip.ParsePrefix(defaultNetworkCIDR)
		if err != nil {
			return nil, fmt.Errorf("netbird kernel route: invalid CIDR %q: %w", networkCIDR, err)
		}
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("netbird kernel route: IPv4 required, got %s", prefix)
	}
	dst := &net.IPNet{
		IP:   prefix.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), 32),
	}

	link, err := netlink.LinkByName(kernelIfaceName)
	if err != nil {
		return nil, fmt.Errorf("netbird kernel route: find %s: %w", kernelIfaceName, err)
	}

	// Kernel-mode DNS: netbird's in-process DNS server binds the WG
	// interface's own overlay IP on port 53 (service_listener.go:
	// testFreePort tries wgInterface.Address().IP first). Record it so the
	// DNS transport dials the local resolver instead of the netstack-mode
	// fake address (second-last network IP, e.g. 100.121.255.254) which
	// would be encapsulated into the tunnel and never reach the resolver.
	if addrs, err := netlink.AddrList(link, unix.AF_INET); err == nil {
		for _, a := range addrs {
			if a.IPNet != nil && a.IPNet.IP != nil && !a.IPNet.IP.IsUnspecified() {
				SetDNSAddr(net.JoinHostPort(a.IPNet.IP.String(), "53"))
				break
			}
		}
	}

	// Route: overlay CIDR -> wt0 in the dedicated table.
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Table:     kernelRouteTable,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return nil, fmt.Errorf("netbird kernel route: add route: %w", err)
	}

	// Rule: packets to the overlay CIDR consult the dedicated table first.
	rule := netlink.NewRule()
	rule.Priority = kernelRoutePriority
	rule.Table = kernelRouteTable
	rule.Dst = prefix
	rule.Family = unix.AF_INET
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		_ = netlink.RouteDel(route) // roll back the route we just added
		return nil, fmt.Errorf("netbird kernel route: add rule: %w", err)
	}

	cleanup := func() {
		_ = netlink.RuleDel(rule)
		_ = netlink.RouteDel(route)
	}
	return cleanup, nil
}
