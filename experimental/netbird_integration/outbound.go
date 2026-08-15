//go:build with_netbird

package netbird_integration

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const OutboundType = "netbird"

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[NetbirdOutboundOptions](registry, OutboundType, NewOutbound)
}

var _ N.Dialer = (*Outbound)(nil)

// Outbound routes traffic through netbird's netstack WireGuard tunnel.
// Used by route rules matching 100.121.0.0/16.
type Outbound struct {
	outbound.Adapter
	ctx    context.Context
	cancel context.CancelFunc
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options NetbirdOutboundOptions) (adapter.Outbound, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &Outbound{
		Adapter: outbound.NewAdapter(OutboundType, tag, []string{"tcp", "udp"}, nil),
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	// Use Fqdn if available (proxy CONNECT requests route by domain, not IP)
	var addr string
	if destination.Fqdn != "" {
		addr = net.JoinHostPort(destination.Fqdn, strconv.Itoa(int(destination.Port)))
	} else {
		addr = net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port)))
	}
	// Kernel-TUN mode: no wgnetstack (client.DialContext is unavailable).
	// Dial via the host stack — the kernel routes the overlay destination
	// straight to wt0. This outbound is normally unused in kernel mode
	// (no route rules are injected), it is a defensive fallback.
	if IsKernelMode() {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, addr)
	}
	client := GetClient()
	if client == nil {
		return nil, context.Canceled
	}
	return client.DialContext(ctx, network, addr)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	// Kernel-TUN mode has no wgnetstack; UDP to the overlay is handled by
	// the kernel route (wt0). This outbound is not selected in kernel mode
	// since no route rules are injected.
	if IsKernelMode() {
		return nil, fmt.Errorf("netbird outbound: ListenPacket unavailable in kernel-tun mode")
	}
	client := GetClient()
	if client == nil {
		return nil, context.Canceled
	}
	addr := net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port)))
	return client.ListenUDP(addr)
}
