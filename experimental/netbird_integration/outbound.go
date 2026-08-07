//go:build with_netbird

package netbird_integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const OutboundType = "netbird"

func RegisterOutbound(registry *outbound.Registry) {
	fmt.Fprintf(os.Stderr, "[nb-out] RegisterOutbound called\n")
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
	fmt.Fprintf(os.Stderr, "[nb-out] NewOutbound tag=%s\n", tag)
	return &Outbound{
		Adapter: outbound.NewAdapter(OutboundType, tag, []string{"tcp", "udp"}, nil),
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client := GetClient()
	if client == nil {
		return nil, context.Canceled
	}
	// Use Fqdn if available (proxy CONNECT requests route by domain, not IP)
	var addr string
	if destination.Fqdn != "" {
		addr = net.JoinHostPort(destination.Fqdn, strconv.Itoa(int(destination.Port)))
	} else {
		addr = net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port)))
	}
	fmt.Fprintf(os.Stderr, "[nb-out] DialContext network=%s addr=%s\n", network, addr)
	conn, err := client.DialContext(ctx, network, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[nb-out] FAILED: %v\n", err)
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[nb-out] SUCCESS addr=%s\n", addr)
	return conn, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	client := GetClient()
	if client == nil {
		return nil, context.Canceled
	}
	addr := net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port)))
	return client.ListenUDP(addr)
}
