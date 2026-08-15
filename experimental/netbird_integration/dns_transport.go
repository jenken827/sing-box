//go:build with_netbird

package netbird_integration

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	nbembed "github.com/netbirdio/netbird/client/embed"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// netbirdDNSPort is the DNS server port inside the netbird tunnel.
const netbirdDNSPort = 53

// globalClient stores the netbird embed client reference for DNS resolution
// plus the tunnel DNS server address (computed from the account network CIDR).
// Set by SetClient()/SetDNSAddr() after embed Start(), read by Transport.Exchange().
var globalClient struct {
	mu      sync.Mutex
	client  *nbembed.Client
	dnsAddr string
}

func SetClient(c *nbembed.Client) {
	globalClient.mu.Lock()
	defer globalClient.mu.Unlock()
	globalClient.client = c
}

func GetClient() *nbembed.Client {
	globalClient.mu.Lock()
	defer globalClient.mu.Unlock()
	return globalClient.client
}

// ClearClient drops the global embed client reference. Called by
// Engine.Shutdown() so nb-out / the DNS transport never dial through a
// stopped engine after service teardown.
func ClearClient() {
	globalClient.mu.Lock()
	defer globalClient.mu.Unlock()
	globalClient.client = nil
}

// SetDNSAddr records the netbird tunnel DNS server address (host:port).
func SetDNSAddr(addr string) {
	globalClient.mu.Lock()
	defer globalClient.mu.Unlock()
	globalClient.dnsAddr = addr
}

// GetDNSAddr returns the netbird tunnel DNS server address (host:port).
func GetDNSAddr() string {
	globalClient.mu.Lock()
	defer globalClient.mu.Unlock()
	return globalClient.dnsAddr
}

// ComputeDNSAddr derives the netbird DNS server address from the account's
// overlay network CIDR. Netbird runs its DNS server on the last-but-one IP of
// the overlay network (GetLastIPFromNetwork(network, 1) in client/net/net.go),
// e.g. 100.121.0.0/16 → 100.121.255.254:53. Empty CIDR falls back to the
// netbird default 100.121.0.0/16. Returns "" when the CIDR cannot be parsed.
func ComputeDNSAddr(networkCIDR string) string {
	if networkCIDR == "" {
		networkCIDR = "100.121.0.0/16"
	}
	prefix, err := netip.ParsePrefix(networkCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() >= 32 {
		return ""
	}
	// broadcast = network | ^mask; DNS = broadcast - 1 (same as GetLastIPFromNetwork(_, 1))
	netU32 := binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())
	hostBits := 32 - prefix.Bits()
	broadcast := netU32 + (uint32(1)<<hostBits - 1)
	dnsU32 := broadcast - 1
	var dnsIP [4]byte
	binary.BigEndian.PutUint32(dnsIP[:], dnsU32)
	return net.JoinHostPort(netip.AddrFrom4(dnsIP).String(), fmt.Sprint(netbirdDNSPort))
}

// DNSTransportType is the sing-box DNS transport type used in config.
const DNSTransportType = "netbird"

// RegisterTransport registers the netbird DNS transport with sing-box's DNS
// transport registry. Called from an init() in include/ under with_netbird tag.
func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.LocalDNSServerOptions](registry, DNSTransportType, NewTransport)
}

var _ adapter.DNSTransport = (*Transport)(nil)

// Transport resolves DNS queries through netbird's engine DNS handler chain.
// Custom domains (from management server) return internal IPs.
// For non-custom domains, falls back to a public DNS server.
type Transport struct {
	tag     string
	started bool
	closeCh chan struct{}
	client  *mdns.Client
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.LocalDNSServerOptions) (adapter.DNSTransport, error) {
	return &Transport{
		tag:     tag,
		closeCh: make(chan struct{}),
		client:  &mdns.Client{Net: "udp", Timeout: 5 * time.Second, SingleInflight: true},
	}, nil
}

func (t *Transport) Type() string           { return DNSTransportType }
func (t *Transport) Tag() string            { return t.tag }
func (t *Transport) Dependencies() []string { return nil }

func (t *Transport) Start(stage adapter.StartStage) error {
	t.started = true
	return nil
}

func (t *Transport) Close() error {
	close(t.closeCh)
	t.started = false
	return nil
}

func (t *Transport) Reset() {}

// Exchange resolves a DNS query through netbird's handler chain first.
// If netbird cannot resolve (Refused), falls back to public DNS.
func (t *Transport) Exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	client := GetClient()
	if client != nil {
		// Try resolving through netbird's tunnel DNS
		resp, err := t.resolveViaNetbird(ctx, client, message)
		if err == nil && resp != nil && resp.Rcode != mdns.RcodeRefused {
			return resp, nil
		}
	}
	// Fallback: public DNS via UDP
	return t.fallbackExchange(ctx, message)
}

// ExchangeAsync wraps Exchange in a goroutine.
func (t *Transport) ExchangeAsync(ctx context.Context, message *mdns.Msg, callback func(response *mdns.Msg, err error)) {
	go func() {
		resp, err := t.Exchange(ctx, message)
		callback(resp, err)
	}()
}

// resolveViaNetbird sends the DNS query through the netbird tunnel to the
// tunnel's DNS server using the netbird client's DialContext (wgnetstack).
// This is the only path that reaches netbird's in-process DNS handler —
// a bare net.Dialer would use the host network stack and never enter the tunnel.
func (t *Transport) resolveViaNetbird(ctx context.Context, client *nbembed.Client, message *mdns.Msg) (*mdns.Msg, error) {
	dnsAddr := GetDNSAddr()
	if dnsAddr == "" {
		return nil, fmt.Errorf("netbird DNS address not set")
	}
	// Kernel-TUN mode: client.DialContext is unavailable (no wgnetstack).
	// Dial the tunnel DNS via the host stack — the kernel route delivers
	// the packet to wt0.
	var conn net.Conn
	var err error
	if IsKernelMode() {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err = dialer.DialContext(ctx, "udp", dnsAddr)
	} else {
		conn, err = client.DialContext(ctx, "udp", dnsAddr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	co := &mdns.Conn{Conn: conn}
	defer co.Close()
	if err := co.WriteMsg(message); err != nil {
		return nil, err
	}
	return co.ReadMsg()
}

// fallbackServer is the default public DNS server used when netbird can't resolve.
const fallbackServer = "223.5.5.5:53"

func (t *Transport) fallbackExchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", fallbackServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	co := &mdns.Conn{Conn: conn}
	defer co.Close()
	if err := co.WriteMsg(message); err != nil {
		return nil, err
	}
	return co.ReadMsg()
}
