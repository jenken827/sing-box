//go:build !with_netbird

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/experimental/netbird_integration"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerNetbirdOutbound(registry *outbound.Registry) {
	outbound.Register[netbird_integration.NetbirdOutboundOptions](registry, "netbird", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options netbird_integration.NetbirdOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New("Netbird outbound is not included in this build, rebuild with -tags with_netbird")
	})
}
