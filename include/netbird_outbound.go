//go:build with_netbird

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/experimental/netbird_integration"
)

func registerNetbirdOutbound(registry *outbound.Registry) {
	outbound.Register[netbird_integration.NetbirdOutboundOptions](registry, "netbird", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options netbird_integration.NetbirdOutboundOptions) (adapter.Outbound, error) {
		return netbird_integration.NewOutbound(ctx, router, logger, tag, options)
	})
}
