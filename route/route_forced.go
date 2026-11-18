package route

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// routeForcedConnection routes a connection whose outbound is named by
// metadata.ForcedOutbound: rules are not matched and the connection is not
// offered to the MITM engine. Trackers see it like any routed connection.
func (r *Router) routeForcedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	selectedOutbound, loaded := r.outbound.Outbound(metadata.ForcedOutbound)
	if !loaded {
		return E.New("outbound not found: ", metadata.ForcedOutbound)
	}
	chain, err := resolveOutbound(selectedOutbound, N.NetworkTCP, &metadata)
	if err != nil {
		return err
	}
	metadata.RouteOutbound = selectedOutbound.Tag()
	metadata.OutboundChain = chain
	for _, tracker := range r.trackers {
		conn = tracker.RoutedConnection(ctx, conn, metadata, nil, selectedOutbound)
	}
	ctx = interrupt.ContextWithIsExternalConnection(ctx, true)
	onClose = registerInterrupt(chain, conn, pinOnClose(r.outbound, chain, onClose))
	outbound := chain[len(chain)-1]
	if outboundHandler, isHandler := outbound.(adapter.ConnectionHandler); isHandler {
		outboundHandler.NewConnection(ctx, conn, metadata, onClose)
	} else {
		r.connection.NewConnection(ctx, outbound, conn, metadata, onClose)
	}
	return nil
}
