package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// blockQUIC reports whether the MITM engine blocks the connection as QUIC to
// a decrypted host, so that the client falls back to TCP. A miss costs one nil
// check and the engine's own non-allocating match.
func (r *Router) blockQUIC(ctx context.Context, metadata *adapter.InboundContext) bool {
	if r.mitm == nil || metadata.Network != N.NetworkUDP {
		return false
	}
	if !r.mitm.MatchQUIC(metadata) {
		return false
	}
	r.logger.DebugContext(ctx, "mitm: blocked quic to ", metadata.Destination, " domain: ", metadata.Domain)
	return true
}
