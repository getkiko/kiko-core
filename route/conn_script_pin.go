package route

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// pinScriptDestination resolves the host name of a script $httpClient connection that a
// direct outbound will dial, checks every resolved address against the target restrictions
// and pins the connection to the addresses that pass: the dialer connects to those and never
// resolves the name again, so a DNS answer that changes between the check and the dial
// (rebinding) is not used, and a refusal does not depend on whether the port answers. Other
// outbounds resolve on the far side and keep only the name rules. Without a DNS router
// (tests) the check after the dial, scriptAddressRefused, remains the only one.
func (m *ConnectionManager) pinScriptDestination(ctx context.Context, this N.Dialer, metadata *adapter.InboundContext) error {
	if outbound, isOutbound := this.(adapter.Outbound); !isOutbound || outbound.Type() != C.TypeDirect {
		return nil
	}
	guard, ok := m.mitm.(scriptTargetGuard)
	if !ok {
		return E.New("refused: no target guard")
	}
	addresses := metadata.DestinationAddresses
	if len(addresses) == 0 {
		if metadata.Destination.IsIP() {
			addresses = []netip.Addr{metadata.Destination.Addr}
		} else if metadata.Destination.IsFqdn() && m.ctx != nil {
			router := service.FromContext[adapter.DNSRouter](m.ctx)
			if router == nil {
				return nil
			}
			resolved, err := router.Lookup(ctx, metadata.Destination.Fqdn, adapter.DNSQueryOptions{})
			if err != nil {
				return E.Cause(err, "resolve ", metadata.Destination.Fqdn)
			}
			addresses = resolved
		}
	}
	if len(addresses) == 0 {
		return nil
	}
	allowed := make([]netip.Addr, 0, len(addresses))
	var reason string
	for _, addr := range addresses {
		if why := guard.ScriptAddressRefused(addr); why != "" {
			if reason == "" {
				reason = why
			}
			continue
		}
		allowed = append(allowed, addr.Unmap())
	}
	if len(allowed) == 0 {
		return E.New("refused: ", reason)
	}
	if !metadata.Destination.IsIP() || len(metadata.DestinationAddresses) > 0 {
		metadata.DestinationAddresses = allowed
	}
	return nil
}
