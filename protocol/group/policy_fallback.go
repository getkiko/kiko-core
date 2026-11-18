package group

import (
	"context"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	return newGroup(ctx, logger, C.TypeFallback, tag, options.Outbounds, options.GroupHealthCheckOptions, options.InterruptExistConnections, &fallbackStrategy{noReturn: options.NoReturn})
}

// fallbackStrategy uses the first member that is not down, in the
// members' order.
type fallbackStrategy struct {
	noReturn bool
}

func (s *fallbackStrategy) mode() string     { return C.GroupModeFallback }
func (s *fallbackStrategy) name() string     { return "" }
func (s *fallbackStrategy) hasCurrent() bool { return true }
func (s *fallbackStrategy) learns() bool     { return false }

func (s *fallbackStrategy) inherit(old groupStrategy) {}

func (s *fallbackStrategy) pick(g *Group, network string, metadata *adapter.InboundContext, dryRun bool) adapter.Outbound {
	return g.Selected(network)
}

func (s *fallbackStrategy) choose(g *Group, network string, current adapter.Outbound, now time.Time) adapter.Outbound {
	if s.noReturn && g.isMember(current) && supports(current, network) && g.state(current, network) != adapter.GroupMemberDown {
		return current
	}
	for _, member := range g.members {
		if supports(member, network) && g.state(member, network) != adapter.GroupMemberDown {
			return member
		}
	}
	return g.firstSupporting(network)
}

// probeSet are the current member and those before it, which the group
// returns to when they recover, and the members down, which it falls
// back on once they recover; all members before a selection.
func (s *fallbackStrategy) probeSet(g *Group) []adapter.Outbound {
	current := g.current[0].Load()
	index := slices.Index(g.members, current)
	if index < 0 {
		return g.members
	}
	var members []adapter.Outbound
	if s.noReturn {
		members = []adapter.Outbound{current}
	} else {
		members = slices.Clone(g.members[:index+1])
	}
	// A member stays down until a probe finds it up; once its recovery
	// probes end, only this check keeps its state from going stale.
	for _, member := range g.members {
		if !slices.Contains(members, member) && g.state(member, N.NetworkTCP) == adapter.GroupMemberDown {
			members = append(members, member)
		}
	}
	return members
}
