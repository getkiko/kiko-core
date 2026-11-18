package group

import (
	"context"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func RegisterSmart(registry *outbound.Registry) {
	outbound.Register[option.SmartOutboundOptions](registry, C.TypeSmart, NewSmart)
}

func NewSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartOutboundOptions) (adapter.Outbound, error) {
	return newGroup(ctx, logger, C.TypeSmart, tag, options.Outbounds, options.GroupHealthCheckOptions, options.InterruptExistConnections, &smartStrategy{})
}

// smartStrategy uses the member with the lowest cost: the time to first
// byte of routed connections (the probe delay while there are few), made
// dearer by failures and slow bulk transfers. It switches only to a
// member clearly better, and not again soon after a switch.
type smartStrategy struct{}

const (
	// smartSwitchRatio is how much cheaper a member must be to switch to.
	smartSwitchRatio = 0.8
	// smartDwell is how long a switch holds unless the member goes down.
	smartDwell = time.Minute
	// smartPassiveWeight is the weight of connections at which the probe
	// delay no longer counts.
	smartPassiveWeight = 3
	// smartUnknownFactor makes a member known only by probes dearer.
	smartUnknownFactor = 1.5
)

func (s *smartStrategy) mode() string     { return C.GroupModeSmart }
func (s *smartStrategy) name() string     { return "" }
func (s *smartStrategy) hasCurrent() bool { return true }
func (s *smartStrategy) learns() bool     { return true }

func (s *smartStrategy) inherit(old groupStrategy) {}

func (s *smartStrategy) pick(g *Group, network string, metadata *adapter.InboundContext, dryRun bool) adapter.Outbound {
	return g.Selected(network)
}

func (s *smartStrategy) probeSet(g *Group) []adapter.Outbound {
	return g.members
}

// baseCost is the cost of member before its throughput is weighed, and
// whether it has one.
func (s *smartStrategy) baseCost(g *Group, member adapter.Outbound, network string) (float64, float64, bool) {
	realTag := RealTag(member, network)
	if realTag == "" {
		return 0, 0, false
	}
	stats := g.health.Stats(realTag)
	var probe float64
	if history := g.history.LoadURLTestHistory(realTag); history != nil {
		probe = float64(history.Delay)
	}
	var latency float64
	switch {
	case stats.LatencyWeight >= smartPassiveWeight:
		latency = stats.Latency
	case stats.LatencyWeight > 0 && probe > 0:
		w := stats.LatencyWeight / smartPassiveWeight
		latency = stats.Latency*w + probe*(1-w)
	case stats.LatencyWeight > 0:
		latency = stats.Latency
	case probe > 0:
		latency = probe
	default:
		return 0, 0, false
	}
	latency = math.Max(latency, 1)
	success := 1.0
	if stats.SuccessWeight > 0 && stats.Success >= 0 {
		success = stats.Success
	}
	cost := latency * (1 + 4*(1-success)) * (1 + stats.Penalty)
	if stats.SuccessWeight == 0 && stats.LatencyWeight == 0 {
		cost *= smartUnknownFactor
	}
	return cost, stats.Rate, true
}

// cost is the cost of member among the group's members.
func (s *smartStrategy) cost(g *Group, member adapter.Outbound, network string) (float64, bool) {
	costs := s.costs(g, network, []adapter.Outbound{member})
	cost, ok := costs[member]
	return cost, ok
}

// costs are the costs of members, the throughput weighed against the
// median rate of the group's members.
func (s *smartStrategy) costs(g *Group, network string, members []adapter.Outbound) map[adapter.Outbound]float64 {
	var rates []float64
	for _, member := range g.members {
		if realTag := RealTag(member, network); realTag != "" {
			if rate := g.health.Stats(realTag).Rate; rate > 0 {
				rates = append(rates, rate)
			}
		}
	}
	var median float64
	if len(rates) > 0 {
		sort.Float64s(rates)
		median = rates[len(rates)/2]
	}
	costs := make(map[adapter.Outbound]float64, len(members))
	for _, member := range members {
		cost, rate, ok := s.baseCost(g, member, network)
		if !ok {
			continue
		}
		if rate > 0 && median > 0 {
			cost *= math.Min(math.Max(math.Sqrt(median/rate), 0.7), 1.4)
		}
		costs[member] = cost
	}
	return costs
}

func (s *smartStrategy) choose(g *Group, network string, current adapter.Outbound, now time.Time) adapter.Outbound {
	candidates := g.available(network)
	if len(candidates) == 0 {
		return g.firstSupporting(network)
	}
	costs := s.costs(g, network, candidates)
	var best adapter.Outbound
	bestCost := math.Inf(1)
	for _, member := range candidates {
		if cost, ok := costs[member]; ok && cost < bestCost {
			best, bestCost = member, cost
		}
	}
	usable := g.isMember(current) && slices.Contains(candidates, current)
	if best == nil {
		if usable {
			return current
		}
		return candidates[0]
	}
	if !usable {
		return best
	}
	currentCost, known := costs[current]
	if !known {
		return best
	}
	if best != current && bestCost < currentCost*smartSwitchRatio && now.Sub(g.switchedAt[networkIndex(network)]) >= smartDwell {
		return best
	}
	return current
}
