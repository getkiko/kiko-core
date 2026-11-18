package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type PolicyTestResult struct {
	Action       string
	Rule         string
	RuleIndex    int
	OutboundPath []string
}

// TestPolicy walks active rules with synthetic connection metadata, without dialing the destination.
func (r *Router) TestPolicy(ctx context.Context, metadata adapter.InboundContext) (PolicyTestResult, error) {
	selected, index, _, _, err := r.matchRule(ctx, &metadata, nil, nil)
	if err != nil {
		return PolicyTestResult{}, err
	}
	result := PolicyTestResult{Action: C.RuleActionTypeRoute, RuleIndex: -1}
	var outboundTag string
	if selected != nil {
		result.Rule = selected.String()
		result.RuleIndex = index
		switch action := selected.Action().(type) {
		case *R.RuleActionRoute:
			outboundTag = action.Outbound
		case *R.RuleActionBypass:
			outboundTag = action.Outbound
		case *R.RuleActionReject, *R.RuleActionHijackDNS:
			result.Action = selected.Action().Type()
			return result, nil
		default:
			result.Action = selected.Action().Type()
			return result, nil
		}
	}
	result.OutboundPath, err = r.outboundPath(outboundTag, &metadata)
	return result, err
}

// OutboundPath resolves the active selection of each outbound group.
func (r *Router) OutboundPath(tag string) ([]string, error) {
	return r.outboundPath(tag, nil)
}

// outboundPath resolves the member each outbound group would give a
// connection described by metadata, without changing the groups.
func (r *Router) outboundPath(tag string, metadata *adapter.InboundContext) ([]string, error) {
	var outbound adapter.Outbound
	if tag == "" {
		outbound = r.outbound.Default()
	} else {
		var loaded bool
		outbound, loaded = r.outbound.Outbound(tag)
		if !loaded {
			return nil, E.New("outbound not found: ", tag)
		}
	}
	if outbound == nil {
		return nil, E.New("default outbound unavailable")
	}
	var path []string
	seen := make(map[string]bool)
	for outbound != nil {
		tag := outbound.Tag()
		if seen[tag] {
			return nil, E.New("outbound group cycle: ", tag)
		}
		seen[tag] = true
		path = append(path, tag)
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		outbound = selectMember(group, N.NetworkTCP, metadata, true)
		if outbound == nil {
			return nil, E.New("selected outbound unavailable: ", tag)
		}
	}
	return path, nil
}
