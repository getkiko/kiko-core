package route

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type policyOutboundManager struct {
	adapter.OutboundManager
	items map[string]adapter.Outbound
}

func (m *policyOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	item, ok := m.items[tag]
	return item, ok
}
func (m *policyOutboundManager) Default() adapter.Outbound { return m.items["direct"] }

type policyDNSManager struct{ adapter.DNSTransportManager }

func (policyDNSManager) FakeIP() adapter.FakeIPTransport { return nil }

type policyPreferredOutbound struct {
	*selectorFlowOutbound
}

func (*policyPreferredOutbound) PreferredDomain(_ *adapter.InboundContext, domain string) bool {
	return domain == "work.ts.net"
}
func (*policyPreferredOutbound) PreferredAddress(_ *adapter.InboundContext, address netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(address)
}

type policyRule struct {
	name     string
	outbound string
	match    func(*adapter.InboundContext) bool
	mitm     string
}

func (*policyRule) Start() error                                  { return nil }
func (*policyRule) Close() error                                  { return nil }
func (*policyRule) Type() string                                  { return "default" }
func (r *policyRule) String() string                              { return r.name }
func (r *policyRule) Match(metadata *adapter.InboundContext) bool { return r.match(metadata) }
func (r *policyRule) Action() adapter.RuleAction {
	return &R.RuleActionRoute{Outbound: r.outbound, RuleActionRouteOptions: R.RuleActionRouteOptions{MITM: r.mitm}}
}

func TestPolicyFollowsPreferredRoutesAndCurrentSelector(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()
	manager := &policyOutboundManager{items: make(map[string]adapter.Outbound)}
	service.MustRegister[adapter.OutboundManager](ctx, manager)
	scope := adapter.NewScope(ctx, logger)
	defer scope.Close()
	for _, tag := range []string{"direct", "node-a", "node-b"} {
		manager.items[tag] = &selectorFlowOutbound{Adapter: outbound.NewAdapter("direct", tag, []string{N.NetworkTCP}, nil)}
	}
	manager.items["tailscale"] = &policyPreferredOutbound{selectorFlowOutbound: &selectorFlowOutbound{Adapter: outbound.NewAdapter("tailscale", "tailscale", []string{N.NetworkTCP}, nil)}}
	selected, err := group.NewSelector(ctx, nil, logger, "selected", option.SelectorOutboundOptions{Outbounds: []string{"node-a", "node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	selector := selected.(*group.Selector)
	manager.items["selected"] = selector
	if err := selector.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	preferred := R.NewPreferredByItem(ctx, []string{"tailscale"})
	if err := preferred.Start(); err != nil {
		t.Fatal(err)
	}
	router := &Router{ctx: ctx, logger: logger, outbound: manager, dnsTransport: policyDNSManager{}}
	router.rules.Store(&[]adapter.Rule{
		&policyRule{name: "Tailscale", outbound: "tailscale", match: preferred.Match},
		&policyRule{name: "local", outbound: "selected", match: func(metadata *adapter.InboundContext) bool {
			return metadata.Source.Addr == netip.MustParseAddr("192.168.1.10")
		}},
		&policyRule{name: "fallback", outbound: "direct", match: func(*adapter.InboundContext) bool { return true }},
	})
	metadata := adapter.InboundContext{Inbound: "tun-in", InboundType: "tun", Network: N.NetworkTCP, Protocol: "tls",
		Source: M.ParseSocksaddr("192.168.1.10:53421"), Destination: M.ParseSocksaddr("203.0.113.8:443"), Domain: "www.baidu.com"}
	result, err := router.TestPolicy(ctx, metadata)
	if err != nil || result.RuleIndex != 1 || !slices.Equal(result.OutboundPath, []string{"selected", "node-a"}) {
		t.Fatalf("public domain result=%+v err=%v", result, err)
	}
	if !selector.SelectOutbound("node-b") {
		t.Fatal("selector change failed")
	}
	result, err = router.TestPolicy(ctx, metadata)
	if err != nil || !slices.Equal(result.OutboundPath, []string{"selected", "node-b"}) {
		t.Fatalf("selector result=%+v err=%v", result, err)
	}
	metadata.Domain = "work.ts.net"
	result, err = router.TestPolicy(ctx, metadata)
	if err != nil || result.RuleIndex != 0 || !slices.Equal(result.OutboundPath, []string{"tailscale"}) {
		t.Fatalf("tailnet result=%+v err=%v", result, err)
	}
	metadata.Domain = "www.baidu.com"
	metadata.Source = M.ParseSocksaddr("192.168.1.20:53421")
	result, err = router.TestPolicy(ctx, metadata)
	if err != nil || result.RuleIndex != 2 || !slices.Equal(result.OutboundPath, []string{"direct"}) {
		t.Fatalf("other source result=%+v err=%v", result, err)
	}
}
