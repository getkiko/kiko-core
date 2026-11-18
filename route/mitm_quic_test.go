package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// fakeMITMEngine implements the matching surface of the engine.
type fakeMITMEngine struct {
	adapter.MITMEngine
	quic    func(*adapter.InboundContext) bool
	decide  func(*adapter.InboundContext) *adapter.MITMState
	explain func(*adapter.InboundContext) (string, string)
	decided int
}

func (e *fakeMITMEngine) Explain(metadata *adapter.InboundContext) (string, string) {
	if e.explain != nil {
		return e.explain(metadata)
	}
	state := e.decide
	if state == nil {
		return "", ""
	}
	switch result := state(metadata); result.Status() {
	case adapter.MITMStatusPending, adapter.MITMStatusDecrypted:
		return "decrypted", ""
	case adapter.MITMStatusSkipped:
		return "skipped", result.Reason()
	}
	return "", ""
}

func (e *fakeMITMEngine) MatchQUIC(metadata *adapter.InboundContext) bool {
	return e.quic != nil && e.quic(metadata)
}

func (e *fakeMITMEngine) Decide(metadata *adapter.InboundContext) *adapter.MITMState {
	e.decided++
	if e.decide == nil {
		return nil
	}
	return e.decide(metadata)
}

func quicMetadata(domain string) adapter.InboundContext {
	return adapter.InboundContext{Inbound: "tun-in", InboundType: "tun", Network: N.NetworkUDP, Protocol: C.ProtocolQUIC,
		Source: M.ParseSocksaddr("192.168.1.10:53421"), Destination: M.ParseSocksaddr("203.0.113.8:443"), Domain: domain}
}

func TestBlockQUIC(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	engine := &fakeMITMEngine{quic: func(m *adapter.InboundContext) bool { return m.Domain == "blocked.example" }}
	router := &Router{ctx: context.Background(), logger: logger, mitm: engine}
	blocked := quicMetadata("blocked.example")
	if !router.blockQUIC(context.Background(), &blocked) {
		t.Fatal("matching QUIC not blocked")
	}
	other := quicMetadata("other.example")
	if router.blockQUIC(context.Background(), &other) {
		t.Fatal("non-matching QUIC blocked")
	}
	tcp := quicMetadata("blocked.example")
	tcp.Network = N.NetworkTCP
	if router.blockQUIC(context.Background(), &tcp) {
		t.Fatal("TCP must not be blocked")
	}
	router.mitm = nil
	if router.blockQUIC(context.Background(), &blocked) {
		t.Fatal("blocked without an engine")
	}
}

func TestPreMatchBlocksQUICBeforeFlowForwarding(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()
	manager := &policyOutboundManager{items: map[string]adapter.Outbound{
		"direct": &selectorFlowOutbound{Adapter: outbound.NewAdapter("direct", "direct", []string{N.NetworkUDP}, nil)},
	}}
	engine := &fakeMITMEngine{quic: func(m *adapter.InboundContext) bool { return m.Domain == "blocked.example" }}
	router := &Router{ctx: ctx, logger: logger, outbound: manager, dnsTransport: policyDNSManager{}, mitm: engine}
	for _, rules := range [][]adapter.Rule{
		nil,
		{&policyRule{name: "route", outbound: "direct", match: func(*adapter.InboundContext) bool { return true }}},
	} {
		router.rules.Store(&rules)
		blocked := router.PreMatch(quicMetadata("blocked.example"), nil)
		if blocked.Action != adapter.PreMatchReject {
			t.Fatalf("rules=%d blocked host action=%v", len(rules), blocked.Action)
		}
		passed := router.PreMatch(quicMetadata("other.example"), nil)
		if passed.Action == adapter.PreMatchReject {
			t.Fatalf("rules=%d other host rejected", len(rules))
		}
	}
}

func TestPreMatchAppliesRouteMITMOverride(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()
	manager := &policyOutboundManager{items: map[string]adapter.Outbound{
		"direct": &selectorFlowOutbound{Adapter: outbound.NewAdapter("direct", "direct", []string{N.NetworkUDP}, nil)},
	}}
	// included.example is selected by the host lists; other.example only by force.
	engine := &fakeMITMEngine{quic: func(m *adapter.InboundContext) bool {
		switch m.MITMOverride {
		case C.MITMOverrideSkip:
			return false
		case C.MITMOverrideForce:
			return true
		}
		return m.Domain == "included.example"
	}}
	router := &Router{ctx: ctx, logger: logger, outbound: manager, dnsTransport: policyDNSManager{}, mitm: engine}
	for _, test := range []struct {
		name   string
		mitm   string
		domain string
		reject bool
	}{
		{"no override", "", "included.example", true},
		{"skip", C.MITMOverrideSkip, "included.example", false},
		{"force", C.MITMOverrideForce, "other.example", true},
		{"force not applied to others without override", "", "other.example", false},
	} {
		rules := []adapter.Rule{&policyRule{name: "route", outbound: "direct", mitm: test.mitm, match: func(*adapter.InboundContext) bool { return true }}}
		router.rules.Store(&rules)
		result := router.PreMatch(quicMetadata(test.domain), nil)
		if (result.Action == adapter.PreMatchReject) != test.reject {
			t.Fatalf("%s: action=%v reject=%v", test.name, result.Action, test.reject)
		}
	}
}

func TestPolicyReportsMITM(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()
	manager := &policyOutboundManager{items: map[string]adapter.Outbound{
		"direct": &selectorFlowOutbound{Adapter: outbound.NewAdapter("direct", "direct", []string{N.NetworkTCP, N.NetworkUDP}, nil)},
	}}
	engine := &fakeMITMEngine{
		quic: func(m *adapter.InboundContext) bool { return m.Domain == "blocked.example" },
		explain: func(m *adapter.InboundContext) (string, string) {
			switch m.Domain {
			case "scoped.example":
				return "skipped", "scope"
			case "excluded.example":
				return "skipped", "excluded"
			case "off.example":
				return "", ""
			}
			if m.Protocol != "tls" {
				return "skipped", "not_tls"
			}
			switch m.Domain {
			case "decrypt.example":
				return "decrypted", ""
			case "pinned.example":
				return "skipped", "pinned"
			case "builtin.example":
				return "skipped", "builtin"
			}
			return "skipped", "not_included"
		},
		decide: func(m *adapter.InboundContext) *adapter.MITMState {
			switch m.Domain {
			case "decrypt.example":
				return adapter.NewMITMState(adapter.MITMStatusPending, "")
			case "pinned.example":
				return adapter.NewMITMState(adapter.MITMStatusSkipped, "pinned")
			case "builtin.example":
				return adapter.NewMITMState(adapter.MITMStatusSkipped, "builtin")
			}
			return nil
		},
	}
	router := &Router{ctx: ctx, logger: logger, outbound: manager, dnsTransport: policyDNSManager{}, mitm: engine}
	router.rules.Store(&[]adapter.Rule{
		&policyRule{name: "fallback", outbound: "direct", match: func(*adapter.InboundContext) bool { return true }},
	})
	tcp := func(domain, protocol string) adapter.InboundContext {
		return adapter.InboundContext{Inbound: "tun-in", InboundType: "tun", Network: N.NetworkTCP, Protocol: protocol,
			Source: M.ParseSocksaddr("192.168.1.10:53421"), Destination: M.ParseSocksaddr("203.0.113.8:443"), Domain: domain}
	}
	for _, test := range []struct {
		name     string
		metadata adapter.InboundContext
		want     string
	}{
		{"decrypted", tcp("decrypt.example", "tls"), PolicyMITMDecrypted},
		{"unsniffed port 443", tcp("decrypt.example", ""), PolicyMITMDecrypted},
		{"skipped", tcp("pinned.example", "tls"), "skipped:pinned"},
		{"built-in exclusion", tcp("builtin.example", "tls"), "skipped:builtin"},
		{"not included", tcp("plain.example", "tls"), "skipped:not_included"},
		{"not tls", tcp("decrypt.example", "http"), "skipped:not_tls"},
		{"scope", tcp("scoped.example", "tls"), "skipped:scope"},
		{"excluded", tcp("excluded.example", "tls"), "skipped:excluded"},
		{"feature off", tcp("off.example", "tls"), ""},
		{"quic blocked", quicMetadata("blocked.example"), PolicyMITMBlockedQUIC},
		{"quic passed", quicMetadata("plain.example"), ""},
	} {
		result, err := router.TestPolicy(ctx, test.metadata)
		if err != nil || result.MITM != test.want {
			t.Fatalf("%s: mitm=%q want %q err=%v", test.name, result.MITM, test.want, err)
		}
	}
	router.mitm = nil
	result, err := router.TestPolicy(ctx, tcp("decrypt.example", "tls"))
	if err != nil || result.MITM != "" {
		t.Fatalf("no engine: mitm=%q err=%v", result.MITM, err)
	}
}
