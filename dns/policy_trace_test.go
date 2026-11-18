package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

type tracedDNSTransport struct{ *fakeDNSTransport }

func (*tracedDNSTransport) DNSMonitorDetour() (string, bool) { return "selected", true }

func TestPolicyTraceRecordsActualDNSRoute(t *testing.T) {
	transport := &tracedDNSTransport{&fakeDNSTransport{
		tag: "dns-work", address: netip.MustParseAddr("203.0.113.8"), immediate: true,
	}}
	router := raceTestRouter(t, transport.fakeDNSTransport)
	manager := router.transport.(*fakeDNSTransportManager)
	manager.transports[transport.Tag()] = transport
	router.rules = raceTestRules(t, []option.DNSRule{{DefaultOptions: option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{DomainSuffix: []string{"example.com"}},
		DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{Server: "dns-work"}},
	}}})
	ctx, metadata := adapter.ExtendContext(context.Background())
	metadata.Inbound = "tun-in"
	metadata.Source = M.ParseSocksaddr("192.168.1.10:53421")
	trace := &PolicyTrace{}
	ctx = WithPolicyTrace(ctx, trace)
	query := new(mDNS.Msg)
	query.SetQuestion("www.example.com.", mDNS.TypeA)
	response, err := router.Exchange(ctx, query, adapter.DNSQueryOptions{})
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("response=%v err=%v", response, err)
	}
	rule, index, server, detour := trace.Snapshot()
	if index != 0 || server != "dns-work" || detour != "selected" || rule == "" {
		t.Fatalf("trace rule=%q index=%d server=%q detour=%q", rule, index, server, detour)
	}
}
