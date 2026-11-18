package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type typedFakeDNSTransport struct {
	*fakeDNSTransport
	transportType string
}

func (t *typedFakeDNSTransport) Type() string { return t.transportType }

func parallelRouteRule(servers ...string) option.DNSRule {
	return option.DNSRule{
		DefaultOptions: option.DefaultDNSRule{
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Servers: servers},
			},
		},
	}
}

func parallelRequest(name string) *mDNS.Msg {
	request := new(mDNS.Msg)
	request.SetQuestion(name, mDNS.TypeA)
	return request
}

func newParallel(router *Router, servers ...string) adapter.DNSTransport {
	transport, loaded := router.routeTransport(&R.RuleActionDNSRoute{Server: R.ParallelDNSServerTag(servers), Servers: servers})
	if !loaded {
		panic("parallel transport not loaded")
	}
	return transport
}

func TestParallelDNSFirstSuccessWins(t *testing.T) {
	t.Parallel()
	slow := &fakeDNSTransport{tag: "slow", delay: 500 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}
	fast := &fakeDNSTransport{tag: "fast", delay: 20 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, slow, fast)
	started := time.Now()
	response, err := newParallel(router, "slow", "fast").Exchange(context.Background(), parallelRequest("a.example."))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, response))
	require.Less(t, time.Since(started), 300*time.Millisecond)
	require.Equal(t, int32(1), slow.queryCount.Load())
	require.Equal(t, int32(1), fast.queryCount.Load())
}

// A fast SERVFAIL or error must not end the query while a server is pending.
func TestParallelDNSFailuresWaitForSuccess(t *testing.T) {
	t.Parallel()
	failing := &fakeDNSTransport{tag: "servfail", delay: 5 * time.Millisecond, rcode: mDNS.RcodeServerFailure}
	refused := &fakeDNSTransport{tag: "refused", delay: 5 * time.Millisecond, exchangeErr: RcodeRefused}
	broken := &fakeDNSTransport{tag: "broken", delay: 5 * time.Millisecond, exchangeErr: errors.New("connection refused")}
	good := &fakeDNSTransport{tag: "good", delay: 80 * time.Millisecond, address: netip.MustParseAddr("192.0.2.3")}
	router := raceTestRouter(t, failing, refused, broken, good)
	response, err := newParallel(router, "servfail", "refused", "broken", "good").Exchange(context.Background(), parallelRequest("b.example."))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("192.0.2.3"), responseAddress(t, response))
}

// NXDOMAIN is a definite answer and wins like NOERROR.
func TestParallelDNSNameErrorWins(t *testing.T) {
	t.Parallel()
	missing := &fakeDNSTransport{tag: "nx", delay: 5 * time.Millisecond, rcode: mDNS.RcodeNameError}
	slow := &fakeDNSTransport{tag: "slow", delay: 500 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}
	router := raceTestRouter(t, missing, slow)
	response, err := newParallel(router, "nx", "slow").Exchange(context.Background(), parallelRequest("c.example."))
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
}

func TestParallelDNSAllFail(t *testing.T) {
	t.Parallel()
	failing := &fakeDNSTransport{tag: "servfail", delay: 20 * time.Millisecond, rcode: mDNS.RcodeServerFailure}
	broken := &fakeDNSTransport{tag: "broken", delay: 5 * time.Millisecond, exchangeErr: errors.New("connection refused")}
	other := &fakeDNSTransport{tag: "other", delay: 5 * time.Millisecond, exchangeErr: errors.New("timeout")}
	router := raceTestRouter(t, failing, broken, other)
	response, err := newParallel(router, "broken", "servfail").Exchange(context.Background(), parallelRequest("d.example."))
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
	_, err = newParallel(router, "broken", "other").Exchange(context.Background(), parallelRequest("d.example."))
	require.ErrorContains(t, err, "connection refused")
	require.ErrorContains(t, err, "timeout")
}

func TestParallelDNSRuleRoutesThroughRouter(t *testing.T) {
	t.Parallel()
	slow := &fakeDNSTransport{tag: "x", delay: 300 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}
	fast := &fakeDNSTransport{tag: "y", delay: 10 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, slow, fast)
	rules := raceTestRules(t, []option.DNSRule{parallelRouteRule("x", "y")})
	result := raceTestExchange(router, rules)
	require.NoError(t, result.err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, result.response))
	require.Equal(t, "[x, y]", result.transport.Tag())
	require.Equal(t, C.DNSTypeParallel, result.transport.Type())
}

func TestParallelDNSMonitorRecordsAnsweringServer(t *testing.T) {
	ctx, m := dnsMonitorTestContext(t)
	slow := &fakeDNSTransport{tag: "slow", delay: 300 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}
	fast := &fakeDNSTransport{tag: "fast", delay: 10 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, slow, fast)
	client := NewClient(ClientOptions{Context: ctx, Logger: log.NewNOPFactory().Logger()})
	transport := newParallel(router, "slow", "fast")
	_, err := client.Exchange(ctx, transport, parallelRequest("e.example."), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	queries := m.List(dnsmonitor.Filter{}).Queries
	require.Len(t, queries, 1)
	query, _ := m.Get(queries[0].ID)
	require.Equal(t, "fast", query.Resolver)
	require.Equal(t, "fake", query.Transport)
	require.Equal(t, []string{"slow", "fast"}, query.Candidates)
	resolvers := map[string]bool{}
	for _, attempt := range query.Attempts {
		resolvers[attempt.Resolver] = true
	}
	require.Equal(t, map[string]bool{"slow": true, "fast": true}, resolvers)

	// The cached answer still names the servers asked.
	_, err = client.Exchange(ctx, transport, parallelRequest("e.example."), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), fast.queryCount.Load())
	queries = m.List(dnsmonitor.Filter{}).Queries
	require.Len(t, queries, 2)
	cached, _ := m.Get(queries[0].ID)
	if cached.Cache != "hit" {
		cached, _ = m.Get(queries[1].ID)
	}
	require.Equal(t, "hit", cached.Cache)
	require.Equal(t, []string{"slow", "fast"}, cached.Candidates)
}

// The cache keys a concurrent query by its servers: another set of servers
// or a single member does not reuse its answer.
func TestParallelDNSCacheKey(t *testing.T) {
	t.Parallel()
	x := &fakeDNSTransport{tag: "x", delay: 5 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}
	y := &fakeDNSTransport{tag: "y", delay: 50 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, x, y)
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	_, err := client.Exchange(context.Background(), newParallel(router, "x", "y"), parallelRequest("f.example."), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), newParallel(router, "x", "y"), parallelRequest("f.example."), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), x.queryCount.Load())
	_, err = client.Exchange(context.Background(), x, parallelRequest("f.example."), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), x.queryCount.Load())
}

func TestParallelDNSRuleOptions(t *testing.T) {
	t.Parallel()
	var rule option.DNSRule
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"domain":"example.com","servers":["a","b","a"]}`), &rule))
	require.Equal(t, []string{"a", "b", "a"}, []string(rule.DefaultOptions.RouteOptions.Servers))
	built, err := R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rule, true, false)
	require.NoError(t, err)
	action := built.Action().(*R.RuleActionDNSRoute)
	require.Equal(t, []string{"a", "b"}, action.Servers)
	require.Equal(t, "[a, b]", action.Server)

	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"domain":"example.com","servers":"a"}`), &rule))
	built, err = R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rule, true, false)
	require.NoError(t, err)
	action = built.Action().(*R.RuleActionDNSRoute)
	require.Equal(t, "a", action.Server)
	require.Empty(t, action.Servers)

	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"domain":"example.com","server":"a","servers":["b","c"]}`), &rule))
	_, err = R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rule, true, false)
	require.ErrorContains(t, err, "mutually exclusive")

	rule = option.DNSRule{}
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"domain":"example.com","servers":["a","b"]}`), &rule))
	encoded, err := json.Marshal(rule)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"servers":["a","b"]`)
}

func TestParallelDNSRejectsFakeIP(t *testing.T) {
	t.Parallel()
	plain := &fakeDNSTransport{tag: "real"}
	fake := &typedFakeDNSTransport{fakeDNSTransport: &fakeDNSTransport{tag: "fakeip"}, transportType: C.DNSTypeFakeIP}
	manager := &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{"real": plain, "fakeip": fake}}
	require.ErrorContains(t, validateParallelDNSRules([]option.DNSRule{parallelRouteRule("real", "fakeip")}, manager), "fakeip")
	require.ErrorContains(t, validateParallelDNSRules([]option.DNSRule{parallelRouteRule("real", "missing")}, manager), "not found")
	require.NoError(t, validateParallelDNSRules([]option.DNSRule{parallelRouteRule("real", "real")}, manager))
	require.NoError(t, validateParallelDNSRules([]option.DNSRule{parallelRouteRule("real")}, manager))
}

// Through the router, the monitor and a policy test name the server that
// answered, not the combined query.
func TestParallelDNSRouterRecordsAnsweringServer(t *testing.T) {
	ctx, m := dnsMonitorTestContext(t)
	slow := &tracedDNSTransport{&fakeDNSTransport{tag: "slow", delay: 300 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}}
	fast := &tracedDNSTransport{&fakeDNSTransport{tag: "fast", delay: 10 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}}
	router := raceTestRouter(t)
	manager := router.transport.(*fakeDNSTransportManager)
	manager.transports["slow"], manager.transports["fast"] = slow, fast
	router.client = NewClient(ClientOptions{Context: ctx, DisableCache: true, Logger: log.NewNOPFactory().Logger()})
	rule := parallelRouteRule("slow", "fast")
	rule.DefaultOptions.DomainSuffix = []string{"example.com"}
	router.rules = raceTestRules(t, []option.DNSRule{rule})
	ctx, _ = adapter.ExtendContext(ctx)
	trace := &PolicyTrace{}
	ctx = WithPolicyTrace(ctx, trace)
	response, err := router.Exchange(ctx, parallelRequest("www.example.com."), adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), responseAddress(t, response))
	_, _, server, detour := trace.Snapshot()
	require.Equal(t, "fast", server)
	require.Equal(t, "selected", detour)
	var found bool
	for _, q := range m.List(dnsmonitor.Filter{}).Queries {
		full, _ := m.Get(q.ID)
		if len(full.Candidates) > 0 {
			found = true
			require.Equal(t, "fast", full.Resolver)
			require.Equal(t, []string{"slow", "fast"}, full.Candidates)
		}
	}
	require.True(t, found)
}

type environmentFakeDNSTransport struct {
	*fakeDNSTransport
	environment atomic.Value
}

func (t *environmentFakeDNSTransport) Environment() []string {
	return []string{t.environment.Load().(string)}
}

// A concurrent query with a network-dependent member (local, DHCP) keys
// its cache by that member's environment, as the member alone would: a
// network change does not reuse the answer.
func TestParallelDNSCacheKeyEnvironment(t *testing.T) {
	t.Parallel()
	local := &environmentFakeDNSTransport{fakeDNSTransport: &fakeDNSTransport{tag: "local", delay: 5 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}}
	local.environment.Store("lan-a")
	remote := &fakeDNSTransport{tag: "remote", delay: 50 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, local.fakeDNSTransport, remote)
	router.transport.(*fakeDNSTransportManager).transports["local"] = local
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	exchange := func() {
		_, err := client.Exchange(context.Background(), newParallel(router, "local", "remote"), parallelRequest("g.example."), adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err)
	}
	exchange()
	exchange()
	require.Equal(t, int32(1), local.queryCount.Load())
	local.environment.Store("lan-b")
	exchange()
	require.Equal(t, int32(2), local.queryCount.Load())

	plain := &fakeDNSTransport{tag: "plain", delay: 5 * time.Millisecond, address: netip.MustParseAddr("192.0.2.3")}
	other := &fakeDNSTransport{tag: "other", delay: 50 * time.Millisecond, address: netip.MustParseAddr("192.0.2.4")}
	require.Zero(t, client.environmentHash(newParallel(raceTestRouter(t, plain, other), "plain", "other")))
}
