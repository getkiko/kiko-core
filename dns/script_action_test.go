package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// scriptEngine is the part of a MITM engine the DNS router sees: its script manager.
type scriptEngine struct {
	adapter.MITMEngine
	manager *script.Manager
}

func (e scriptEngine) Scripts() *script.Manager { return e.manager }
func (e scriptEngine) ScriptHub() *script.Hub   { return nil }

type scriptRouterFixture struct {
	router  *Router
	final   *fakeDNSTransport
	alt     *fakeDNSTransport
	manager *script.Manager
	ctx     context.Context
	monitor *dnsmonitor.Manager
}

func newScriptRouter(t *testing.T, legacy bool, scripts []script.Config, rules []option.DNSRule) *scriptRouterFixture {
	t.Helper()
	final := &fakeDNSTransport{tag: "final", immediate: true, address: netip.MustParseAddr("203.0.113.1")}
	alt := &fakeDNSTransport{tag: "alt", immediate: true, address: netip.MustParseAddr("203.0.113.9")}
	manager := script.NewManager(script.ManagerOptions{})
	t.Cleanup(manager.Close)
	require.NoError(t, manager.Apply(scripts))
	ctx, monitor := dnsMonitorTestContext(t)
	service.MustRegister[adapter.MITMEngine](ctx, scriptEngine{manager: manager})
	router := raceTestRouter(t, final, alt)
	router.ctx = ctx
	router.legacyDNSMode = legacy
	router.rules = scriptTestRules(t, ctx, rules, legacy)
	return &scriptRouterFixture{router: router, final: final, alt: alt, manager: manager, ctx: ctx, monitor: monitor}
}

func scriptTestRules(t *testing.T, ctx context.Context, raw []option.DNSRule, legacy bool) []adapter.DNSRule {
	t.Helper()
	rules := make([]adapter.DNSRule, 0, len(raw))
	for _, rawRule := range raw {
		rule, err := R.NewDNSRule(ctx, log.NewNOPFactory().Logger(), rawRule, true, legacy)
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return rules
}

func (f *scriptRouterFixture) exchange(t *testing.T, name string, qtype uint16) *mDNS.Msg {
	t.Helper()
	query := new(mDNS.Msg)
	query.SetQuestion(name, qtype)
	response, err := f.router.Exchange(f.ctx, query, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	return response
}

func scriptRule(tag string, onError string, conditions ...func(*option.RawDefaultDNSRule)) option.DNSRule {
	rule := option.DefaultDNSRule{
		DNSRuleAction: option.DNSRuleAction{
			Action:        C.RuleActionTypeScript,
			ScriptOptions: option.DNSScriptActionOptions{Script: tag, OnError: onError},
		},
	}
	for _, apply := range conditions {
		apply(&rule.RawDefaultDNSRule)
	}
	return option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: rule}
}

func serverRule(server string, conditions ...func(*option.RawDefaultDNSRule)) option.DNSRule {
	rule := option.DefaultDNSRule{
		DNSRuleAction: option.DNSRuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{Server: server},
		},
	}
	for _, apply := range conditions {
		apply(&rule.RawDefaultDNSRule)
	}
	return option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: rule}
}

func domainSuffix(suffix string) func(*option.RawDefaultDNSRule) {
	return func(r *option.RawDefaultDNSRule) { r.DomainSuffix = []string{suffix} }
}

const dnsTestScript = `
	var d = $request.domain;
	if (d === 'answer.example') { $done({addresses: ['10.1.1.1', '2001:db8::1'], ttl: 77}); }
	else if (d === 'block.example') { $done({rcode: 'NXDOMAIN'}); }
	else if (d === 'via.example') { $done({server: 'alt'}); }
	else if (d === 'boom.example') { throw new Error('boom'); }
	else if (d === 'nodata.example') { $done({addresses: []}); }
`

func TestDNSScriptActionDecisions(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "modern"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			f := newScriptRouter(t, legacy,
				[]script.Config{{Tag: "dnsjs", Type: script.PhaseDNS, Source: dnsTestScript}},
				[]option.DNSRule{
					scriptRule("dnsjs", "", domainSuffix("example")),
					serverRule("final"),
				})

			// An answer: A gets the IPv4 address with the script's TTL, AAAA the IPv6 one.
			response := f.exchange(t, "answer.example.", mDNS.TypeA)
			require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
			require.Len(t, response.Answer, 1)
			a, ok := response.Answer[0].(*mDNS.A)
			require.True(t, ok)
			require.Equal(t, "10.1.1.1", a.A.String())
			require.EqualValues(t, 77, a.Hdr.Ttl)
			require.Equal(t, "answer.example.", a.Hdr.Name)
			response = f.exchange(t, "answer.example.", mDNS.TypeAAAA)
			require.Len(t, response.Answer, 1)
			require.Equal(t, "2001:db8::1", response.Answer[0].(*mDNS.AAAA).AAAA.String())
			// Another question type gets an empty, successful answer.
			response = f.exchange(t, "answer.example.", mDNS.TypeTXT)
			require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
			require.Empty(t, response.Answer)
			require.Zero(t, f.final.queryCount.Load(), "a script answer is not forwarded")

			response = f.exchange(t, "block.example.", mDNS.TypeA)
			require.Equal(t, mDNS.RcodeNameError, response.Rcode)
			response = f.exchange(t, "nodata.example.", mDNS.TypeA)
			require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
			require.Empty(t, response.Answer)

			// A server decision sends the query there.
			response = f.exchange(t, "via.example.", mDNS.TypeA)
			require.Len(t, response.Answer, 1)
			require.Equal(t, "203.0.113.9", response.Answer[0].(*mDNS.A).A.String())
			require.EqualValues(t, 1, f.alt.queryCount.Load())

			// No decision, and a failing script (default on_error), go on to the next rule.
			response = f.exchange(t, "other.example.", mDNS.TypeA)
			require.Equal(t, "203.0.113.1", response.Answer[0].(*mDNS.A).A.String())
			response = f.exchange(t, "boom.example.", mDNS.TypeA)
			require.Equal(t, "203.0.113.1", response.Answer[0].(*mDNS.A).A.String())
		})
	}
}

func TestDNSScriptActionOnErrorReject(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		f := newScriptRouter(t, legacy,
			[]script.Config{{Tag: "dnsjs", Type: script.PhaseDNS, Source: dnsTestScript}},
			[]option.DNSRule{scriptRule("dnsjs", "reject"), serverRule("final")})
		response := f.exchange(t, "boom.example.", mDNS.TypeA)
		require.Equal(t, mDNS.RcodeRefused, response.Rcode, "legacy=%v", legacy)
		require.Zero(t, f.final.queryCount.Load())
		// A healthy answer still passes through.
		response = f.exchange(t, "answer.example.", mDNS.TypeA)
		require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
		require.Len(t, response.Answer, 1)
	}
}

func TestDNSScriptActionMissingScriptContinues(t *testing.T) {
	f := newScriptRouter(t, false, nil, []option.DNSRule{scriptRule("gone", ""), serverRule("final")})
	response := f.exchange(t, "any.example.", mDNS.TypeA)
	require.Equal(t, "203.0.113.1", response.Answer[0].(*mDNS.A).A.String())
}

func TestDNSScriptConditionDecidesRule(t *testing.T) {
	cond := func(r *option.RawDefaultDNSRule) { r.Script = []string{"only-a"} }
	f := newScriptRouter(t, false,
		[]script.Config{{Tag: "only-a", Type: script.PhaseRule, Source: `$done($request.domain === 'a.example' && $request.queryType === 'A')`}},
		[]option.DNSRule{serverRule("alt", cond), serverRule("final")})
	response := f.exchange(t, "a.example.", mDNS.TypeA)
	require.Equal(t, "203.0.113.9", response.Answer[0].(*mDNS.A).A.String())
	response = f.exchange(t, "b.example.", mDNS.TypeA)
	require.Equal(t, "203.0.113.1", response.Answer[0].(*mDNS.A).A.String())
}

// A policy test does not run scripts: a script condition is false, a script action passes,
// and the tags are reported.
func TestDNSScriptDryRunReportsMaybe(t *testing.T) {
	cond := func(r *option.RawDefaultDNSRule) { r.Script = []string{"only-a"} }
	f := newScriptRouter(t, false,
		[]script.Config{
			{Tag: "only-a", Type: script.PhaseRule, Source: `$done(true)`},
			{Tag: "dnsjs", Type: script.PhaseDNS, Source: dnsTestScript},
		},
		[]option.DNSRule{serverRule("alt", cond), scriptRule("dnsjs", ""), serverRule("final")})
	dry := &adapter.ScriptDryRun{}
	ctx, metadata := adapter.ExtendContext(f.ctx)
	metadata.ScriptDryRun = dry
	f.ctx = ctx
	response := f.exchange(t, "answer.example.", mDNS.TypeA)
	require.Equal(t, "203.0.113.1", response.Answer[0].(*mDNS.A).A.String())
	require.Equal(t, []string{"only-a", "dnsjs"}, dry.Tags())
	require.Zero(t, f.manager.RuleCacheLen(), "no script ran")
}

func TestDNSScriptResultInMonitor(t *testing.T) {
	f := newScriptRouter(t, false,
		[]script.Config{{Tag: "dnsjs", Type: script.PhaseDNS, Source: dnsTestScript}},
		[]option.DNSRule{scriptRule("dnsjs", ""), serverRule("final")})
	f.exchange(t, "answer.example.", mDNS.TypeA)
	f.exchange(t, "answer.example.", mDNS.TypeA)
	f.exchange(t, "boom.example.", mDNS.TypeA)
	var answered, cached, failed int
	for _, summary := range f.monitor.List(dnsmonitor.Filter{}).Queries {
		query, ok := f.monitor.Get(summary.ID)
		require.True(t, ok)
		for _, run := range query.Scripts {
			require.Equal(t, "dnsjs", run.Tag)
			switch run.Outcome {
			case "answer":
				answered++
				require.Contains(t, run.Detail, "10.1.1.1")
				if run.Cached {
					cached++
				}
			case "error":
				failed++
				require.Contains(t, run.Detail, "boom")
			}
		}
	}
	require.Equal(t, 2, answered)
	require.Equal(t, 1, cached)
	require.Equal(t, 1, failed)
}

func TestScriptAnswerRecords(t *testing.T) {
	decision := script.DNSDecision{Kind: script.DNSAnswer, TTL: 30, Addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("::1")}}
	require.Len(t, scriptAnswer(decision, mDNS.TypeA).Answer, 1)
	require.Len(t, scriptAnswer(decision, mDNS.TypeAAAA).Answer, 1)
	require.Len(t, scriptAnswer(decision, mDNS.TypeANY).Answer, 2)
	require.Empty(t, scriptAnswer(decision, mDNS.TypeMX).Answer)
	require.Equal(t, mDNS.RcodeNameError, scriptAnswer(script.DNSDecision{Kind: script.DNSAnswer, Rcode: mDNS.RcodeNameError}, mDNS.TypeA).Rcode)
}

func TestScriptAnswerQueryTypeZeroAnswersBothFamilies(t *testing.T) {
	decision := script.DNSDecision{Kind: script.DNSAnswer, TTL: 30, Addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("::1")}}
	require.Len(t, scriptAnswer(decision, 0).Answer, 2)
}

func TestDNSScriptLookup(t *testing.T) {
	const source = `
		if ($request.domain === 'answer.example') {
			if ($request.queryType === 'AAAA') { $done({addresses: ['2001:db8::1']}); }
			else if ($request.queryType === 'A') { $done({addresses: ['10.1.1.1']}); }
			else { $done({addresses: ['10.1.1.1', '2001:db8::1']}); }
		}
	`
	for _, legacy := range []bool{false, true} {
		name := "modern"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			f := newScriptRouter(t, legacy,
				[]script.Config{{Tag: "dnsjs", Type: script.PhaseDNS, Source: source}},
				[]option.DNSRule{
					scriptRule("dnsjs", "", domainSuffix("example")),
					serverRule("final"),
				})
			addrs, err := f.router.Lookup(f.ctx, "answer.example", adapter.DNSQueryOptions{})
			require.NoError(t, err)
			require.ElementsMatch(t, []netip.Addr{netip.MustParseAddr("10.1.1.1"), netip.MustParseAddr("2001:db8::1")}, addrs)

			addrs, err = f.router.Lookup(f.ctx, "answer.example", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("10.1.1.1")}, addrs)

			addrs, err = f.router.Lookup(f.ctx, "answer.example", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv6Only})
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, addrs)
		})
	}
}

// A pre-match evaluation has partial metadata: the script condition is false without running.
func TestScriptConditionSkipsPreMatch(t *testing.T) {
	f := newScriptRouter(t, false,
		[]script.Config{{Tag: "only-a", Type: script.PhaseRule, Source: `$done(false)`}}, nil)
	item := R.NewScriptItem(f.ctx, log.NewNOPFactory().Logger(), []string{"only-a"})
	metadata := &adapter.InboundContext{PreMatch: true}
	require.False(t, item.Match(metadata))
	require.Zero(t, f.manager.RuleCacheLen(), "the script did not run")
	metadata.PreMatch = false
	metadata.Domain = "a.example"
	require.False(t, item.Match(metadata))
	require.NotZero(t, f.manager.RuleCacheLen(), "the script ran outside pre-match")
}
