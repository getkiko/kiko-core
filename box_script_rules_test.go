package box_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const scriptRulesConfig = `{
  "log": {"disabled": true},
  "scripts": [
    {"tag": "pick", "type": "rule", "source_path": "scripts/pick.js"},
    {"tag": "dnsjs", "type": "dns", "source_path": "scripts/dns.js"}
  ],
  "dns": {
    "servers": [{"type": "local", "tag": "dns-local"}],
    "rules": [{"domain_suffix": ["fast.test"], "action": "script", "dns_script": "dnsjs"}],
    "final": "dns-local"
  },
  "outbounds": [
    {"type": "direct", "tag": "d1"},
    {"type": "direct", "tag": "d2"}
  ],
  "route": {
    "rules": [{"domain_suffix": ["x.test"], "script": ["pick"], "outbound": "d2"}],
    "final": "d1"
  }
}`

func writeRuleScripts(t *testing.T, pick, dns string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts", "pick.js"), []byte(pick), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts", "dns.js"), []byte(dns), 0o644))
	t.Chdir(dir)
}

func scriptTestMetadata(domain string) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound: "in", InboundType: "mixed", Network: N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.168.1.10:53421"),
		Destination: M.ParseSocksaddr("203.0.113.8:443"),
		Domain:      domain,
	}
}

func TestScriptRulesRouteAndDNS(t *testing.T) {
	writeRuleScripts(t,
		`$done($request.domain.indexOf('yes.') === 0)`,
		`$done({addresses: ['10.9.8.7'], ttl: 20})`)
	ctx, instance := startLiveBox(t, scriptRulesConfig)
	router := instance.Router().(*route.Router)

	// The script condition decides the route; a script that says no leaves the rule unmatched.
	result, err := router.TestPolicy(ctx, scriptTestMetadata("yes.x.test"))
	require.NoError(t, err)
	require.Equal(t, 0, result.RuleIndex)
	require.Equal(t, []string{"d2"}, result.OutboundPath)
	result, err = router.TestPolicy(ctx, scriptTestMetadata("no.x.test"))
	require.NoError(t, err)
	require.Equal(t, -1, result.RuleIndex)
	require.Equal(t, []string{"d1"}, result.OutboundPath)

	// A policy test (dry run) does not run the script and names it.
	dry := &adapter.ScriptDryRun{}
	metadata := scriptTestMetadata("yes.x.test")
	metadata.ScriptDryRun = dry
	result, err = router.TestPolicy(ctx, metadata)
	require.NoError(t, err)
	require.Equal(t, -1, result.RuleIndex)
	require.Equal(t, []string{"pick"}, dry.Tags())
	// A rule whose other conditions fail does not consult the script at all.
	dry = &adapter.ScriptDryRun{}
	metadata = scriptTestMetadata("yes.other.test")
	metadata.ScriptDryRun = dry
	_, err = router.TestPolicy(ctx, metadata)
	require.NoError(t, err)
	require.Empty(t, dry.Tags())

	// The DNS action answers without any upstream.
	query := new(mDNS.Msg)
	query.SetQuestion("www.fast.test.", mDNS.TypeA)
	response, err := service.FromContext[adapter.DNSRouter](ctx).Exchange(ctx, query, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	require.Equal(t, netip.MustParseAddr("10.9.8.7"), mustAddr(t, response.Answer[0].(*mDNS.A).A))
	require.EqualValues(t, 20, response.Answer[0].Header().Ttl)
}

func mustAddr(t *testing.T, ip []byte) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	require.True(t, ok)
	return addr.Unmap()
}

// A live apply replaces the scripts and rules without rebuilding the router, and an answer
// cached for the old script is not served for the new one.
func TestScriptRulesLiveApply(t *testing.T) {
	writeRuleScripts(t,
		`$done($request.domain.indexOf('yes.') === 0)`,
		`$done({addresses: ['10.9.8.7'], ttl: 20})`)
	ctx, instance := startLiveBox(t, scriptRulesConfig)
	router := instance.Router().(*route.Router)
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	probe := func() (int, string) {
		result, err := router.TestPolicy(ctx, scriptTestMetadata("yes.x.test"))
		require.NoError(t, err)
		query := new(mDNS.Msg)
		query.SetQuestion("www.fast.test.", mDNS.TypeA)
		response, err := dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{})
		require.NoError(t, err)
		return result.RuleIndex, response.Answer[0].(*mDNS.A).A.String()
	}
	index, address := probe()
	require.Equal(t, 0, index)
	require.Equal(t, "10.9.8.7", address)

	// New script files and a changed argument (the options must differ for a reload).
	require.NoError(t, os.WriteFile("scripts/pick.js", []byte(`$done(false)`), 0o644))
	require.NoError(t, os.WriteFile("scripts/dns.js", []byte(`$done({addresses: ['10.9.8.99']})`), 0o644))
	changed := strings.Replace(scriptRulesConfig, `"source_path": "scripts/pick.js"`, `"source_path": "scripts/pick.js", "argument": "2"`, 1)
	changed = strings.Replace(changed, `"source_path": "scripts/dns.js"`, `"source_path": "scripts/dns.js", "argument": "2"`, 1)
	result, err := applyLive(t, ctx, changed)
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Same(t, router, instance.Router().(*route.Router))
	index, address = probe()
	require.Equal(t, -1, index)
	require.Equal(t, "10.9.8.99", address)

	// A reference to a script that does not exist is refused, and the running rules stay.
	broken := strings.Replace(changed, `"script": ["pick"]`, `"script": ["nope"]`, 1)
	_, err = applyLive(t, ctx, broken)
	require.Error(t, err)
	index, _ = probe()
	require.Equal(t, -1, index)
}

func TestScriptReferencesValidated(t *testing.T) {
	writeRuleScripts(t, `$done(true)`, `$done()`)
	ctx := include.Context(context.Background())
	for name, tc := range map[string]struct {
		from, to string
		message  string
	}{
		"missing rule script":     {`"script": ["pick"]`, `"script": ["nope"]`, "script not found: nope"},
		"dns script in condition": {`"script": ["pick"]`, `"script": ["dnsjs"]`, "not a rule script"},
		"rule script in action":   {`"dns_script": "dnsjs"`, `"dns_script": "pick"`, "not a dns script"},
	} {
		t.Run(name, func(t *testing.T) {
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(strings.Replace(scriptRulesConfig, tc.from, tc.to, 1)))
			require.NoError(t, err)
			require.ErrorContains(t, route.ValidateScriptReferences(options.Scripts, *options.Route, *options.DNS), tc.message)
		})
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(scriptRulesConfig))
	require.NoError(t, err)
	require.NoError(t, route.ValidateScriptReferences(options.Scripts, *options.Route, *options.DNS))
}
