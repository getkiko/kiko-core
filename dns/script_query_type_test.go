package dns

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A legacy-mode lookup reports its question type to scripts only: query_type rules see the
// metadata as before (no question type), whatever the domain strategy is.
func TestLegacyLookupQueryTypeRulesUnchanged(t *testing.T) {
	queryTypeA := func(r *option.RawDefaultDNSRule) {
		r.QueryType = badoption.Listable[option.DNSQueryType]{option.DNSQueryType(mDNS.TypeA)}
	}
	invert := func(r *option.RawDefaultDNSRule) { r.Invert = true }
	final := netip.MustParseAddr("203.0.113.1")
	alt := netip.MustParseAddr("203.0.113.9")
	for _, strategy := range []C.DomainStrategy{C.DomainStrategyAsIS, C.DomainStrategyIPv4Only} {
		f := newScriptRouter(t, true, nil, []option.DNSRule{
			serverRule("alt", queryTypeA),
			serverRule("final"),
		})
		addrs, err := f.router.Lookup(f.ctx, "plain.example", adapter.DNSQueryOptions{Strategy: strategy})
		require.NoError(t, err)
		require.NotContains(t, addrs, alt, "a query_type:[A] rule must not match a legacy lookup (strategy %d)", strategy)
		require.Contains(t, addrs, final)

		f = newScriptRouter(t, true, nil, []option.DNSRule{
			serverRule("alt", queryTypeA, invert),
			serverRule("final"),
		})
		addrs, err = f.router.Lookup(f.ctx, "plain.example", adapter.DNSQueryOptions{Strategy: strategy})
		require.NoError(t, err)
		require.Contains(t, addrs, alt, "an inverted query_type rule matches as before (strategy %d)", strategy)
	}
}
