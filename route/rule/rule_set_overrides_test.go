package rule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

func defaultRule(build func(*option.DefaultHeadlessRule)) option.HeadlessRule {
	rule := option.HeadlessRule{Type: C.RuleTypeDefault}
	build(&rule.DefaultOptions)
	return rule
}

func removeOverrides(build func(*option.DefaultHeadlessRule), add ...option.HeadlessRule) *option.RuleSetOverrides {
	remove := &option.DefaultHeadlessRule{}
	build(remove)
	return &option.RuleSetOverrides{Remove: remove, Add: add}
}

func TestApplyRuleSetOverridesRemovesDomains(t *testing.T) {
	t.Parallel()
	source := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test", "b.test"}
		r.DomainSuffix = badoption.Listable[string]{"c.test", "d.test"}
		r.DomainKeyword = badoption.Listable[string]{"kw", "other"}
		r.DomainRegex = badoption.Listable[string]{`^x\.test$`}
	})}
	rules, err := ApplyRuleSetOverrides(source, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
		r.DomainSuffix = badoption.Listable[string]{"d.test"}
		r.DomainKeyword = badoption.Listable[string]{"kw"}
		r.DomainRegex = badoption.Listable[string]{`^x\.test$`}
	}))
	require.NoError(t, err)
	require.Len(t, rules, 1)
	got := rules[0].DefaultOptions
	require.Equal(t, []string{"b.test"}, []string(got.Domain))
	require.Equal(t, []string{"c.test"}, []string(got.DomainSuffix))
	require.Equal(t, []string{"other"}, []string(got.DomainKeyword))
	require.Empty(t, got.DomainRegex)
	// The source stays as it is.
	require.Equal(t, []string{"a.test", "b.test"}, []string(source[0].DefaultOptions.Domain))
	require.Len(t, source[0].DefaultOptions.DomainRegex, 1)
}

func TestApplyRuleSetOverridesSplitsAddressRanges(t *testing.T) {
	t.Parallel()
	source := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/8", "192.168.1.1"}
		r.SourceIPCIDR = badoption.Listable[string]{"172.16.0.0/12"}
	})}
	rules, err := ApplyRuleSetOverrides(source, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.IPCIDR = badoption.Listable[string]{"10.1.2.3", "192.168.1.1/32"}
		r.SourceIPCIDR = badoption.Listable[string]{"172.16.5.0/24"}
	}))
	require.NoError(t, err)
	require.Len(t, rules, 1)
	destination := ipSetOf(t, rules[0].DefaultOptions.IPCIDR)
	require.False(t, destination.Contains(netip.MustParseAddr("10.1.2.3")))
	require.False(t, destination.Contains(netip.MustParseAddr("192.168.1.1")))
	require.True(t, destination.Contains(netip.MustParseAddr("10.1.2.4")))
	require.True(t, destination.Contains(netip.MustParseAddr("10.200.0.1")))
	source2 := ipSetOf(t, rules[0].DefaultOptions.SourceIPCIDR)
	require.False(t, source2.Contains(netip.MustParseAddr("172.16.5.9")))
	require.True(t, source2.Contains(netip.MustParseAddr("172.16.6.1")))
}

func TestApplyRuleSetOverridesSubtractsDecodedSets(t *testing.T) {
	t.Parallel()
	var builder netipx.IPSetBuilder
	builder.AddPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	set, err := builder.IPSet()
	require.NoError(t, err)
	source := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) { r.IPSet = set })}
	rules, err := ApplyRuleSetOverrides(source, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/9"}
	}))
	require.NoError(t, err)
	require.Len(t, rules, 1)
	got := rules[0].DefaultOptions.IPSet
	require.NotNil(t, got)
	require.False(t, got.Contains(netip.MustParseAddr("10.1.0.0")))
	require.True(t, got.Contains(netip.MustParseAddr("10.128.0.1")))
	require.True(t, set.Contains(netip.MustParseAddr("10.1.0.0")))
}

func TestApplyRuleSetOverridesEmptiedGroups(t *testing.T) {
	t.Parallel()
	source := []option.HeadlessRule{
		// The domains empty and nothing else can satisfy the destination:
		// the rule stays and matches nothing.
		defaultRule(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"a.test"}
			r.ProcessName = badoption.Listable[string]{"curl"}
		}),
		// The domains empty, ip_cidr stays: the domains match nothing.
		defaultRule(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"a.test"}
			r.IPCIDR = badoption.Listable[string]{"1.1.1.1/32"}
		}),
		// The process_name group empties: it matches nothing.
		defaultRule(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"b.test"}
			r.ProcessName = badoption.Listable[string]{"wget"}
		}),
		// The whole address range leaves: ip_cidr matches nothing.
		defaultRule(func(r *option.DefaultHeadlessRule) {
			r.IPCIDR = badoption.Listable[string]{"10.0.0.0/24"}
		}),
		// Untouched.
		defaultRule(func(r *option.DefaultHeadlessRule) {
			r.Port = badoption.Listable[uint16]{443}
		}),
	}
	rules, err := ApplyRuleSetOverrides(source, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
		r.ProcessName = badoption.Listable[string]{"wget"}
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/16"}
	}))
	require.NoError(t, err)
	// No rule goes: emptied groups hold values that match nothing.
	require.Len(t, rules, 5)
	require.Empty(t, rules[0].DefaultOptions.Domain)
	require.Equal(t, []string{noDomainRegex}, []string(rules[0].DefaultOptions.DomainRegex))
	require.Equal(t, []string{"curl"}, []string(rules[0].DefaultOptions.ProcessName))
	require.Equal(t, []string{noDomainRegex}, []string(rules[1].DefaultOptions.DomainRegex))
	require.Equal(t, []string{"1.1.1.1/32"}, []string(rules[1].DefaultOptions.IPCIDR))
	require.Equal(t, []string{noProcessValue}, []string(rules[2].DefaultOptions.ProcessName))
	require.Equal(t, []string{"b.test"}, []string(rules[2].DefaultOptions.Domain))
	require.Empty(t, rules[3].DefaultOptions.IPCIDR)
	require.NotNil(t, rules[3].DefaultOptions.IPSet)
	require.Equal(t, []uint16{443}, []uint16(rules[4].DefaultOptions.Port))

	// The process placeholder keeps the metadata.
	before := buildRuleSetMetadata(source)
	require.Equal(t, before, buildRuleSetMetadata(rules))
}

// An outer rule with a condition of the same group as a single-rule set
// merges with it (or); removing values must not change the rule count and
// with it the merge path.
func TestApplyRuleSetOverridesKeepsMergePath(t *testing.T) {
	t.Parallel()
	outer := func(ruleSet adapter.RuleSet) *DefaultRule {
		return routeRuleForTest(func(rule *abstractDefaultRule) {
			addDestinationIPCIDRItem(t, rule, []string{"10.0.0.0/8"})
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}})
		})
	}
	matches := func(rule *DefaultRule, domain, to string) bool {
		metadata := adapter.InboundContext{
			Network:     "tcp",
			Domain:      domain,
			Source:      M.ParseSocksaddrHostPort("192.168.1.2", 1000),
			Destination: M.ParseSocksaddrHostPort(to, 443),
		}
		return rule.Match(&metadata)
	}
	load := func(source []option.HeadlessRule, overrides *option.RuleSetOverrides) *LocalRuleSet {
		ruleSet := &LocalRuleSet{ctx: context.Background(), tag: "merge", overrides: overrides}
		require.NoError(t, ruleSet.reloadRules(source))
		return ruleSet
	}
	removeA := removeOverrides(func(r *option.DefaultHeadlessRule) { r.Domain = badoption.Listable[string]{"a.test"} })

	// Two rules, one emptied: the set stays off the merge path, so the
	// outer ip_cidr still has to match together with the set.
	two := []option.HeadlessRule{
		defaultRule(func(r *option.DefaultHeadlessRule) { r.Domain = badoption.Listable[string]{"a.test"} }),
		defaultRule(func(r *option.DefaultHeadlessRule) { r.DomainSuffix = badoption.Listable[string]{"b.test"} }),
	}
	original, overridden := outer(load(two, nil)), outer(load(two, removeA))
	require.False(t, matches(original, "other.test", "10.1.1.1"))
	require.False(t, matches(overridden, "other.test", "10.1.1.1"))
	require.True(t, matches(original, "a.test", "10.1.1.1"))
	require.False(t, matches(overridden, "a.test", "10.1.1.1"))
	require.True(t, matches(overridden, "x.b.test", "10.1.1.1"))
	require.Len(t, load(two, removeA).rules, 2)

	// Two rules, process_name emptied: the same.
	withProcess := []option.HeadlessRule{
		defaultRule(func(r *option.DefaultHeadlessRule) { r.ProcessName = badoption.Listable[string]{"curl"} }),
		defaultRule(func(r *option.DefaultHeadlessRule) { r.DomainSuffix = badoption.Listable[string]{"b.test"} }),
	}
	removeCurl := removeOverrides(func(r *option.DefaultHeadlessRule) { r.ProcessName = badoption.Listable[string]{"curl"} })
	require.False(t, matches(outer(load(withProcess, nil)), "other.test", "10.1.1.1"))
	require.False(t, matches(outer(load(withProcess, removeCurl)), "other.test", "10.1.1.1"))

	// A single rule stays a single merged rule: its emptied domains join the
	// outer ip_cidr and match nothing themselves.
	one := two[:1]
	original, overridden = outer(load(one, nil)), outer(load(one, removeA))
	require.True(t, matches(original, "other.test", "10.1.1.1"))
	require.True(t, matches(overridden, "other.test", "10.1.1.1"))
	require.True(t, matches(original, "a.test", "1.1.1.1"))
	require.False(t, matches(overridden, "a.test", "1.1.1.1"))
	require.NotNil(t, load(one, removeA).mergeableRule())

	// A single rule losing some values keeps the rest on the merge path.
	oneMore := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test", "c.test"}
	})}
	overridden = outer(load(oneMore, removeA))
	require.True(t, matches(overridden, "c.test", "1.1.1.1"))
	require.False(t, matches(overridden, "a.test", "1.1.1.1"))
	require.True(t, matches(overridden, "a.test", "10.1.1.1"))
}

// overrideMatcher matches like a route rule referencing the rule set, with
// or without rule_set_ip_cidr_match_source.
func overrideMatcher(t *testing.T, source []option.HeadlessRule, overrides *option.RuleSetOverrides) func(matchSource bool, domain, from, to string) bool {
	t.Helper()
	ruleSet := &LocalRuleSet{ctx: context.Background(), tag: "modes", overrides: overrides}
	require.NoError(t, ruleSet.reloadRules(source))
	return func(matchSource bool, domain, from, to string) bool {
		rule := routeRuleForTest(func(rule *abstractDefaultRule) {
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, ipCidrMatchSource: matchSource})
		})
		metadata := adapter.InboundContext{
			Network:     "tcp",
			Domain:      domain,
			Source:      M.ParseSocksaddrHostPort(from, 1000),
			Destination: M.ParseSocksaddrHostPort(to, 443),
		}
		return rule.Match(&metadata)
	}
}

// Emptied address groups match nothing, so the rule set keeps exactly the
// remaining values in both modes.
func TestApplyRuleSetOverridesAddressGroupsInBothModes(t *testing.T) {
	t.Parallel()
	telegram := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.DomainSuffix = badoption.Listable[string]{"telegram.org", "t.me"}
		r.IPCIDR = badoption.Listable[string]{"91.108.4.0/22"}
	})}
	// All of ip_cidr leaves.
	match := overrideMatcher(t, telegram, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.IPCIDR = badoption.Listable[string]{"91.108.4.0/22"}
	}))
	require.True(t, match(false, "telegram.org", "10.0.0.1", "1.2.3.4"))
	require.False(t, match(false, "", "10.0.0.1", "91.108.4.1"))
	require.False(t, match(false, "example.com", "10.0.0.1", "1.2.3.4"))
	require.False(t, match(true, "telegram.org", "91.108.4.1", "1.2.3.4"))
	require.False(t, match(true, "telegram.org", "10.0.0.1", "1.2.3.4"))

	// All of the domains leave.
	match = overrideMatcher(t, telegram, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.DomainSuffix = badoption.Listable[string]{"telegram.org", "t.me"}
	}))
	require.True(t, match(false, "", "10.0.0.1", "91.108.4.1"))
	require.False(t, match(false, "telegram.org", "10.0.0.1", "1.2.3.4"))
	require.False(t, match(true, "telegram.org", "91.108.4.1", "1.2.3.4"))
	require.False(t, match(true, "example.com", "91.108.4.1", "1.2.3.4"))

	// Before any removal, for comparison.
	match = overrideMatcher(t, telegram, nil)
	require.True(t, match(false, "telegram.org", "10.0.0.1", "1.2.3.4"))
	require.True(t, match(false, "", "10.0.0.1", "91.108.4.1"))
	require.True(t, match(true, "telegram.org", "91.108.4.1", "1.2.3.4"))
	require.False(t, match(true, "telegram.org", "10.0.0.1", "1.2.3.4"))

	// source_ip_cidr empties: nothing matches normally; under match source
	// ip_cidr still stands for the source.
	withSource := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
		r.SourceIPCIDR = badoption.Listable[string]{"192.168.1.0/24"}
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/8"}
	})}
	match = overrideMatcher(t, withSource, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.SourceIPCIDR = badoption.Listable[string]{"192.168.1.0/24"}
	}))
	require.False(t, match(false, "a.test", "192.168.1.5", "10.0.0.1"))
	require.True(t, match(true, "a.test", "10.0.0.5", "1.2.3.4"))
	require.False(t, match(true, "a.test", "192.168.1.5", "1.2.3.4"))
}

func TestApplyRuleSetOverridesKeepsInvertedRules(t *testing.T) {
	t.Parallel()
	inverted := defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test", "b.test"}
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/8"}
		r.Invert = true
	})
	rules, err := ApplyRuleSetOverrides([]option.HeadlessRule{inverted}, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
		r.IPCIDR = badoption.Listable[string]{"10.1.0.0/16"}
	}))
	require.NoError(t, err)
	require.Equal(t, []option.HeadlessRule{inverted}, rules)

	// a.test stays unmatched by the inverted rule.
	ruleSet := &LocalRuleSet{ctx: context.Background(), tag: "inverted", overrides: removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
	})}
	require.NoError(t, ruleSet.reloadRules([]option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
		r.Invert = true
	})}))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
}

// With rule_set_ip_cidr_match_source, a rule set's ip_cidr matches the
// source address and its domains still have to match: emptying the domains
// drops the rule rather than letting every domain match.
func TestApplyRuleSetOverridesIPCIDRMatchSource(t *testing.T) {
	t.Parallel()
	ruleSet := &LocalRuleSet{ctx: context.Background(), tag: "match-source"}
	source := []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/8"}
	})}
	require.NoError(t, ruleSet.reloadRules(source))
	rule := routeRuleForTest(func(rule *abstractDefaultRule) {
		addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{ruleSet}, ipCidrMatchSource: true})
	})
	// testMetadata comes from 10.0.0.1.
	matched := testMetadata("a.test")
	other := testMetadata("other.test")
	require.True(t, rule.Match(&matched))
	require.False(t, rule.Match(&other))

	ruleSet.overrides = removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
	})
	require.NoError(t, ruleSet.reloadRules(source))
	other = testMetadata("other.test")
	require.False(t, rule.Match(&other))
	matched = testMetadata("a.test")
	require.False(t, rule.Match(&matched))

	// Removing every ip_cidr drops the rule too.
	ruleSet.overrides = removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.IPCIDR = badoption.Listable[string]{"0.0.0.0/0"}
	})
	require.NoError(t, ruleSet.reloadRules(source))
	matched = testMetadata("a.test")
	require.False(t, rule.Match(&matched))
}

func TestLocalRuleSetUpdateReportsLastError(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "local.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":3,"rules":[{"domain":["a.test"]}]}`), 0o644))
	ruleSet, err := NewLocalRuleSet(context.Background(), logger.NOP(), "local", option.RuleSet{
		Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatSource, LocalOptions: option.LocalRuleSet{Path: path},
	})
	require.NoError(t, err)
	defer ruleSet.Close()
	require.NoError(t, os.WriteFile(path, []byte(`not json`), 0o644))
	require.Error(t, ruleSet.Update(context.Background()))
	require.NotEmpty(t, ruleSet.LastError())
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.NoError(t, os.WriteFile(path, []byte(`{"version":3,"rules":[{"domain":["b.test"]}]}`), 0o644))
	require.NoError(t, ruleSet.Update(context.Background()))
	require.Empty(t, ruleSet.LastError())
}

func TestApplyRuleSetOverridesKeepsLogicalRulesAndAppends(t *testing.T) {
	t.Parallel()
	logical := option.HeadlessRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalHeadlessRule{
			Mode: C.LogicalTypeOr,
			Rules: []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
				r.Domain = badoption.Listable[string]{"a.test"}
			})},
		},
	}
	added := defaultRule(func(r *option.DefaultHeadlessRule) { r.Domain = badoption.Listable[string]{"new.test"} })
	source := []option.HeadlessRule{logical, defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test", "b.test"}
	})}
	rules, err := ApplyRuleSetOverrides(source, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
	}, added))
	require.NoError(t, err)
	require.Len(t, rules, 3)
	require.Equal(t, logical, rules[0])
	require.Equal(t, []string{"b.test"}, []string(rules[1].DefaultOptions.Domain))
	require.Equal(t, added, rules[2])
	require.Len(t, source, 2)

	// Add alone keeps the source rules.
	rules, err = ApplyRuleSetOverrides(source, &option.RuleSetOverrides{Add: []option.HeadlessRule{added}})
	require.NoError(t, err)
	require.Len(t, rules, 3)
	require.Equal(t, []string{"a.test", "b.test"}, []string(rules[1].DefaultOptions.Domain))
}

func TestApplyRuleSetOverridesBinaryDomainMatcher(t *testing.T) {
	t.Parallel()
	content := binaryRuleSet(t, defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test", "b.test"}
		r.DomainSuffix = badoption.Listable[string]{"c.test"}
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/8"}
	}))
	ruleSet := &LocalRuleSet{
		ctx:        context.Background(),
		tag:        "bin",
		fileFormat: C.RuleSetFormatBinary,
		overrides: removeOverrides(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"a.test"}
			r.IPCIDR = badoption.Listable[string]{"10.1.2.3"}
		}),
	}
	path := filepath.Join(t.TempDir(), "bin.srs")
	require.NoError(t, os.WriteFile(path, content, 0o644))
	ruleSet.filePath = path
	require.NoError(t, ruleSet.reloadFile(path))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "x.c.test"}))
	requireIPs(t, ruleSet.ExtractIPSet(), "10.1.2.4", "10.1.2.3")

	// The source content keeps what the overrides remove.
	source, err := ruleSet.SourceContent(context.Background())
	require.NoError(t, err)
	require.Len(t, source.Options.Rules, 1)
	require.Equal(t, []string{"a.test", "b.test"}, []string(source.Options.Rules[0].DefaultOptions.Domain))
	require.Equal(t, []string{"10.0.0.0/8"}, []string(source.Options.Rules[0].DefaultOptions.IPCIDR))
}

func TestLocalRuleSetReappliesOverridesOnReload(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "local.json")
	write := func(domains string) {
		require.NoError(t, os.WriteFile(path, []byte(`{"version":3,"rules":[{"domain":[`+domains+`]}]}`), 0o644))
	}
	write(`"a.test","b.test"`)
	options := option.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Format:       C.RuleSetFormatSource,
		LocalOptions: option.LocalRuleSet{Path: path},
		Overrides: removeOverrides(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"a.test"}
		}, defaultRule(func(r *option.DefaultHeadlessRule) { r.Domain = badoption.Listable[string]{"added.test"} })),
	}
	ruleSet, err := NewLocalRuleSet(context.Background(), logger.NOP(), "local", options)
	require.NoError(t, err)
	defer ruleSet.Close()
	require.False(t, ruleSet.IsInline())
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))

	write(`"a.test","c.test"`)
	require.NoError(t, ruleSet.Update(context.Background()))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "c.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))

	source, err := ruleSet.SourceContent(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint8(3), source.Version)
	require.Equal(t, []string{"a.test", "c.test"}, []string(source.Options.Rules[0].DefaultOptions.Domain))

	require.NoError(t, ruleSet.ReloadOverrides(nil))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))

	// Overrides that fail to build keep the previous ones.
	bad := &option.RuleSetOverrides{Add: []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.DomainRegex = badoption.Listable[string]{"("}
	})}}
	require.ErrorContains(t, ruleSet.ReloadOverrides(bad), "overrides.add")
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.Nil(t, ruleSet.overrides)
}

func TestInlineRuleSetOverrides(t *testing.T) {
	t.Parallel()
	options := option.RuleSet{
		Type: C.RuleSetTypeInline,
		InlineOptions: option.PlainRuleSet{Rules: []option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"a.test", "b.test"}
		})}},
		Overrides: removeOverrides(func(r *option.DefaultHeadlessRule) {
			r.Domain = badoption.Listable[string]{"a.test"}
		}),
	}
	ruleSet, err := NewLocalRuleSet(context.Background(), logger.NOP(), "inline", options)
	require.NoError(t, err)
	require.True(t, ruleSet.IsInline())
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.Error(t, ruleSet.Update(context.Background()))

	source, err := ruleSet.SourceContent(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"a.test", "b.test"}, []string(source.Options.Rules[0].DefaultOptions.Domain))

	require.NoError(t, ruleSet.ReloadInline([]option.HeadlessRule{defaultRule(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test", "c.test"}
	})}, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"c.test"}
	})))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "c.test"}))
}

type overridesTestCache struct {
	adapter.CacheFile
	access sync.Mutex
	saved  map[string]*adapter.SavedBinary
}

func (c *overridesTestCache) LoadRuleSet(tag string) *adapter.SavedBinary {
	c.access.Lock()
	defer c.access.Unlock()
	if saved := c.saved[tag]; saved != nil {
		copied := *saved
		return &copied
	}
	return nil
}

func (c *overridesTestCache) SaveRuleSet(tag string, set *adapter.SavedBinary) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.saved[tag] = set
	return nil
}

type remoteTestServer struct {
	access   sync.Mutex
	content  string
	etag     string
	status   int
	requests atomic.Int32
}

func (s *remoteTestServer) set(content, etag string, status int) {
	s.access.Lock()
	defer s.access.Unlock()
	s.content, s.etag, s.status = content, etag, status
}

func (s *remoteTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	s.access.Lock()
	content, etag, status := s.content, s.etag, s.status
	s.access.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if etag != "" && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if etag != "" {
		w.Header().Set("Etag", etag)
	}
	_, _ = w.Write([]byte(content))
}

func newRemoteRuleSetWithServer(t *testing.T, server *httptest.Server, cache adapter.CacheFile, overrides *option.RuleSetOverrides) *RemoteRuleSet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ruleSet := &RemoteRuleSet{
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger.NOP(),
		tag:       "remote",
		url:       server.URL,
		options:   option.RuleSet{Type: C.RuleSetTypeRemote, Format: C.RuleSetFormatSource},
		overrides: overrides,
		cacheFile: cache,
	}
	ruleSet.updateAccess = make(chan struct{}, 1)
	ruleSet.urlHash = sha256Of(server.URL)
	ruleSet.httpClient = server.Client()
	ruleSet.IncRef()
	return ruleSet
}

func TestRemoteRuleSetReappliesOverrides(t *testing.T) {
	t.Parallel()
	upstream := &remoteTestServer{}
	upstream.set(`{"version":3,"rules":[{"domain":["a.test","b.test"]}]}`, `"v1"`, 0)
	server := httptest.NewServer(upstream)
	defer server.Close()
	cache := &overridesTestCache{saved: map[string]*adapter.SavedBinary{}}
	ruleSet := newRemoteRuleSetWithServer(t, server, cache, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
	}, defaultRule(func(r *option.DefaultHeadlessRule) { r.Domain = badoption.Listable[string]{"added.test"} })))

	// First download.
	require.NoError(t, ruleSet.Update(context.Background()))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))
	first := ruleSet.LastUpdatedAtMillis()
	require.NotZero(t, first)
	require.Contains(t, string(cache.LoadRuleSet("remote").Content), "a.test")

	// The source content is the cached download, before the overrides.
	source, err := ruleSet.SourceContent(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"a.test", "b.test"}, []string(source.Options.Rules[0].DefaultOptions.Domain))
	require.Len(t, source.Options.Rules, 1)

	// Unchanged content (304) is a successful update.
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, ruleSet.Update(context.Background()))
	require.Greater(t, ruleSet.LastUpdatedAtMillis(), first)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))

	// A failed update keeps the rules and reports the error until the next
	// successful one.
	upstream.set("", "", http.StatusInternalServerError)
	require.Error(t, ruleSet.Update(context.Background()))
	require.Contains(t, ruleSet.LastError(), "500")
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))

	// New content: the overrides apply to it.
	upstream.set(`{"version":3,"rules":[{"domain":["a.test","c.test"]}]}`, `"v2"`, 0)
	require.NoError(t, ruleSet.Update(context.Background()))
	require.Empty(t, ruleSet.LastError())
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "c.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))

	// New overrides apply to the cached content without a download.
	requests := upstream.requests.Load()
	require.NoError(t, ruleSet.ReloadOverrides(nil))
	require.Equal(t, requests, upstream.requests.Load())
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "added.test"}))
}

func TestRemoteRuleSetLoadsCacheWithOverrides(t *testing.T) {
	t.Parallel()
	upstream := &remoteTestServer{}
	upstream.set(`{"version":3,"rules":[{"domain":["x.test"]}]}`, `"v1"`, 0)
	server := httptest.NewServer(upstream)
	defer server.Close()
	cache := &overridesTestCache{saved: map[string]*adapter.SavedBinary{}}
	ruleSet := newRemoteRuleSetWithServer(t, server, cache, removeOverrides(func(r *option.DefaultHeadlessRule) {
		r.Domain = badoption.Listable[string]{"a.test"}
	}))
	cache.saved["remote"] = &adapter.SavedBinary{
		Content:     []byte(`{"version":3,"rules":[{"domain":["a.test","b.test"]}]}`),
		LastUpdated: time.Now(),
		URLHash:     ruleSet.urlHash[:],
	}
	// Restoring the cache is a load of the saved content.
	require.NoError(t, ruleSet.lock(context.Background()))
	require.NoError(t, ruleSet.loadBytes(ruleSet.savedContent()))
	ruleSet.unlock()
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "b.test"}))
	require.True(t, ruleSet.HasSavedContent())

	// Without saved content new overrides do not download: the live apply
	// restarts instead.
	ruleSet.cacheFile = nil
	require.False(t, ruleSet.HasSavedContent())
	require.Error(t, ruleSet.ReloadOverrides(nil))
	require.Zero(t, upstream.requests.Load())
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
	require.NotNil(t, ruleSet.overrides)
	_, err := ruleSet.SourceContent(context.Background())
	require.ErrorIs(t, err, os.ErrNotExist)
}

// Waiting for a running update ends with the caller's context.
func TestRemoteRuleSetWaitHonorsContext(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	ruleSet := newRemoteRuleSetWithServer(t, server, nil, nil)
	require.NoError(t, ruleSet.lock(context.Background()))
	defer ruleSet.unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	require.ErrorIs(t, ruleSet.Update(ctx), context.DeadlineExceeded)
	_, err := ruleSet.SourceContent(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second)
	require.True(t, ruleSet.lastUpdatedTime().IsZero())
}

func TestRemoteRuleSetUpdatesDoNotOverlap(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var inFlight, maxInFlight atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := inFlight.Add(1)
		for {
			previous := maxInFlight.Load()
			if current <= previous || maxInFlight.CompareAndSwap(previous, current) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain":["a.test"]}]}`))
	}))
	defer server.Close()
	ruleSet := newRemoteRuleSetWithServer(t, server, nil, nil)
	var wait sync.WaitGroup
	for range 3 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = ruleSet.Update(context.Background())
		}()
	}
	// The scheduled update skips while a manual one runs.
	require.Eventually(t, func() bool { return inFlight.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.False(t, ruleSet.updateOnce())
	close(release)
	wait.Wait()
	require.Equal(t, int32(1), maxInFlight.Load())
}

func binaryRuleSet(t *testing.T, rules ...option.HeadlessRule) []byte {
	t.Helper()
	var buffer bytes.Buffer
	require.NoError(t, srs.Write(&buffer, option.PlainRuleSet{Rules: rules}, C.RuleSetVersionCurrent))
	return buffer.Bytes()
}

func ipSetOf(t *testing.T, values []string) *netipx.IPSet {
	t.Helper()
	var builder netipx.IPSetBuilder
	for _, value := range values {
		prefix, err := option.ParseRuleSetOverridePrefix(value)
		require.NoError(t, err)
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	require.NoError(t, err)
	return set
}

func requireIPs(t *testing.T, sets []*netipx.IPSet, contained, missing string) {
	t.Helper()
	contains := func(addr string) bool {
		for _, set := range sets {
			if set.Contains(netip.MustParseAddr(addr)) {
				return true
			}
		}
		return false
	}
	require.True(t, contains(contained), contained)
	require.False(t, contains(missing), missing)
}

func TestRuleSetSourceContentMarshalsAsSource(t *testing.T) {
	t.Parallel()
	content := binaryRuleSet(t, defaultRule(func(r *option.DefaultHeadlessRule) {
		r.DomainSuffix = badoption.Listable[string]{"c.test"}
		r.IPCIDR = badoption.Listable[string]{"10.0.0.0/8"}
	}))
	compat, err := srs.Read(bytes.NewReader(content), true)
	require.NoError(t, err)
	body, err := json.Marshal(compat)
	require.NoError(t, err)
	decoded, err := json.UnmarshalExtended[option.PlainRuleSetCompat](body)
	require.NoError(t, err)
	require.Equal(t, uint8(C.RuleSetVersionCurrent), decoded.Version)
	require.Len(t, decoded.Options.Rules, 1)
	require.Equal(t, []string{"c.test"}, []string(decoded.Options.Rules[0].DefaultOptions.DomainSuffix))
	require.Equal(t, []string{"10.0.0.0/8"}, []string(decoded.Options.Rules[0].DefaultOptions.IPCIDR))
}

func sha256Of(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

// A scheduled update that finds the rule set busy runs again soon, not
// after a whole update interval.
func TestRuleSetUpdaterRetriesBusyRuleSet(t *testing.T) {
	previous := ruleSetUpdateRetry
	ruleSetUpdateRetry = 50 * time.Millisecond
	t.Cleanup(func() { ruleSetUpdateRetry = previous })
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain":["a.test"]}]}`))
	}))
	defer server.Close()
	ruleSet := newRemoteRuleSetWithServer(t, server, nil, nil)
	ruleSet.updateInterval = 24 * time.Hour
	require.NoError(t, ruleSet.lock(context.Background()))
	updater := NewRuleSetUpdater(context.Background(), []adapter.RuleSet{ruleSet})
	updater.Start()
	defer updater.Close()
	time.Sleep(20 * time.Millisecond)
	require.Zero(t, requests.Load())
	ruleSet.unlock()
	require.Eventually(t, func() bool { return ruleSet.LastUpdatedAtMillis() != 0 }, 5*time.Second, 5*time.Millisecond)
	require.Equal(t, int32(1), requests.Load())
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "a.test"}))
}
