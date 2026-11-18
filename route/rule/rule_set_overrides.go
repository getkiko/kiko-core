package rule

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"

	"go4.org/netipx"
)

// buildRuleSetRules applies the overrides to rules loaded from a rule set's
// source and builds the matchers. Every load of the source content (inline
// rules, local files, remote downloads and caches) goes through it.
func buildRuleSetRules(ctx context.Context, tag string, sourceRules []option.HeadlessRule, overrides *option.RuleSetOverrides) ([]adapter.HeadlessRule, adapter.RuleSetMetadata, error) {
	headlessRules, err := ApplyRuleSetOverrides(sourceRules, overrides)
	if err != nil {
		return nil, adapter.RuleSetMetadata{}, err
	}
	addStart := len(headlessRules)
	if overrides != nil {
		addStart -= len(overrides.Add)
	}
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			if i >= addStart {
				return nil, adapter.RuleSetMetadata{}, E.Cause(err, "parse rule_set.overrides.add.[", i-addStart, "]")
			}
			return nil, adapter.RuleSetMetadata{}, E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := buildRuleSetMetadata(headlessRules)
	err = validateRuleSetMetadataUpdate(ctx, tag, metadata)
	if err != nil {
		return nil, adapter.RuleSetMetadata{}, err
	}
	return rules, metadata, nil
}

// ApplyRuleSetOverrides returns the rules of a rule set source with the
// overrides applied: the values of overrides.Remove leave the top-level
// default rules (ip_cidr and source_ip_cidr as address sets), an emptied
// condition group matches nothing rather than vanishing, so the rule never
// matches more than before, logical and inverted rules stay as they are, and
// overrides.Add is appended. sourceRules is not modified.
//
// Known limits: Add turning a single-rule set into several moves it off the
// merge path with the outer rule (mergeableRuleIn), so outer conditions of
// the same group no longer join it with "or". Binary rule sets decode
// domains with Dump, which folds a domain into a suffix when both are
// listed; removing that domain then finds nothing, leaving the rule as it
// was.
func ApplyRuleSetOverrides(sourceRules []option.HeadlessRule, overrides *option.RuleSetOverrides) ([]option.HeadlessRule, error) {
	if overrides.IsEmpty() {
		return sourceRules, nil
	}
	result := sourceRules
	if overrides.HasRemove() {
		remover, err := newRuleSetRemover(overrides.Remove)
		if err != nil {
			return nil, err
		}
		result = make([]option.HeadlessRule, 0, len(sourceRules)+len(overrides.Add))
		for _, rule := range sourceRules {
			// Removing values from logical or inverted rules would let them
			// match more: they stay as they are.
			if rule.Type == C.RuleTypeLogical || rule.DefaultOptions.Invert {
				result = append(result, rule)
				continue
			}
			rule.DefaultOptions = remover.apply(rule.DefaultOptions)
			result = append(result, rule)
		}
	}
	if len(overrides.Add) > 0 {
		result = append(result[:len(result):len(result)], overrides.Add...)
	}
	return result, nil
}

type ruleSetRemover struct {
	domain        map[string]bool
	domainSuffix  map[string]bool
	domainKeyword map[string]bool
	domainRegex   map[string]bool
	processName   map[string]bool
	processPath   map[string]bool
	packageName   map[string]bool
	ipCIDR        *netipx.IPSet
	sourceIPCIDR  *netipx.IPSet
}

func newRuleSetRemover(remove *option.DefaultHeadlessRule) (*ruleSetRemover, error) {
	ipCIDR, err := overrideIPSet(remove.IPCIDR)
	if err != nil {
		return nil, E.Cause(err, "overrides.remove.ip_cidr")
	}
	sourceIPCIDR, err := overrideIPSet(remove.SourceIPCIDR)
	if err != nil {
		return nil, E.Cause(err, "overrides.remove.source_ip_cidr")
	}
	return &ruleSetRemover{
		domain:        stringSet(remove.Domain),
		domainSuffix:  stringSet(remove.DomainSuffix),
		domainKeyword: stringSet(remove.DomainKeyword),
		domainRegex:   stringSet(remove.DomainRegex),
		processName:   stringSet(remove.ProcessName),
		processPath:   stringSet(remove.ProcessPath),
		packageName:   stringSet(remove.PackageName),
		ipCIDR:        ipCIDR,
		sourceIPCIDR:  sourceIPCIDR,
	}, nil
}

func stringSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func overrideIPSet(values []string) (*netipx.IPSet, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var builder netipx.IPSetBuilder
	for _, value := range values {
		prefix, err := option.ParseRuleSetOverridePrefix(value)
		if err != nil {
			return nil, err
		}
		builder.AddPrefix(prefix)
	}
	return builder.IPSet()
}

// filterStrings drops the values in remove, keeping the original slice when
// nothing matches.
func filterStrings(values []string, remove map[string]bool) ([]string, bool) {
	if len(remove) == 0 || len(values) == 0 {
		return values, false
	}
	var result []string
	changed := false
	for i, value := range values {
		if remove[value] {
			if !changed {
				result = append(make([]string, 0, len(values)-1), values[:i]...)
				changed = true
			}
			continue
		}
		if changed {
			result = append(result, value)
		}
	}
	if !changed {
		return values, false
	}
	return result, true
}

func (r *ruleSetRemover) apply(rule option.DefaultHeadlessRule) option.DefaultHeadlessRule {
	before := ruleConditionGroups(rule)

	if len(r.domain) > 0 || len(r.domainSuffix) > 0 {
		domains, domainSuffixes := rule.Domain, rule.DomainSuffix
		fromMatcher := len(domains) == 0 && len(domainSuffixes) == 0 && rule.DomainMatcher != nil
		if fromMatcher {
			domains, domainSuffixes = rule.DomainMatcher.Dump()
		}
		var domainChanged, suffixChanged bool
		domains, domainChanged = filterStrings(domains, r.domain)
		domainSuffixes, suffixChanged = filterStrings(domainSuffixes, r.domainSuffix)
		if domainChanged || suffixChanged {
			rule.Domain, rule.DomainSuffix = domains, domainSuffixes
			rule.DomainMatcher = nil
		}
	}
	rule.DomainKeyword, _ = filterStrings(rule.DomainKeyword, r.domainKeyword)
	rule.DomainRegex, _ = filterStrings(rule.DomainRegex, r.domainRegex)
	rule.ProcessName, _ = filterStrings(rule.ProcessName, r.processName)
	rule.ProcessPath, _ = filterStrings(rule.ProcessPath, r.processPath)
	rule.PackageName, _ = filterStrings(rule.PackageName, r.packageName)
	rule.IPCIDR, rule.IPSet = subtractRuleIPs(rule.IPCIDR, rule.IPSet, r.ipCIDR)
	rule.SourceIPCIDR, rule.SourceIPSet = subtractRuleIPs(rule.SourceIPCIDR, rule.SourceIPSet, r.sourceIPCIDR)

	// A condition group emptied by remove keeps a value that matches
	// nothing, rather than the rule going or the group vanishing: the rule
	// set keeps its rule count, so a single rule set stays on the same
	// merge path with the outer rule (mergeableRuleIn), and each group
	// still has to match, which is exactly what the remaining values do
	// with and without rule_set_ip_cidr_match_source.
	after := ruleConditionGroups(rule)
	emptied := func(group int) bool { return before[group] && !after[group] }
	if emptied(groupDomain) {
		rule.DomainRegex = badoption.Listable[string]{noDomainRegex}
	}
	if emptied(groupIPCIDR) {
		rule.IPCIDR, rule.IPSet = nil, new(netipx.IPSet)
	}
	if emptied(groupSourceIPCIDR) {
		rule.SourceIPCIDR, rule.SourceIPSet = nil, new(netipx.IPSet)
	}
	// The process items take part in every rule with "and"; the same item
	// with an impossible value keeps the rule set's metadata.
	if emptied(groupProcessName) {
		rule.ProcessName = badoption.Listable[string]{noProcessValue}
	}
	if emptied(groupProcessPath) {
		rule.ProcessPath = badoption.Listable[string]{noProcessValue}
	}
	if emptied(groupPackageName) {
		rule.PackageName = badoption.Listable[string]{noProcessValue}
	}
	return rule
}

// noProcessValue is no process name, path or package name: none holds a
// NUL byte.
const noProcessValue = "\x00"

// noDomainRegex matches no domain; it holds the place of emptied domains,
// as an empty domain matcher cannot be built.
const noDomainRegex = `[^\s\S]`

// subtractRuleIPs removes the addresses in remove from a rule's ip_cidr
// list, or from its decoded address set when the list is empty (binary rule
// sets). Prefixes that cover a removed address are split.
func subtractRuleIPs(list []string, set *netipx.IPSet, remove *netipx.IPSet) ([]string, *netipx.IPSet) {
	if remove == nil {
		return list, set
	}
	if len(list) > 0 {
		var builder netipx.IPSetBuilder
		for _, value := range list {
			prefix, err := option.ParseRuleSetOverridePrefix(value)
			if err != nil {
				// NewHeadlessRule reports the invalid value.
				return list, set
			}
			builder.AddPrefix(prefix)
		}
		original, err := builder.IPSet()
		if err != nil || !original.Overlaps(remove) {
			return list, set
		}
		builder.RemoveSet(remove)
		remaining, err := builder.IPSet()
		if err != nil {
			return list, set
		}
		return common.Map(remaining.Prefixes(), netip.Prefix.String), nil
	}
	if set == nil || !set.Overlaps(remove) {
		return list, set
	}
	var builder netipx.IPSetBuilder
	builder.AddSet(set)
	builder.RemoveSet(remove)
	remaining, err := builder.IPSet()
	if err != nil {
		return list, set
	}
	if len(remaining.Prefixes()) == 0 {
		return nil, nil
	}
	return nil, remaining
}

const (
	groupDomain = iota
	groupIPCIDR
	groupSourceIPCIDR
	groupProcessName
	groupProcessPath
	groupPackageName
)

// ruleConditionGroups reports which condition groups of a rule hold
// values, indexed by the group constants. Every group present must match;
// ip_cidr joins the domains, or the source addresses under
// rule_set_ip_cidr_match_source.
func ruleConditionGroups(rule option.DefaultHeadlessRule) [6]bool {
	return [6]bool{
		groupDomain: len(rule.Domain) > 0 || len(rule.DomainSuffix) > 0 || rule.DomainMatcher != nil ||
			len(rule.DomainKeyword) > 0 || len(rule.DomainRegex) > 0 ||
			len(rule.AdGuardDomain) > 0 || rule.AdGuardDomainMatcher != nil,
		groupIPCIDR:       len(rule.IPCIDR) > 0 || rule.IPSet != nil,
		groupSourceIPCIDR: len(rule.SourceIPCIDR) > 0 || rule.SourceIPSet != nil,
		groupProcessName:  len(rule.ProcessName) > 0,
		groupProcessPath:  len(rule.ProcessPath) > 0,
		groupPackageName:  len(rule.PackageName) > 0,
	}
}
