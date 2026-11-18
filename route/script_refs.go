package route

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// ValidateScriptReferences checks that the `script` conditions of route and DNS rules name
// rule scripts, and the `script` actions of DNS rules dns scripts, of the top-level scripts.
// A disabled script is a valid reference: it is not compiled and its condition never holds.
func ValidateScriptReferences(scripts []option.ScriptOptions, route option.RouteOptions, dns option.DNSOptions) error {
	types := make(map[string]string, len(scripts))
	for _, s := range scripts {
		types[s.Tag] = s.Type
	}
	check := func(tag, want, where string) error {
		got, found := types[tag]
		if !found {
			return E.New(where, ": script not found: ", tag)
		}
		if got != want {
			return E.New(where, ": script ", tag, " is a ", got, " script, not a ", want, " script")
		}
		return nil
	}
	var walkRules func(rules []option.Rule, where string) error
	walkRules = func(rules []option.Rule, where string) error {
		for i, rule := range rules {
			at := F.ToString(where, "[", i, "]")
			switch rule.Type {
			case C.RuleTypeDefault:
				for _, tag := range rule.DefaultOptions.Script {
					if err := check(tag, option.ScriptTypeRule, at); err != nil {
						return err
					}
				}
			case C.RuleTypeLogical:
				if err := walkRules(rule.LogicalOptions.Rules, at+" sub rule"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	var walkDNS func(rules []option.DNSRule, where string) error
	walkDNS = func(rules []option.DNSRule, where string) error {
		for i, rule := range rules {
			at := F.ToString(where, "[", i, "]")
			switch rule.Type {
			case "", C.RuleTypeDefault:
				for _, tag := range rule.DefaultOptions.Script {
					if err := check(tag, option.ScriptTypeRule, at); err != nil {
						return err
					}
				}
				if rule.DefaultOptions.Action == C.RuleActionTypeScript {
					if err := check(rule.DefaultOptions.ScriptOptions.Script, option.ScriptTypeDNS, at); err != nil {
						return err
					}
				}
			case C.RuleTypeLogical:
				if rule.LogicalOptions.Action == C.RuleActionTypeScript {
					if err := check(rule.LogicalOptions.ScriptOptions.Script, option.ScriptTypeDNS, at); err != nil {
						return err
					}
				}
				if err := walkDNS(rule.LogicalOptions.Rules, at+" sub rule"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walkRules(route.Rules, "route rule"); err != nil {
		return err
	}
	return walkDNS(dns.Rules, "dns rule")
}
