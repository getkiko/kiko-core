package rule

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// A script condition has no "false because the input does not match" answer: an error, a
// timeout, a tripped breaker, a missing script, a dry run and a pre-match all evaluate to false.
// Under `invert` those would turn into matches, so a script condition is refused anywhere below
// an inverted rule.
var errInvertScript = E.New("`invert` cannot be combined with a `script` condition")

func validateInvertScript(rule option.Rule) error {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if rule.DefaultOptions.Invert && len(rule.DefaultOptions.Script) > 0 {
			return errInvertScript
		}
	case C.RuleTypeLogical:
		if rule.LogicalOptions.Invert && ruleHasScript(rule) {
			return errInvertScript
		}
	}
	return nil
}

func ruleHasScript(rule option.Rule) bool {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return len(rule.DefaultOptions.Script) > 0
	case C.RuleTypeLogical:
		for _, sub := range rule.LogicalOptions.Rules {
			if ruleHasScript(sub) {
				return true
			}
		}
	}
	return false
}

func validateInvertScriptDNS(rule option.DNSRule) error {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		if rule.DefaultOptions.Invert && len(rule.DefaultOptions.Script) > 0 {
			return errInvertScript
		}
	case C.RuleTypeLogical:
		if rule.LogicalOptions.Invert && dnsRuleHasScript(rule) {
			return errInvertScript
		}
	}
	return nil
}

func dnsRuleHasScript(rule option.DNSRule) bool {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return len(rule.DefaultOptions.Script) > 0
	case C.RuleTypeLogical:
		for _, sub := range rule.LogicalOptions.Rules {
			if dnsRuleHasScript(sub) {
				return true
			}
		}
	}
	return false
}
