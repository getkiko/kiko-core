package dns

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

func scriptLeaf(invert bool) option.DNSRule {
	var d option.DefaultDNSRule
	d.Script = []string{"s"}
	d.Invert = invert
	return option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: d}
}

func domainLeaf(invert bool) option.DNSRule {
	var d option.DefaultDNSRule
	d.Domain = []string{"a.example"}
	d.Invert = invert
	return option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: d}
}

func logicalDNS(invert bool, subs ...option.DNSRule) option.DNSRule {
	var l option.LogicalDNSRule
	l.Mode = C.LogicalTypeAnd
	l.Invert = invert
	l.Rules = subs
	l.Action = C.RuleActionTypeReject
	return option.DNSRule{Type: C.RuleTypeLogical, LogicalOptions: l}
}

func TestInvertedScriptConditionRejectedDNS(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("dns")
	build := func(rule option.DNSRule) error {
		_, err := R.NewDNSRule(context.Background(), logger, rule, false, false)
		return err
	}
	require.ErrorContains(t, build(scriptLeaf(true)), "invert")
	require.NoError(t, build(scriptLeaf(false)))
	require.NoError(t, build(logicalDNS(true, domainLeaf(false))))
	require.NoError(t, build(logicalDNS(false, scriptLeaf(false), domainLeaf(false))))
	// A script leaf anywhere under an inverted logical rule.
	require.ErrorContains(t, build(logicalDNS(true, domainLeaf(false), scriptLeaf(false))), "invert")
	inner := logicalDNS(false, domainLeaf(false), scriptLeaf(false))
	require.ErrorContains(t, build(logicalDNS(true, inner)), "invert")
	// An inverted sub-rule that holds the script.
	require.ErrorContains(t, build(logicalDNS(false, scriptLeaf(true))), "invert")
}

func TestInvertedScriptConditionRejectedRoute(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("router")
	var leaf option.DefaultRule
	leaf.Script = []string{"s"}
	leaf.Invert = true
	leaf.Action = C.RuleActionTypeReject
	_, err := R.NewRule(context.Background(), logger, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: leaf}, false)
	require.ErrorContains(t, err, "invert")

	var sub option.DefaultRule
	sub.Script = []string{"s"}
	var l option.LogicalRule
	l.Mode = C.LogicalTypeOr
	l.Invert = true
	l.Rules = []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: sub}}
	l.Action = C.RuleActionTypeReject
	_, err = R.NewRule(context.Background(), logger, option.Rule{Type: C.RuleTypeLogical, LogicalOptions: l}, false)
	require.ErrorContains(t, err, "invert")
}
