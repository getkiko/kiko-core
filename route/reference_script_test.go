package route

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestDNSRulesUseScript(t *testing.T) {
	var plain, scripted option.DefaultDNSRule
	plain.Action = C.RuleActionTypeReject
	scripted.Action = C.RuleActionTypeScript
	var logical option.LogicalDNSRule
	logical.Action = C.RuleActionTypeScript
	if dnsRulesUseScript(nil) {
		t.Fatal("no rules")
	}
	if dnsRulesUseScript([]option.DNSRule{{Type: C.RuleTypeDefault, DefaultOptions: plain}}) {
		t.Fatal("reject rule is not a script")
	}
	if !dnsRulesUseScript([]option.DNSRule{{Type: C.RuleTypeDefault, DefaultOptions: plain}, {Type: C.RuleTypeDefault, DefaultOptions: scripted}}) {
		t.Fatal("default script rule")
	}
	if !dnsRulesUseScript([]option.DNSRule{{Type: C.RuleTypeLogical, LogicalOptions: logical}}) {
		t.Fatal("logical script rule")
	}
}
