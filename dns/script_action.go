package dns

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-box/script"
)

// scriptResolvedRule is a DNS rule whose `script` action has been decided: it behaves as the
// rule did, but reports the action the script chose (predefined, route, reject or a no-op),
// so the rest of the router sees only the actions it already handles.
type scriptResolvedRule struct {
	adapter.DNSRule
	action adapter.RuleAction
}

func (s *scriptResolvedRule) Action() adapter.RuleAction { return s.action }

// resolveScriptAction runs the dns script when rule's action is `script` and returns the rule
// to continue with; any other rule is returned as it is, at the cost of one type assertion.
func (r *Router) resolveScriptAction(ctx context.Context, rule adapter.DNSRule, metadata *adapter.InboundContext) adapter.DNSRule {
	action, isScript := rule.Action().(*R.RuleActionDNSScript)
	if !isScript {
		return rule
	}
	return &scriptResolvedRule{DNSRule: rule, action: r.runScriptAction(ctx, action, metadata)}
}

func (r *Router) runScriptAction(ctx context.Context, action *R.RuleActionDNSScript, metadata *adapter.InboundContext) adapter.RuleAction {
	pass := &R.RuleActionDNSRouteOptions{}
	if dry := metadata.ScriptDryRun; dry != nil {
		dry.Add(action.Script)
		dnsmonitor.Script(ctx, dnsmonitor.ScriptRun{Tag: action.Script, Outcome: "maybe"})
		return pass
	}
	failed := func(reason string, cached bool, took time.Duration) adapter.RuleAction {
		outcome := "error"
		var result adapter.RuleAction = pass
		if action.RejectOnError() {
			outcome = "reject"
			result = &R.RuleActionReject{Method: "default"}
		}
		if !cached {
			r.logger.WarnContext(ctx, "dns script ", action.Script, ": ", reason)
		}
		dnsmonitor.Script(ctx, dnsmonitor.ScriptRun{Tag: action.Script, Outcome: outcome, Detail: reason, Cached: cached, DurationMS: millis(took)})
		return result
	}
	manager := R.ScriptManager(r.ctx)
	if manager == nil {
		return failed("script runtime unavailable", false, 0)
	}
	outcome := manager.RunDNS(action.Script, R.ScriptInput(metadata))
	if outcome.Err != "" {
		return failed(outcome.Err, outcome.Cached, outcome.Duration)
	}
	decision := outcome.Decision
	run := dnsmonitor.ScriptRun{Tag: action.Script, Outcome: string(decision.Kind), Cached: outcome.Cached, DurationMS: millis(outcome.Duration)}
	switch decision.Kind {
	case script.DNSServer:
		run.Detail = decision.Server
		dnsmonitor.Script(ctx, run)
		return &R.RuleActionDNSRoute{Server: decision.Server}
	case script.DNSAnswer:
		run.Detail = decision.Summary()
		dnsmonitor.Script(ctx, run)
		return scriptAnswer(decision, metadata.ScriptQuestionType())
	}
	dnsmonitor.Script(ctx, run)
	return pass
}

// scriptAnswer builds the predefined answer for a decision. Addresses answer A and AAAA
// questions with the records of their family (ANY, and 0 for a legacy lookup of both families, get both); any other question type gets an
// empty answer. The record owner "*" takes the name of the question.
func scriptAnswer(decision script.DNSDecision, qType uint16) *R.RuleActionPredefined {
	answer := &R.RuleActionPredefined{Rcode: decision.Rcode}
	for _, addr := range decision.Addresses {
		header := dns.RR_Header{Name: "*", Class: dns.ClassINET, Ttl: decision.TTL}
		switch {
		case addr.Is4() && (qType == 0 || qType == dns.TypeA || qType == dns.TypeANY):
			header.Rrtype = dns.TypeA
			answer.Answer = append(answer.Answer, &dns.A{Hdr: header, A: addr.AsSlice()})
		case addr.Is6() && (qType == 0 || qType == dns.TypeAAAA || qType == dns.TypeANY):
			header.Rrtype = dns.TypeAAAA
			answer.Answer = append(answer.Answer, &dns.AAAA{Hdr: header, AAAA: addr.AsSlice()})
		}
	}
	return answer
}

func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
