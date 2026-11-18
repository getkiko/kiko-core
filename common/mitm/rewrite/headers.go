package rewrite

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

type headerOp struct {
	action string
	name   string
	value  string
	re     *regexp.Regexp
}

// ApplyRequest applies the matching request-scope header rules to headers.
// headers is never modified; the result is a new slice when any rule changed
// something and headers itself otherwise. hits lists the rules that changed
// something, in list order.
func (p *Plan) ApplyRequest(headers []flow.Header) ([]flow.Header, []flow.RewriteHit) {
	if p == nil {
		return headers, nil
	}
	return applyRules(p.request, ScopeRequest, headers)
}

// ApplyResponse is ApplyRequest for the response-scope rules.
func (p *Plan) ApplyResponse(headers []flow.Header) ([]flow.Header, []flow.RewriteHit) {
	if p == nil {
		return headers, nil
	}
	return applyRules(p.response, ScopeResponse, headers)
}

func applyRules(rules []*headerRule, side string, headers []flow.Header) ([]flow.Header, []flow.RewriteHit) {
	if len(rules) == 0 {
		return headers, nil
	}
	work := make([]flow.Header, len(headers), len(headers)+4)
	copy(work, headers)
	var hits []flow.RewriteHit
	for _, rule := range rules {
		var changes []flow.RewriteChange
		for i := range rule.ops {
			var change flow.RewriteChange
			var changed bool
			work, change, changed = rule.ops[i].apply(work)
			if changed {
				changes = append(changes, change)
			}
		}
		if len(changes) == 0 {
			continue
		}
		action := changes[0].Op
		for _, c := range changes[1:] {
			if c.Op != action {
				action = "edit"
				break
			}
		}
		hits = append(hits, flow.RewriteHit{Kind: KindHeader, Rule: rule.id, Action: action, Side: side, Changes: changes})
	}
	if len(hits) == 0 {
		return headers, nil
	}
	return work, hits
}

func joined(headers []flow.Header, name string) (string, bool) {
	var out string
	found := false
	for i := range headers {
		if !strings.EqualFold(headers[i].Name, name) {
			continue
		}
		if found {
			out += ", "
		}
		out += headers[i].Value
		found = true
	}
	return out, found
}

func (o *headerOp) apply(h []flow.Header) ([]flow.Header, flow.RewriteChange, bool) {
	change := flow.RewriteChange{Op: o.action, Name: o.name}
	change.Before, change.HadBefore = joined(h, o.name)
	switch o.action {
	case OpAdd:
		h = append(h, flow.Header{Name: o.name, Value: o.value})
	case OpDelete:
		if !change.HadBefore {
			return h, change, false
		}
		out := h[:0]
		for _, f := range h {
			if !strings.EqualFold(f.Name, o.name) {
				out = append(out, f)
			}
		}
		h = out
	case OpReplace:
		first, count := -1, 0
		for i := range h {
			if strings.EqualFold(h[i].Name, o.name) {
				if first < 0 {
					first = i
				}
				count++
			}
		}
		switch {
		case first < 0:
			h = append(h, flow.Header{Name: o.name, Value: o.value})
		case count == 1 && h[first].Value == o.value:
			return h, change, false
		default:
			h[first].Value = o.value
			if count > 1 {
				out := h[:first+1]
				for _, f := range h[first+1:] {
					if !strings.EqualFold(f.Name, o.name) {
						out = append(out, f)
					}
				}
				h = out
			}
		}
	case OpReplaceRegex:
		modified := false
		for i := range h {
			if !strings.EqualFold(h[i].Name, o.name) {
				continue
			}
			if v := o.re.ReplaceAllString(h[i].Value, o.value); v != h[i].Value {
				h[i].Value = v
				modified = true
			}
		}
		if !modified {
			return h, change, false
		}
	}
	change.After, change.HasAfter = joined(h, o.name)
	change.Before, change.After = clip(change.Before), clip(change.After)
	return h, change, true
}

// maxChangeValue bounds the header values a record keeps per change.
const maxChangeValue = 1 << 10

func clip(value string) string {
	if len(value) > maxChangeValue {
		return value[:maxChangeValue]
	}
	return value
}
