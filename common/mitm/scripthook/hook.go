// Package scripthook runs the http-request and http-response scripts of an exchange. The h1
// and h2 engines share it: they hand over the message (headers, the body collected with
// rewrite.Plan.HoldFor, the status) and apply the Outcome to the message.
package scripthook

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/script"
)

var counter atomic.Uint64

var epoch = strconv.FormatInt(time.Now().UnixNano()&0xffffffff, 36)

// Exchange follows the scripts of one request. A nil *Exchange has no scripts: every method
// is safe on it.
type Exchange struct {
	mgr       *script.Manager
	rw        *rewrite.Set
	ctx       context.Context
	scheme    string
	authority string
	method    string
	id        string
	// URL is the URL scripts see: scheme://authority+target.
	URL        string
	req        []*script.Script
	resp       []*script.Script
	reqHeaders []script.Header
}

// Begin matches the scripts against the request. url parts are those of the request after
// the URL rewrite rules. It returns nil when no http script matches the request or its
// response, or mgr is nil.
func Begin(ctx context.Context, mgr *script.Manager, rw *rewrite.Set, scheme, authority, target, method string) *Exchange {
	if mgr == nil {
		return nil
	}
	set := mgr.Current()
	if !set.HasHTTP() {
		return nil
	}
	url := scheme + "://" + authority + target
	req := set.Match(script.PhaseRequest, url)
	resp := set.Match(script.PhaseResponse, url)
	if len(req) == 0 && len(resp) == 0 {
		return nil
	}
	return &Exchange{
		mgr: mgr, rw: rw, ctx: ctx, scheme: scheme, authority: authority, method: method, URL: url,
		req: req, resp: resp,
		id: epoch + "-" + strconv.FormatUint(counter.Add(1), 36),
	}
}

// HasRequest reports whether http-request scripts match.
func (x *Exchange) HasRequest() bool { return x != nil && len(x.req) > 0 }

// HasResponse reports whether http-response scripts match.
func (x *Exchange) HasResponse() bool { return x != nil && len(x.resp) > 0 }

// WantsBody reports whether a matching script of the phase needs the body of a message that
// has one (hasBody).
func (x *Exchange) WantsBody(phase script.Phase, hasBody bool) bool {
	if x == nil || !hasBody {
		return false
	}
	for _, sc := range x.list(phase) {
		if sc.RequiresBody() {
			return true
		}
	}
	return false
}

// MaxBody is the largest buffer the matching body scripts of the phase ask for.
func (x *Exchange) MaxBody(phase script.Phase) int64 {
	var n int64
	if x == nil {
		return n
	}
	for _, sc := range x.list(phase) {
		if sc.RequiresBody() {
			n = max(n, sc.MaxSize())
		}
	}
	return n
}

func (x *Exchange) list(phase script.Phase) []*script.Script {
	if phase == script.PhaseResponse {
		return x.resp
	}
	return x.req
}

// Message is a message handed to the scripts of a phase.
type Message struct {
	// Headers are the fields in wire order.
	Headers []flow.Header
	// Status is the response status (response phase).
	Status int
	// Held is the body as collected, nil when none was collected.
	Held *rewrite.Held
	// Encoding is the Content-Encoding of the body as received ("" for none).
	Encoding string
	// HasBody reports that the message has a body (by its framing).
	HasBody bool
	// Limit is the buffer cap the body was collected with.
	Limit int64
	// Head reports a HEAD request's response: the status may not turn into one with a body.
	Head bool
}

// Outcome is what the scripts of a phase did to a message. The zero value changes nothing.
type Outcome struct {
	// Local, when set, answers the exchange (a script response, or an abort); Hits holds the
	// records of the other scripts and Local.Hit the record of the script that answered.
	Local *rewrite.LocalResponse
	// Headers is the new field list when HeadersChanged.
	Headers        []flow.Header
	HeadersChanged bool
	// Status is the new response status, 0 when unchanged.
	Status int
	// Internal is the new destination of a request (a script returned another URL).
	Internal *rewrite.Internal
	// Body is the new body in the encoding the message has, when BodyChanged.
	Body        []byte
	BodyChanged bool
	// Hits are the records of every script that ran or was skipped.
	Hits []flow.RewriteHit
}

// RunRequest runs the http-request scripts.
func (x *Exchange) RunRequest(m *Message, target string) *Outcome {
	out := x.run(script.PhaseRequest, x.req, m, target)
	if out.HeadersChanged {
		x.reqHeaders = toScript(out.Headers)
	} else {
		x.reqHeaders = toScript(m.Headers)
	}
	return out
}

// SetRequestHeaders records the request headers as they go upstream; response scripts see
// them as $request.headers.
func (x *Exchange) SetRequestHeaders(headers []flow.Header) {
	if x != nil {
		x.reqHeaders = toScript(headers)
	}
}

// SetURL records the URL of the request after the scripts (for response scripts).
func (x *Exchange) SetURL(url string) {
	if x == nil {
		return
	}
	x.URL = url
	x.resp = x.mgr.Current().Match(script.PhaseResponse, url)
}

// RunResponse runs the http-response scripts.
func (x *Exchange) RunResponse(m *Message) *Outcome {
	return x.run(script.PhaseResponse, x.resp, m, "")
}

func toScript(h []flow.Header) []script.Header {
	out := make([]script.Header, len(h))
	for i := range h {
		out[i] = script.Header{Name: h[i].Name, Value: h[i].Value}
	}
	return out
}

func fromScript(h []script.Header) []flow.Header {
	out := make([]flow.Header, len(h))
	for i := range h {
		out[i] = flow.Header{Name: h[i].Name, Value: h[i].Value}
	}
	return out
}

// run is the chain of one phase: scripts run in order, each seeing the result of the
// previous one.
func (x *Exchange) run(phase script.Phase, scripts []*script.Script, m *Message, target string) *Outcome {
	out := &Outcome{}
	headers := m.Headers
	url := x.URL
	status := m.Status
	side := "request"
	if phase == script.PhaseResponse {
		side = "response"
	}
	var (
		plain      []byte
		plainState int // 0 not decoded, 1 ready, 2 failed
		plainWhy   string
		bodyOwner  string // tag of the last script that changed the body
	)
	decode := func() bool {
		switch plainState {
		case 1:
			return true
		case 2:
			return false
		}
		held := m.Held
		switch {
		case !m.HasBody:
			plainState, plainWhy = 2, rewrite.SkipStream
		case held == nil:
			plainState, plainWhy = 2, rewrite.SkipStream
		case held.Reason != "":
			plainState, plainWhy = 2, held.Reason
		case !held.Complete:
			plainState, plainWhy = 2, rewrite.SkipSize
		case len(body.ParseEncodings(m.Encoding)) == 0:
			plain, plainState = held.Data, 1
		default:
			decoded, err := body.Decode(m.Encoding, bytes.NewReader(held.Data), body.Limits{MaxOutput: max(m.Limit, rewrite.DefaultMaxBodySize)})
			if err != nil {
				plainState, plainWhy = 2, rewrite.SkipDecode
				if e, ok := err.(*body.Error); ok {
					switch e.Kind {
					case body.ErrUnsupported:
						plainWhy = rewrite.SkipEncoding
					case body.ErrOutputLimit, body.ErrBomb:
						plainWhy = rewrite.SkipDecodedSize
					}
				}
			} else {
				plain, plainState = decoded, 1
			}
		}
		return plainState == 1
	}
	bodyChanged := false
	for _, sc := range scripts {
		cfg := sc.Config()
		tag := cfg.Tag
		hit := flow.RewriteHit{Kind: rewrite.KindScript, Rule: tag, Side: side, Target: tag}
		skip := func(reason string) {
			hit.Action = string(script.ActionSkipped)
			hit.Run = &flow.ScriptRun{Phase: string(phase), Reason: reason}
			hit.Changes = []flow.RewriteChange{{Op: "skipped", Name: "reason", After: reason, HasAfter: true}}
			out.Hits = append(out.Hits, hit)
		}
		in := &script.Input{}
		wantBody := cfg.RequiresBody && m.HasBody
		if cfg.RequiresBody && !m.HasBody {
			// Nothing to hand over (no body, a 204 or 304, a HEAD answer): a script that
			// expects one is not run, so it cannot fail on every message.
			skip(rewrite.SkipStream)
			continue
		}
		if wantBody {
			if !decode() {
				skip(plainWhy)
				continue
			}
			if int64(len(plain)) > cfg.MaxSize {
				skip(rewrite.SkipSize)
				continue
			}
		}
		request := &script.Request{URL: url, Method: x.method, ID: x.id}
		if phase == script.PhaseRequest {
			request.Headers = toScript(headers)
			if wantBody {
				request.Body, request.HasBody = plain, true
			}
		} else {
			request.Headers = x.reqHeaders
			resp := &script.Response{Status: status, Headers: toScript(headers)}
			if wantBody {
				resp.Body, resp.HasBody = plain, true
			}
			in.Response = resp
		}
		in.Request = request
		res := x.mgr.Run(x.ctx, sc, in)
		hit.Action = string(res.Action)
		hit.Run = &flow.ScriptRun{Phase: string(phase), Duration: res.Duration, Error: res.Error, Reason: res.Reason, Logs: logs(res.Logs)}
		switch res.Action {
		case script.ActionError, script.ActionTimeout, script.ActionLimit, script.ActionPaused, script.ActionSkipped:
			out.Hits = append(out.Hits, hit)
			continue
		case script.ActionAbort:
			out.Local = rewrite.NewAbort(hit)
			return finish(out, headers, status, bodyChanged, plain, m, bodyOwner, x)
		case script.ActionRespond:
			local, why := x.respond(&hit, res.Response, m.Head)
			if why != "" {
				fail(&hit, why)
				out.Hits = append(out.Hits, hit)
				continue
			}
			out.Local = local
			return finish(out, headers, status, bodyChanged, plain, m, bodyOwner, x)
		}
		// modify or none: validate everything first, apply only if all of it is acceptable.
		next := struct {
			headers []flow.Header
			status  int
			url     string
			in      *rewrite.Internal
			body    []byte
		}{headers: headers, status: status, url: url}
		var changes []flow.RewriteChange
		if res.HeadersChanged {
			updated, why := sanitize(headers, res.Headers)
			if why != "" {
				fail(&hit, why)
				out.Hits = append(out.Hits, hit)
				continue
			}
			changes = append(changes, headerChanges(headers, updated)...)
			next.headers = updated
		}
		if res.Status != 0 {
			if why := statusProblem(status, res.Status, m.Head); why != "" {
				changes = append(changes, flow.RewriteChange{Op: "status", Name: "status", Before: strconv.Itoa(status), HadBefore: true, After: strconv.Itoa(res.Status) + " (ignored: " + why + ")", HasAfter: true})
			} else {
				changes = append(changes, flow.RewriteChange{Op: "status", Name: "status", Before: strconv.Itoa(status), HadBefore: true, After: strconv.Itoa(res.Status), HasAfter: true})
				next.status = res.Status
			}
		}
		if res.URL != "" && res.URL != url {
			if phase != script.PhaseRequest {
				changes = append(changes, flow.RewriteChange{Op: "url", Name: "url", After: "ignored: response scripts cannot change the URL", HasAfter: true})
			} else {
				in, err := x.rw.ScriptInternal(res.URL, target)
				if err != nil {
					fail(&hit, "url: "+err.Error())
					out.Hits = append(out.Hits, hit)
					continue
				}
				changes = append(changes, flow.RewriteChange{Op: "url", Name: "url", Before: url, HadBefore: true, After: in.URL, HasAfter: true})
				next.in, next.url = in, in.URL
			}
		}
		if res.BodyChanged && !m.HasBody {
			// There is no body to replace: the message was framed without one.
			res.BodyChanged = false
		}
		if res.BodyChanged {
			if int64(len(res.Body)) > 2*max(m.Limit, cfg.MaxSize) {
				fail(&hit, "body larger than the limit")
				hit.Action = string(script.ActionLimit)
				out.Hits = append(out.Hits, hit)
				continue
			}
			changes = append(changes, flow.RewriteChange{Op: "body", Name: "body", Before: strconv.Itoa(len(plain)), HadBefore: true, After: strconv.Itoa(len(res.Body)), HasAfter: true})
			next.body = res.Body
		}
		headers, status = next.headers, next.status
		if next.in != nil {
			url = next.url
			out.Internal = next.in
			target = next.in.Target
		}
		if res.BodyChanged {
			plain, bodyChanged, bodyOwner = next.body, true, tag
		}
		if len(changes) == 0 {
			hit.Action = string(script.ActionNone)
		} else {
			hit.Action = string(script.ActionModify)
			hit.Changes = changes
		}
		out.Hits = append(out.Hits, hit)
	}
	return finish(out, headers, status, bodyChanged, plain, m, bodyOwner, x)
}

// finish fills the outcome from the final state.
func finish(out *Outcome, headers []flow.Header, status int, bodyChanged bool, plain []byte, m *Message, bodyOwner string, x *Exchange) *Outcome {
	if !sameHeaders(headers, m.Headers) {
		out.Headers, out.HeadersChanged = headers, true
	}
	if status != m.Status {
		out.Status = status
	}
	if out.Internal != nil {
		x.SetURL(out.Internal.URL)
	}
	if bodyChanged && out.Local == nil {
		data := plain
		if len(body.ParseEncodings(m.Encoding)) > 0 {
			encoded, err := body.Encode(m.Encoding, plain)
			if err != nil {
				// The edited body cannot be put back in the original coding: it is dropped.
				for i := range out.Hits {
					if out.Hits[i].Rule == bodyOwner && out.Hits[i].Action == string(script.ActionModify) {
						out.Hits[i].Action = string(script.ActionSkipped)
						out.Hits[i].Run.Reason = rewrite.SkipEncoding
						out.Hits[i].Changes = append(out.Hits[i].Changes, flow.RewriteChange{Op: "skipped", Name: "reason", After: rewrite.SkipEncoding, HasAfter: true})
					}
				}
				return out
			}
			data = encoded
		}
		out.Body, out.BodyChanged = data, true
	}
	return out
}

func sameHeaders(a, b []flow.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fail(hit *flow.RewriteHit, why string) {
	hit.Action = string(script.ActionError)
	hit.Run.Error = why
}

func logs(lines []script.LogLine) []flow.ScriptLog {
	if len(lines) == 0 {
		return nil
	}
	out := make([]flow.ScriptLog, len(lines))
	for i, l := range lines {
		out[i] = flow.ScriptLog{Level: l.Level, Message: l.Message}
	}
	return out
}

// bodyless reports statuses that never carry a body.
func bodyless(status int) bool {
	return status < 200 || status == 204 || status == 205 || status == 304
}

func statusProblem(old, next int, head bool) string {
	if next < 200 {
		return "informational status"
	}
	if bodyless(old) != bodyless(next) && !head {
		return "status would change whether the message has a body"
	}
	return ""
}

// sanitize checks the field list a script produced. Fields the proxy manages (framing,
// connection) keep their original values whatever the script did.
func sanitize(orig []flow.Header, updated []script.Header) ([]flow.Header, string) {
	var reserved []flow.Header
	for _, h := range orig {
		if scriptReserved(h.Name) {
			reserved = append(reserved, h)
		}
	}
	out := make([]flow.Header, 0, len(updated)+len(reserved))
	next := 0
	for _, h := range updated {
		if scriptReserved(h.Name) {
			if next < len(reserved) {
				out = append(out, reserved[next])
				next++
			}
			continue
		}
		if issue := rewrite.HeaderIssue(h.Name, h.Value); issue != "" {
			return nil, issue
		}
		out = append(out, flow.Header{Name: h.Name, Value: h.Value})
	}
	out = append(out, reserved[next:]...)
	return out, ""
}

// scriptReserved reports the headers a script cannot change: the framing and connection fields,
// and Content-Encoding, which has to keep describing the body the engine holds.
func scriptReserved(name string) bool {
	return rewrite.ReservedHeader(name) || strings.EqualFold(name, "Content-Encoding")
}

const maxChanges = 32

func headerChanges(before, after []flow.Header) []flow.RewriteChange {
	type entry struct {
		name  string
		value string
		seen  bool
	}
	join := func(list []flow.Header) (map[string]*entry, []string) {
		m := map[string]*entry{}
		var order []string
		for _, h := range list {
			k := strings.ToLower(h.Name)
			if e, ok := m[k]; ok {
				e.value += ", " + h.Value
				continue
			}
			m[k] = &entry{name: h.Name, value: h.Value}
			order = append(order, k)
		}
		return m, order
	}
	was, wasOrder := join(before)
	now, nowOrder := join(after)
	var changes []flow.RewriteChange
	for _, k := range wasOrder {
		w := was[k]
		n, ok := now[k]
		switch {
		case !ok:
			changes = append(changes, flow.RewriteChange{Op: rewrite.OpDelete, Name: w.name, Before: w.value, HadBefore: true})
		case n.value != w.value:
			changes = append(changes, flow.RewriteChange{Op: rewrite.OpReplace, Name: n.name, Before: w.value, HadBefore: true, After: n.value, HasAfter: true})
		}
	}
	for _, k := range nowOrder {
		if _, ok := was[k]; !ok {
			changes = append(changes, flow.RewriteChange{Op: rewrite.OpAdd, Name: now[k].name, After: now[k].value, HasAfter: true})
		}
	}
	if len(changes) > maxChanges {
		changes = changes[:maxChanges]
	}
	return changes
}

// respond turns a script's response into a LocalResponse.
func (x *Exchange) respond(hit *flow.RewriteHit, r *script.Response, head bool) (*rewrite.LocalResponse, string) {
	if r == nil {
		return nil, "empty response"
	}
	if r.Status < 200 || r.Status > 599 {
		return nil, "response status must be between 200 and 599"
	}
	if int64(len(r.Body)) > rewrite.MaxBody {
		return nil, "response body too large"
	}
	headers := make([]flow.Header, 0, len(r.Headers)+1)
	hasType := false
	for _, h := range r.Headers {
		if rewrite.ReservedHeader(h.Name) {
			continue
		}
		if issue := rewrite.HeaderIssue(h.Name, h.Value); issue != "" {
			return nil, issue
		}
		if strings.EqualFold(h.Name, "Content-Type") {
			hasType = true
		}
		headers = append(headers, flow.Header{Name: h.Name, Value: h.Value})
	}
	data := r.Body
	if r.Status == 204 || r.Status == 205 || r.Status == 304 {
		data = nil
	}
	if !hasType && len(data) > 0 {
		headers = append(headers, flow.Header{Name: "Content-Type", Value: "text/plain; charset=utf-8"})
	}
	hit.Action = string(script.ActionRespond)
	hit.Changes = []flow.RewriteChange{{Op: "respond", Name: "status", After: strconv.Itoa(r.Status), HasAfter: true}}
	return rewrite.NewLocal(*hit, r.Status, headers, data), ""
}
