package rewrite

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Body rule actions.
const (
	EditReplaceRegex = "replace-regex"
	EditJSONSet      = "json-set"
	EditJSONDelete   = "json-delete"
	EditJSONAppend   = "json-append"
)

// KindBody is the flow.RewriteHit kind of body rules.
const KindBody = "body"

// Hit actions of body rules and the reasons (RewriteHit.Target) of a skipped one.
const (
	ActionEdit    = "edit"
	ActionSkipped = "skipped"

	SkipStream      = "stream"
	SkipSize        = "size"
	SkipTimeout     = "timeout"
	SkipBusy        = "busy"
	SkipEncoding    = "encoding"
	SkipDecode      = "decode"
	SkipDecodedSize = "decoded-size"
	SkipLimit       = "limit"
)

// Limits of body rules and buffering.
const (
	DefaultMaxBodySize = 2 << 20
	MinMaxBodySize     = 1 << 10
	MaxMaxBodySize     = 32 << 20

	maxEdits        = 32
	maxContentTypes = 32
	maxRegexMatches = 1 << 16
)

type bodyEdit struct {
	action string
	re     *regexp.Regexp
	repl   string
	path   *jsonPath
	value  []byte
	label  string // Regex or Path, for the record
}

type bodyRule struct {
	id       string
	re       *regexp.Regexp
	scope    string
	types    []string // lower case; empty selects the defaults per edit
	edits    []bodyEdit
	hasRegex bool
	hasJSON  bool
}

func compileBody(id string, rule option.MITMBodyRewriteRule) (bodyRule, error) {
	re, err := compilePattern(rule.Pattern)
	if err != nil {
		return bodyRule{}, err
	}
	r := bodyRule{id: id, re: re, scope: rule.Scope}
	switch rule.Scope {
	case ScopeRequest, ScopeResponse:
	case "":
		return bodyRule{}, E.New("missing scope")
	default:
		return bodyRule{}, E.New("unknown scope: ", rule.Scope)
	}
	if len(rule.ContentTypes) > maxContentTypes {
		return bodyRule{}, E.New("too many content_types")
	}
	for _, t := range rule.ContentTypes {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || len(t) > 256 || headerValueIssue(t) != "" {
			return bodyRule{}, E.New("invalid content type ", strconv.Quote(t))
		}
		r.types = append(r.types, t)
	}
	if len(rule.Edits) == 0 {
		return bodyRule{}, E.New("no edits")
	}
	if len(rule.Edits) > maxEdits {
		return bodyRule{}, E.New("too many edits (at most ", maxEdits, ")")
	}
	for i, edit := range rule.Edits {
		compiled := bodyEdit{action: edit.Action}
		if len(edit.Value) > maxValue {
			return bodyRule{}, E.New("edit ", i+1, ": value too long")
		}
		switch edit.Action {
		case EditReplaceRegex:
			if edit.Regex == "" {
				return bodyRule{}, E.New("edit ", i+1, ": replace-regex needs a regex")
			}
			if len(edit.Regex) > maxPattern {
				return bodyRule{}, E.New("edit ", i+1, ": regex too long")
			}
			compiled.re, err = regexp.Compile(edit.Regex)
			if err != nil {
				return bodyRule{}, E.Cause(err, "edit ", i+1, ": invalid regex")
			}
			compiled.repl = edit.Value
			compiled.label = edit.Regex
			r.hasRegex = true
		case EditJSONSet, EditJSONDelete, EditJSONAppend:
			if edit.Path == "" {
				return bodyRule{}, E.New("edit ", i+1, ": ", edit.Action, " needs a path")
			}
			compiled.path, err = parseJSONPath(edit.Path)
			if err != nil {
				return bodyRule{}, E.Cause(err, "edit ", i+1, ": invalid path")
			}
			compiled.label = edit.Path
			if edit.Action != EditJSONDelete {
				value := bytes.TrimFunc([]byte(edit.Value), func(r rune) bool { return r < 0x80 && isJSONSpace(byte(r)) })
				if !validJSONValue(value) {
					return bodyRule{}, E.New("edit ", i+1, ": value is not valid JSON")
				}
				compiled.value = value
			}
			r.hasJSON = true
		case "":
			return bodyRule{}, E.New("edit ", i+1, ": missing action")
		default:
			return bodyRule{}, E.New("edit ", i+1, ": unknown action: ", edit.Action)
		}
		r.edits = append(r.edits, compiled)
	}
	return r, nil
}

func mediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func defaultTextType(contentType string) bool {
	mt := mediaType(contentType)
	return strings.HasPrefix(mt, "text/") || strings.Contains(mt, "json") || strings.Contains(mt, "xml") ||
		strings.Contains(mt, "javascript") || strings.Contains(mt, "x-www-form-urlencoded")
}

func defaultJSONType(contentType string) bool {
	mt := mediaType(contentType)
	return strings.HasSuffix(mt, "/json") || strings.HasSuffix(mt, "+json")
}

// editApplies reports whether edit e of the rule runs for contentType.
func (r *bodyRule) editApplies(e *bodyEdit, contentType string) bool {
	if len(r.types) > 0 {
		lower := strings.ToLower(contentType)
		for _, t := range r.types {
			if strings.Contains(lower, t) {
				return true
			}
		}
		return false
	}
	if e.action == EditReplaceRegex {
		return defaultTextType(contentType)
	}
	return defaultJSONType(contentType)
}

// selects reports whether any edit of the rule runs for scope and contentType.
func (r *bodyRule) selects(scope, contentType string) bool {
	if r.scope != scope {
		return false
	}
	for i := range r.edits {
		if r.editApplies(&r.edits[i], contentType) {
			return true
		}
	}
	return false
}

// NeedsBody reports whether some body rule of the plan selects a message of scope
// (ScopeRequest or ScopeResponse) with contentType, so the engine has to buffer it. It does
// not allocate and is false for a nil plan.
func (p *Plan) NeedsBody(scope, contentType string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.body {
		if r.selects(scope, contentType) {
			return true
		}
	}
	return false
}

// HasBodyRules reports whether the plan has any body rule for scope, whatever the content
// type.
func (p *Plan) HasBodyRules(scope string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.body {
		if r.scope == scope {
			return true
		}
	}
	return false
}

// SkipHits returns the records of the selected body rules that did not rewrite a message
// for reason (one of the Skip* constants).
func (p *Plan) SkipHits(scope, contentType, reason string) []flow.RewriteHit {
	if p == nil {
		return nil
	}
	var hits []flow.RewriteHit
	for _, r := range p.body {
		if r.selects(scope, contentType) {
			hits = append(hits, flow.RewriteHit{Kind: KindBody, Rule: r.id, Action: ActionSkipped, Side: scope, Target: reason})
		}
	}
	return hits
}

// StreamingMessage reports whether a message must never be buffered, so the body rules
// leave it alone: event streams and gRPC bodies (either side), and for responses also
// 1xx, 101, 204, 205, 304, the 206 answer to a range request, HEAD answers and CONNECT. status is 0 for
// requests.
func StreamingMessage(scope, method string, status int, contentType string, ranged bool) bool {
	mt := mediaType(contentType)
	if strings.HasPrefix(mt, "application/grpc") {
		return true
	}
	if scope == ScopeRequest {
		return method == "CONNECT"
	}
	if mt == "text/event-stream" || method == "HEAD" || method == "CONNECT" {
		return true
	}
	switch {
	case status >= 100 && status < 200, status == 204, status == 205, status == 304:
		return true
	case status == 206 && ranged:
		return true
	}
	return false
}

// BodyResult is the outcome of ApplyBody.
type BodyResult struct {
	// Data is what to send: the rewritten bytes in the original Content-Encoding, or the
	// input slice itself when nothing changed.
	Data []byte
	// Changed reports that Data differs from the input.
	Changed bool
	// Hits are the records: one "edit" per rule that changed the body, or "skipped" ones
	// (Target is the reason) when the body was passed through for encoding, decode or size
	// reasons.
	Hits []flow.RewriteHit
}

// ApplyBody applies the selected body rules of scope to an already buffered message
// body. data holds the bytes as received, compressed according to contentEncoding.
// maxBody bounds the decoded and the rewritten size (0 selects the default).
// It never modifies data. Callers update Content-Length (or framing) when Changed, and
// drop Digest and Content-Digest.
func (p *Plan) ApplyBody(scope, contentType, contentEncoding string, data []byte, maxBody int64) BodyResult {
	result := BodyResult{Data: data}
	if p == nil {
		return result
	}
	var selected []*bodyRule
	for _, r := range p.body {
		if r.selects(scope, contentType) {
			selected = append(selected, r)
		}
	}
	if len(selected) == 0 {
		return result
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBodySize
	}
	skip := func(reason string) BodyResult {
		out := BodyResult{Data: data}
		for _, r := range selected {
			out.Hits = append(out.Hits, flow.RewriteHit{Kind: KindBody, Rule: r.id, Action: ActionSkipped, Side: scope, Target: reason})
		}
		return out
	}
	encodings := body.ParseEncodings(contentEncoding)
	plain := data
	if len(encodings) > 0 {
		decoded, err := body.Decode(contentEncoding, bytes.NewReader(data), body.Limits{MaxOutput: maxBody})
		if err != nil {
			if e, ok := err.(*body.Error); ok {
				switch e.Kind {
				case body.ErrUnsupported:
					return skip(SkipEncoding)
				case body.ErrOutputLimit, body.ErrBomb:
					return skip(SkipDecodedSize)
				}
			}
			return skip(SkipDecode)
		}
		plain = decoded
	}
	state := editState{cur: plain, limit: int(maxBody) * 2}
	var hits []flow.RewriteHit
	for _, r := range selected {
		var changes []flow.RewriteChange
		for i := range r.edits {
			e := &r.edits[i]
			if !r.editApplies(e, contentType) {
				continue
			}
			if n := state.apply(e); n > 0 {
				changes = append(changes, flow.RewriteChange{Op: e.action, Name: clip(e.label), After: strconv.Itoa(n), HasAfter: true})
			}
		}
		if len(changes) > 0 {
			hits = append(hits, flow.RewriteHit{Kind: KindBody, Rule: r.id, Action: ActionEdit, Side: scope, Changes: changes})
		}
	}
	state.flush()
	if state.overflow {
		return skip(SkipLimit)
	}
	if len(hits) == 0 {
		return result
	}
	final := state.cur
	if len(encodings) > 0 {
		encoded, err := body.Encode(contentEncoding, final)
		if err != nil {
			return skip(SkipEncoding)
		}
		final = encoded
	}
	return BodyResult{Data: final, Changed: true, Hits: hits}
}

// editState carries the working bytes through the edits. Consecutive JSON edits share one
// parsed document.
type editState struct {
	cur    []byte
	limit  int
	doc    *jsonDoc
	failed bool // cur is not JSON (until it changes)
	// overflow is set when a JSON result exceeded limit.
	overflow bool
}

// flush writes a pending JSON document back into cur.
func (s *editState) flush() {
	if s.doc == nil {
		return
	}
	doc := s.doc
	s.doc = nil
	if doc.overflow {
		s.overflow = true
		return
	}
	if out, ok := doc.bytes(s.limit); ok {
		s.cur = out
	} else {
		s.overflow = true
	}
}

func (s *editState) apply(e *bodyEdit) int {
	if s.overflow {
		return 0
	}
	if e.action == EditReplaceRegex {
		s.flush()
		out, n, many := regexReplace(e.re, s.cur, e.repl, s.limit)
		if many {
			s.overflow = true
			return 0
		}
		if n > 0 {
			s.cur = out
			s.failed = false
		}
		return n
	}
	if s.doc == nil {
		if s.failed {
			return 0
		}
		doc, ok := newJSONDoc(s.cur)
		if !ok {
			s.failed = true
			return 0
		}
		doc.limit = s.limit
		s.doc = doc
	}
	var n int
	switch e.action {
	case EditJSONSet:
		n = s.doc.set(e.path, e.value)
	case EditJSONDelete:
		n = s.doc.remove(e.path)
	default:
		n = s.doc.appendTo(e.path, e.value)
	}
	if s.doc.overflow {
		s.overflow = true
		return 0
	}
	return n
}

// regexReplace replaces every match of re in src with the expanded template. It returns
// the new bytes and the number of replacements (0 when nothing matched or changed). refused
// is set when the edit was abandoned: too many matches, or a result beyond limit.
func regexReplace(re *regexp.Regexp, src []byte, template string, limit int) (out []byte, count int, refused bool) {
	matches := re.FindAllSubmatchIndex(src, maxRegexMatches+1)
	if len(matches) == 0 {
		return nil, 0, false
	}
	if len(matches) > maxRegexMatches {
		return nil, 0, true
	}
	out = make([]byte, 0, len(src)+16)
	last := 0
	tmpl := []byte(template)
	for _, m := range matches {
		out = append(out, src[last:m[0]]...)
		out = re.Expand(out, tmpl, src, m)
		last = m[1]
		if len(out) > limit {
			return nil, 0, true
		}
	}
	out = append(out, src[last:]...)
	if len(out) > limit {
		return nil, 0, true
	}
	if bytes.Equal(out, src) {
		return nil, 0, false
	}
	return out, len(matches), false
}
