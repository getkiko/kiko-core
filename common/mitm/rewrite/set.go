// Package rewrite compiles the mitm.http_rewrite options into an immutable
// rule set and applies it to requests and responses. It knows nothing about
// the HTTP engines: they ask for a Plan per request and apply it to their
// header lists.
package rewrite

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// Limits of compiled rules.
const (
	MaxBody      = 8 << 20
	MaxBodyTotal = 32 << 20
	maxPattern   = 8 << 10
	maxValue     = 32 << 10
)

// Rule kinds in flow.RewriteHit.
const (
	KindURL      = "url"
	KindHeader   = "header"
	KindMapLocal = "map_local"
	KindConnect  = "connect"
)

// URL actions.
const (
	ActionReject      = "reject"
	ActionReject200   = "reject-200"
	ActionRejectImg   = "reject-img"
	ActionRejectGIF   = "reject-tinygif"
	ActionRejectDict  = "reject-dict"
	ActionRejectArray = "reject-array"
	ActionFound       = "302"
	ActionTemporary   = "307"
	ActionMapLocal    = "map_local"
	ActionHeader      = "header"
)

// Header scopes and operations.
const (
	ScopeRequest  = "request"
	ScopeResponse = "response"

	OpAdd          = "add"
	OpDelete       = "delete"
	OpReplace      = "replace"
	OpReplaceRegex = "replace-regex"
)

// Probe paths used by HostReject.
const (
	probeRoot = "/"
	probeDeep = "/__kiko_probe__/x?y=1"
)

type urlRule struct {
	id     string
	re     *regexp.Regexp
	action string
	target string
	local  *LocalResponse // fixed answer; nil for redirects
	// anchored lists the strings every match starts with at the beginning of the URL (nil
	// when the pattern is not anchored).
	anchored []string
}

type mapRule struct {
	id    string
	re    *regexp.Regexp
	local *LocalResponse
}

type headerRule struct {
	id    string
	re    *regexp.Regexp
	scope string
	ops   []headerOp
}

// Set is a compiled, immutable rule set. A nil *Set is an empty set.
type Set struct {
	url     []urlRule
	maps    []mapRule
	headers []headerRule
	body    []bodyRule

	maxBodySize    int64
	guard          func(host string, port int) bool
	appliesToPlain bool
	hasReject      bool
	pool           sync.Pool
}

// Empty reports whether the set has no rule.
func (s *Set) Empty() bool {
	return s == nil || len(s.url) == 0 && len(s.maps) == 0 && len(s.headers) == 0 && len(s.body) == 0
}

// AppliesToPlain reports whether some rule can match an http:// URL. A rule
// whose pattern is anchored at the start and begins with the literal
// "https://" cannot.
func (s *Set) AppliesToPlain() bool { return s != nil && s.appliesToPlain }

// Plan is what the rules decided for one request. It is nil when no rule
// matched.
type Plan struct {
	local    *LocalResponse
	internal *Internal
	request  []*headerRule
	response []*headerRule
	body     []*bodyRule
}

// Plan matches the rules against scheme://authority+target, where authority
// is the host (and port) as the client sent it and target is the path with
// query. It returns nil when nothing matches and does not allocate then.
func (s *Set) Plan(scheme, authority, target string) *Plan {
	if s.Empty() {
		return nil
	}
	bufp := s.getBuf()
	buf := append((*bufp)[:0], scheme...)
	buf = append(buf, "://"...)
	buf = append(buf, authority...)
	buf = append(buf, target...)
	*bufp = buf
	plan := s.plan(buf)
	s.putBuf(bufp)
	return plan
}

// MaxBodySize is the most bytes of a message body the engines buffer for body rules
// (mitm.http_rewrite.max_body_size, 2 MiB by default).
func (s *Set) MaxBodySize() int64 {
	if s == nil || s.maxBodySize <= 0 {
		return DefaultMaxBodySize
	}
	return s.maxBodySize
}

func (s *Set) getBuf() *[]byte {
	if v := s.pool.Get(); v != nil {
		return v.(*[]byte)
	}
	b := make([]byte, 0, 512)
	return &b
}

func (s *Set) putBuf(b *[]byte) {
	if cap(*b) > 64<<10 {
		return
	}
	s.pool.Put(b)
}

func (s *Set) plan(url []byte) *Plan {
	for i := range s.url {
		r := &s.url[i]
		if !r.re.Match(url) {
			continue
		}
		if r.action == ActionHeader {
			if in := s.internalFor(r, url); in != nil {
				return &Plan{internal: in}
			}
			continue
		}
		if r.local != nil {
			return &Plan{local: r.local}
		}
		if local := r.redirect(url); local != nil {
			return &Plan{local: local}
		}
	}
	for i := range s.maps {
		r := &s.maps[i]
		if r.re.Match(url) {
			return &Plan{local: r.local}
		}
	}
	return s.planRest(url)
}

// planRest matches the header and body rules, which never stop at the first match.
func (s *Set) planRest(url []byte) *Plan {
	var plan *Plan
	for i := range s.body {
		r := &s.body[i]
		if !r.re.Match(url) {
			continue
		}
		if plan == nil {
			plan = &Plan{}
		}
		plan.body = append(plan.body, r)
	}
	for i := range s.headers {
		r := &s.headers[i]
		if !r.re.Match(url) {
			continue
		}
		if plan == nil {
			plan = &Plan{}
		}
		if r.scope == ScopeResponse {
			plan.response = append(plan.response, r)
		} else {
			plan.request = append(plan.request, r)
		}
	}
	return plan
}

// HostReject reports a reject rule that applies to every request of host:
// the first URL rule matching both https://host/ and a deep probe URL. Any
// earlier URL rule, whatever its action, that could match some URL of the host
// (it matches a probe, or no anchored literal prefix excludes the host) keeps
// the decision with the request-level engine, so first-match order holds.
//
// host is the authority as the client would send it: the name, plus ":port" when the port
// is not 443.
func (s *Set) HostReject(host string) (ruleID string, ok bool) {
	if s == nil || !s.hasReject || host == "" {
		return "", false
	}
	bufp := s.getBuf()
	defer s.putBuf(bufp)
	buf := append((*bufp)[:0], "https://"...)
	buf = append(buf, host...)
	buf = append(buf, probeRoot...)
	root := len(buf)
	buf = append(buf, probeDeep[len(probeRoot):]...)
	*bufp = buf
	for i := range s.url {
		r := &s.url[i]
		matchRoot, matchDeep := r.re.Match(buf[:root]), r.re.Match(buf)
		if matchRoot && matchDeep {
			if r.action == ActionReject {
				return r.id, true
			}
			return "", false
		}
		if matchRoot || matchDeep || !excludesHost(r.anchored, buf[:root-1]) {
			return "", false
		}
	}
	return "", false
}

// excludesHost reports whether the rule cannot match any URL of the host (authority = root,
// without the path slash, so that a port the client adds stays possible): every possible
// start of its matches conflicts with https://host/.
func excludesHost(prefixes []string, root []byte) bool {
	if len(prefixes) == 0 {
		return false
	}
	for _, prefix := range prefixes {
		n := min(len(prefix), len(root))
		if strings.EqualFold(prefix[:n], string(root[:n])) {
			return false
		}
	}
	return true
}

const maxPrefixes = 64

// anchoredPrefixes returns the strings every match of pattern can start with when the
// pattern is anchored at the beginning of the URL (nil when it is not, or the expansion is
// too large to be useful).
func anchoredPrefixes(pattern string) []string {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	subs := []*syntax.Regexp{parsed}
	if parsed.Op == syntax.OpConcat {
		subs = parsed.Sub
	}
	if len(subs) == 0 || subs[0].Op != syntax.OpBeginText {
		return nil
	}
	prefixes, _ := expandConcat(subs[1:])
	return prefixes
}

// expandConcat returns the possible leading strings of the sequence and whether they are
// complete (the sequence matches exactly one of them and nothing else).
func expandConcat(subs []*syntax.Regexp) ([]string, bool) {
	current := []string{""}
	for _, sub := range subs {
		alts, exact := expandNode(sub)
		if len(current)*len(alts) > maxPrefixes {
			return current, false
		}
		next := make([]string, 0, len(current)*len(alts))
		for _, prefix := range current {
			for _, alt := range alts {
				next = append(next, prefix+alt)
			}
		}
		current = next
		if !exact {
			return current, false
		}
	}
	return current, true
}

func expandNode(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}, true
	case syntax.OpCapture:
		return expandNode(re.Sub[0])
	case syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpConcat:
		return expandConcat(re.Sub)
	case syntax.OpAlternate:
		var all []string
		exact := true
		for _, sub := range re.Sub {
			alts, subExact := expandNode(sub)
			all = append(all, alts...)
			exact = exact && subExact
			if len(all) > maxPrefixes {
				return []string{""}, false
			}
		}
		return all, exact
	case syntax.OpQuest:
		alts, exact := expandNode(re.Sub[0])
		return append([]string{""}, alts...), exact
	case syntax.OpCharClass:
		var all []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if int(re.Rune[i+1])-int(re.Rune[i]) >= maxPrefixes {
				return []string{""}, false
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				all = append(all, string(r))
			}
			if len(all) > maxPrefixes {
				return []string{""}, false
			}
		}
		return all, true
	}
	return []string{""}, false
}

// anchoredHTTPS reports whether every match of re starts with "https://" at
// the beginning of the URL.
func anchoredHTTPS(re *regexp.Regexp, pattern string) bool {
	prefix, _ := re.LiteralPrefix()
	if !strings.HasPrefix(prefix, "https://") {
		return false
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return false
	}
	return prog.StartCond()&syntax.EmptyBeginText != 0
}
