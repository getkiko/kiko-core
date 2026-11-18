package rewrite

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/flow"
	E "github.com/sagernet/sing/common/exceptions"
)

// Internal is the decision of a "header" URL rule: the request goes to another origin and
// path without the client noticing.
type Internal struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is the lower-case host name or IP address, without brackets or port.
	Host string
	// Port is the numeric port (80 and 443 when the target names none).
	Port int
	// Authority is the Host header / :authority value: Host (bracketed for IPv6), plus ":port"
	// when the port is not the default of Scheme.
	Authority string
	// Target is the new request target (path and query, starting with "/").
	Target string
	// URL is Scheme://Authority+Target, the URL the header and body rules match again.
	URL string
	// Hit is the record of the rule (Kind "url", Action "header", Target URL).
	Hit flow.RewriteHit
}

// SameOrigin reports whether the request already goes to scheme://host:port, so that
// the existing upstream connection can be reused and only the target and Host change.
// host is compared case-insensitively without brackets.
func (in *Internal) SameOrigin(scheme, host string, port int) bool {
	return in.Scheme == scheme && in.Port == port && strings.EqualFold(in.Host, host)
}

// Internal returns the header rewrite the rules decided, or nil. When it is set,
// Local is nil and the other edits are not planned: ask Set.PlanAfterInternal for the
// header and body rules of the new URL.
func (p *Plan) Internal() *Internal {
	if p == nil {
		return nil
	}
	return p.internal
}

// PlanAfterInternal matches the header and body rules against the URL after an internal
// rewrite. URL rules and map_local are not consulted again, so a request is rewritten at
// most once. It returns nil when no rule matches.
func (s *Set) PlanAfterInternal(in *Internal) *Plan {
	if s.Empty() || in == nil {
		return nil
	}
	return s.planRest([]byte(in.URL))
}

// SetInternalGuard installs a veto for internal rewrites: when deny returns true for the
// target host and port, the rule is treated as not matching (the engine uses it to keep
// requests away from the core's own API). Call it before the set is used.
func (s *Set) SetInternalGuard(deny func(host string, port int) bool) {
	s.guard = deny
}

func (s *Set) internalFor(r *urlRule, target []byte) *Internal {
	match := r.re.FindSubmatchIndex(target)
	if match == nil {
		return nil
	}
	location := string(r.re.Expand(nil, []byte(r.target), target, match))
	if !validLocation(location) {
		return nil
	}
	// The original request target: everything from the first '/' (or '?') after the authority.
	original := "/"
	if i := strings.Index(string(target), "://"); i >= 0 {
		rest := string(target[i+3:])
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			original = rest[j:]
			if original[0] == '?' {
				original = "/" + original
			}
		}
	}
	in, err := parseInternal(location, original)
	if err != nil {
		return nil
	}
	if s.guard != nil && s.guard(in.Host, in.Port) {
		return nil
	}
	in.Hit = flow.RewriteHit{Kind: KindURL, Rule: r.id, Action: ActionHeader, Target: in.URL}
	return in
}

// parseInternal validates an expanded header-rule target. original is the request target
// kept when location has no path of its own.
func parseInternal(location, original string) (*Internal, error) {
	if len(location) > maxPattern {
		return nil, E.New("target too long")
	}
	u, err := url.Parse(location)
	if err != nil {
		return nil, E.New("invalid target URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, E.New("target must be an absolute http or https URL")
	}
	if u.User != nil {
		return nil, E.New("target must not contain credentials")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, "%\\/@") {
		return nil, E.New("target must have a host")
	}
	if ip, ok := canonicalIPv4(strings.TrimSuffix(host, ".")); ok {
		host = ip
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if text := u.Port(); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > 65535 {
			return nil, E.New("invalid target port")
		}
		port = n
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, E.New("invalid target port")
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		authority += ":" + strconv.Itoa(port)
	}
	// Raw path and query as written after the authority; a fragment is dropped.
	rest := location[strings.Index(location, "://")+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[j:]
	} else {
		rest = ""
	}
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		rest = rest[:j]
	}
	target := rest
	switch {
	case target == "":
		target = original
	case target[0] == '?':
		target = "/" + target
	}
	if target == "" || target[0] != '/' {
		return nil, E.New("invalid target path")
	}
	full := scheme + "://" + authority + target
	return &Internal{Scheme: scheme, Host: host, Port: port, Authority: authority, Target: target, URL: full}, nil
}

// canonicalIPv4 turns the inet_aton spellings of an IPv4 address (decimal integer, hex, octal,
// abbreviated forms such as 127.1) into dotted decimal, so that the host is judged and dialed
// as the address it denotes. ok is false for anything that is not made of numbers only.
func canonicalIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return "", false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return "", false
		}
		base := 10
		digits := part
		switch {
		case len(part) > 2 && (part[:2] == "0x" || part[:2] == "0X"):
			base, digits = 16, part[2:]
		case len(part) > 1 && part[0] == '0':
			base, digits = 8, part[1:]
		}
		n, err := strconv.ParseUint(digits, base, 64)
		if err != nil {
			return "", false
		}
		values[i] = n
	}
	last := values[len(values)-1]
	limit := uint64(1) << (8 * (5 - uint(len(values))))
	if last >= limit {
		return "", false
	}
	var addr uint64
	for i := 0; i < len(values)-1; i++ {
		if values[i] > 255 {
			return "", false
		}
		addr |= values[i] << (8 * (3 - uint(i)))
	}
	addr |= last
	return strconv.Itoa(int(addr>>24)) + "." + strconv.Itoa(int(addr>>16&255)) + "." + strconv.Itoa(int(addr>>8&255)) + "." + strconv.Itoa(int(addr&255)), true
}
