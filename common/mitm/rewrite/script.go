package rewrite

import (
	"github.com/sagernet/sing-box/common/mitm/flow"
	E "github.com/sagernet/sing/common/exceptions"
)

var errInternalDenied = E.New("target is not allowed")

// KindScript is the flow.RewriteHit kind of scripts.
const KindScript = "script"

// NewLocal builds an answer for a producer outside the rule set (scripts). headers must not
// contain Content-Length: it is added from the body.
func NewLocal(hit flow.RewriteHit, status int, headers []flow.Header, body []byte) *LocalResponse {
	local := newLocal(hit.Kind, hit.Rule, hit.Action, status, headers, body)
	hit.Status = status
	local.Hit = hit
	return local
}

// NewAbort builds an answer that ends the connection (h1) or resets the stream (h2).
func NewAbort(hit flow.RewriteHit) *LocalResponse {
	return &LocalResponse{Abort: true, Hit: hit}
}

// ScriptInternal validates a URL produced by a script as the target of an internal rewrite:
// an absolute http or https URL without credentials, which the guard of the set may veto.
// original is the request target kept when location has no path. It returns nil with the
// reason when the URL is not acceptable.
func (s *Set) ScriptInternal(location, original string) (*Internal, error) {
	in, err := parseInternal(location, original)
	if err != nil {
		return nil, err
	}
	if s != nil && s.guard != nil && s.guard(in.Host, in.Port) {
		return nil, errInternalDenied
	}
	return in, nil
}

// ReservedHeader reports whether a header frames the message or selects the connection, so
// that rules and scripts cannot change it.
func ReservedHeader(name string) bool { return reservedHeader(name) }

// HeaderIssue returns why name and value cannot be a header field, or "".
func HeaderIssue(name, value string) string {
	if issue := headerNameIssue(name); issue != "" {
		return issue
	}
	return headerValueIssue(value)
}
