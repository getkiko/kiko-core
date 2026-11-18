package capture

import (
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

// RedactedValue replaces the value of a sensitive header or query parameter
// in persisted records.
const RedactedValue = "[redacted]"

// builtinRedactHeaders are masked in every persisted record. Names are
// lower case.
var builtinRedactHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"cookie2",
	"set-cookie2",
	"x-api-key",
	"api-key",
	"x-auth-token",
	"x-access-token",
	"x-csrf-token",
	"x-xsrf-token",
	"x-amz-security-token",
	"x-goog-api-key",
	"x-session-token",
	"proxy-authenticate",
	"www-authenticate",
	"sec-websocket-protocol",
}

// secretParamExact are query parameter names masked regardless of the
// substring rules (lower case).
var secretParamExact = map[string]struct{}{
	"code": {}, "jwt": {}, "sid": {}, "sig": {}, "pwd": {}, "otp": {},
	"ticket": {}, "bearer": {},
}

// secretParamWords mask any parameter whose lower-case name contains one.
var secretParamWords = []string{
	"token", "secret", "key", "pass", "auth", "sig", "credential", "session", "jwt", "pwd",
}

// SecretParam reports whether the value of a query parameter or fragment
// field is a credential. Persisted records and HAR export share this rule.
func SecretParam(name string) bool {
	name = strings.ToLower(name)
	if _, ok := secretParamExact[name]; ok {
		return true
	}
	for _, word := range secretParamWords {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
}

// redactUserInfo masks the user:password part of an absolute URL.
func redactUserInfo(raw string) string {
	scheme, rest, found := strings.Cut(raw, "://")
	if !found {
		return raw
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	at := strings.LastIndex(rest[:end], "@")
	if at < 0 {
		return raw
	}
	return scheme + "://" + RedactedValue + "@" + rest[at+1:]
}

// redactor masks sensitive values before a record is written.
type redactor struct {
	headers map[string]struct{}
}

func newRedactor(extra []string) *redactor {
	r := &redactor{headers: make(map[string]struct{}, len(builtinRedactHeaders)+len(extra))}
	for _, name := range builtinRedactHeaders {
		r.headers[name] = struct{}{}
	}
	for _, name := range extra {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			r.headers[name] = struct{}{}
		}
	}
	return r
}

// secretHeaderWords mask any header whose lower-case name contains one.
var secretHeaderWords = []string{"token", "secret", "key", "auth", "credential", "session", "pass", "pwd", "sig", "jwt", "bearer", "otp"}

// harmlessHeaderPrefixes and harmlessHeaderNames keep common headers whose names
// contain a secret word but carry no credential (:authority, Accept-*,
// Content-*, Cache-Control, Access-Control-*, Sec-WebSocket-Key).
var harmlessHeaderPrefixes = []string{"accept-", "content-", "access-control-"}

var harmlessHeaderNames = map[string]struct{}{
	":authority": {}, "authority": {}, "cache-control": {}, "sec-websocket-key": {},
}

// urlHeaders carry a URL whose query string and user info are masked like the
// record URL.
var urlHeaders = map[string]struct{}{
	"location": {}, "referer": {}, "content-location": {}, "refresh": {}, "origin": {},
}

func (r *redactor) sensitive(name string) bool {
	name = strings.ToLower(name)
	if _, ok := r.headers[name]; ok {
		return true
	}
	if _, ok := harmlessHeaderNames[name]; ok {
		return false
	}
	for _, prefix := range harmlessHeaderPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	for _, word := range secretHeaderWords {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
}

// value masks the value of header name: all of it for a credential header, the
// secret parts of the URL for a URL header.
func (r *redactor) value(name, value string) string {
	if r.sensitive(name) {
		return RedactedValue
	}
	if _, ok := urlHeaders[strings.ToLower(name)]; ok {
		return redactTarget(value)
	}
	return value
}

// headers returns a masked copy; the input stays as it is.
func (r *redactor) headerList(headers []flow.Header) []flow.Header {
	if len(headers) == 0 {
		return nil
	}
	out := make([]flow.Header, len(headers))
	for i, h := range headers {
		out[i] = h
		out[i].Value = r.value(h.Name, h.Value)
	}
	return out
}

// redactTarget masks the sensitive query parameters and fragment fields of a
// URL or request path.
func redactTarget(target string) string {
	target = redactUserInfo(target)
	fragment := ""
	if hash := strings.IndexByte(target, '#'); hash >= 0 {
		target, fragment = target[:hash], target[hash+1:]
		fragment = "#" + redactFields(fragment)
	}
	if index := strings.IndexByte(target, '?'); index >= 0 {
		target = target[:index+1] + redactFields(target[index+1:])
	}
	return target + fragment
}

// redactFields masks the values of secret name=value pairs in a query string
// or fragment.
func redactFields(query string) string {
	parts := strings.Split(query, "&")
	for i, part := range parts {
		name, _, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		key := name
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		if SecretParam(name) {
			parts[i] = key + "=" + RedactedValue
		}
	}
	return strings.Join(parts, "&")
}

// hits masks changed header values and drops script console output, which
// may print anything.
func (r *redactor) hits(hits []flow.RewriteHit) []flow.RewriteHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]flow.RewriteHit, len(hits))
	for i := range hits {
		out[i] = hits[i]
		if len(hits[i].Changes) > 0 {
			changes := make([]flow.RewriteChange, len(hits[i].Changes))
			copy(changes, hits[i].Changes)
			for j := range changes {
				if changes[j].HadBefore {
					changes[j].Before = r.value(changes[j].Name, changes[j].Before)
				}
				if changes[j].HasAfter {
					changes[j].After = r.value(changes[j].Name, changes[j].After)
				}
			}
			out[i].Changes = changes
		}
		out[i].Target = redactTarget(out[i].Target)
		if run := hits[i].Run; run != nil {
			copied := *run
			copied.Logs = nil
			copied.Error = ""
			copied.Reason = ""
			out[i].Run = &copied
		}
	}
	return out
}

// record returns a masked copy of rec.
func (r *redactor) record(rec Record) Record {
	rec.RequestHeaders = r.headerList(rec.RequestHeaders)
	rec.ResponseHeaders = r.headerList(rec.ResponseHeaders)
	rec.RequestTrailers = r.headerList(rec.RequestTrailers)
	rec.ResponseTrailers = r.headerList(rec.ResponseTrailers)
	rec.Path = redactTarget(rec.Path)
	rec.URL = redactTarget(rec.URL)
	rec.Rewrites = r.hits(rec.Rewrites)
	return rec
}
