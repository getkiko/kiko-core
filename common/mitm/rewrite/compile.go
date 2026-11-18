package rewrite

import (
	"context"
	"encoding/base64"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

// reservedHeaders frame the message or select the connection; rules cannot
// touch them.
var reservedHeaders = map[string]bool{
	"content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true,
	"upgrade": true, "te": true, "trailer": true, "host": true, "proxy-connection": true,
	"proxy-authenticate": true, "proxy-authorization": true, "http2-settings": true,
	"expect": true,
}

// reservedHeader reports whether name is reserved, also in the spelling with underscores
// (Content_Length), which some servers treat as the dashed field.
func reservedHeader(name string) bool {
	name = strings.ToLower(name)
	return reservedHeaders[name] || reservedHeaders[strings.ReplaceAll(name, "_", "-")]
}

// Compile validates options and builds the rule set. Rules without an id get
// url#N, headers#N or map_local#N (N counts from 1). Errors name the rule.
func Compile(ctx context.Context, options *option.MITMHTTPRewriteOptions) (*Set, error) {
	set := &Set{}
	if options == nil {
		return set, nil
	}
	var total int
	if options.MaxBodySize != nil {
		size := int64(options.MaxBodySize.Value())
		if size < MinMaxBodySize || size > MaxMaxBodySize {
			return nil, E.New("http_rewrite.max_body_size must be between ", MinMaxBodySize, " and ", MaxMaxBodySize, " bytes")
		}
		set.maxBodySize = size
	}
	for i, rule := range options.URL {
		id := ruleID(rule.ID, "url", i)
		r, err := compileURL(id, rule)
		if err != nil {
			return nil, E.Cause(err, "http_rewrite.url ", id)
		}
		set.url = append(set.url, r)
		if r.action == ActionReject {
			set.hasReject = true
		}
		if !anchoredHTTPS(r.re, rule.Pattern) {
			set.appliesToPlain = true
		}
	}
	for i, rule := range options.MapLocal {
		id := ruleID(rule.ID, "map_local", i)
		r, err := compileMapLocal(ctx, id, rule)
		if err != nil {
			return nil, E.Cause(err, "http_rewrite.map_local ", id)
		}
		total += len(r.local.Body)
		if total > MaxBodyTotal {
			return nil, E.New("http_rewrite.map_local ", id, ": bodies exceed ", MaxBodyTotal>>20, " MiB in total")
		}
		set.maps = append(set.maps, r)
		if !anchoredHTTPS(r.re, rule.Pattern) {
			set.appliesToPlain = true
		}
	}
	for i, rule := range options.Headers {
		id := ruleID(rule.ID, "headers", i)
		r, err := compileHeaders(id, rule)
		if err != nil {
			return nil, E.Cause(err, "http_rewrite.headers ", id)
		}
		set.headers = append(set.headers, r)
		if !anchoredHTTPS(r.re, rule.Pattern) {
			set.appliesToPlain = true
		}
	}
	for i, rule := range options.Body {
		id := ruleID(rule.ID, "body", i)
		r, err := compileBody(id, rule)
		if err != nil {
			return nil, E.Cause(err, "http_rewrite.body ", id)
		}
		set.body = append(set.body, r)
		if !anchoredHTTPS(r.re, rule.Pattern) {
			set.appliesToPlain = true
		}
	}
	return set, nil
}

func ruleID(id, kind string, index int) string {
	if id != "" {
		return id
	}
	return kind + "#" + strconv.Itoa(index+1)
}

func compilePattern(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, E.New("missing pattern")
	}
	if len(pattern) > maxPattern {
		return nil, E.New("pattern too long")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, E.Cause(err, "invalid pattern")
	}
	return re, nil
}

func compileURL(id string, rule option.MITMURLRewriteRule) (urlRule, error) {
	re, err := compilePattern(rule.Pattern)
	if err != nil {
		return urlRule{}, err
	}
	r := urlRule{id: id, re: re, action: rule.Action, anchored: anchoredPrefixes(rule.Pattern)}
	switch rule.Action {
	case ActionReject, ActionReject200, ActionRejectImg, ActionRejectGIF, ActionRejectDict, ActionRejectArray:
		r.local = fixedAnswer(id, rule.Action)
	case ActionFound, ActionTemporary:
		target := rule.Target
		if target == "" {
			return urlRule{}, E.New("missing target")
		}
		if headerValueIssue(target) != "" {
			return urlRule{}, E.New("invalid target")
		}
		if !strings.Contains(target, "$") {
			u, err := url.Parse(target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return urlRule{}, E.New("target must be an absolute http or https URL")
			}
		}
		r.target = target
	case ActionHeader:
		target := rule.Target
		if target == "" {
			return urlRule{}, E.New("missing target")
		}
		if len(target) > maxPattern || headerValueIssue(target) != "" || strings.ContainsAny(target, " \x7f") {
			return urlRule{}, E.New("invalid target")
		}
		if !strings.Contains(target, "$") {
			if _, err := parseInternal(target, "/"); err != nil {
				return urlRule{}, E.Cause(err, "invalid target")
			}
		}
		r.target = target
	case "":
		return urlRule{}, E.New("missing action")
	default:
		return urlRule{}, E.New("unknown action: ", rule.Action)
	}
	return r, nil
}

func headerNameIssue(name string) string {
	if name == "" {
		return "empty header name"
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return "invalid header name " + strconv.Quote(name)
		}
	}
	if reservedHeader(name) {
		return "header " + name + " is managed by the proxy and cannot be rewritten"
	}
	return ""
}

func headerValueIssue(value string) string {
	if len(value) > maxValue {
		return "header value too long"
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c == '\r' || c == '\n' || c == 0 {
			return "header value contains a line break or NUL"
		} else if c < ' ' && c != '\t' || c == 0x7f {
			return "header value contains a control character"
		}
	}
	return ""
}

func compileHeaders(id string, rule option.MITMHeaderRewriteRule) (headerRule, error) {
	re, err := compilePattern(rule.Pattern)
	if err != nil {
		return headerRule{}, err
	}
	r := headerRule{id: id, re: re, scope: rule.Scope}
	switch rule.Scope {
	case ScopeRequest, ScopeResponse:
	case "":
		return headerRule{}, E.New("missing scope")
	default:
		return headerRule{}, E.New("unknown scope: ", rule.Scope)
	}
	if len(rule.Operations) == 0 {
		return headerRule{}, E.New("no operations")
	}
	for i, op := range rule.Operations {
		compiled := headerOp{action: op.Action, name: op.Name, value: op.Value}
		if issue := headerNameIssue(op.Name); issue != "" {
			return headerRule{}, E.New("operation ", i+1, ": ", issue)
		}
		if issue := headerValueIssue(op.Value); issue != "" {
			return headerRule{}, E.New("operation ", i+1, ": ", issue)
		}
		switch op.Action {
		case OpAdd:
			if op.Value == "" {
				return headerRule{}, E.New("operation ", i+1, ": add needs a value")
			}
		case OpDelete, OpReplace:
		case OpReplaceRegex:
			if op.Regex == "" {
				return headerRule{}, E.New("operation ", i+1, ": replace-regex needs a regex")
			}
			if len(op.Regex) > maxPattern {
				return headerRule{}, E.New("operation ", i+1, ": regex too long")
			}
			compiled.re, err = regexp.Compile(op.Regex)
			if err != nil {
				return headerRule{}, E.Cause(err, "operation ", i+1, ": invalid regex")
			}
		case "":
			return headerRule{}, E.New("operation ", i+1, ": missing action")
		default:
			return headerRule{}, E.New("operation ", i+1, ": unknown action: ", op.Action)
		}
		r.ops = append(r.ops, compiled)
	}
	return r, nil
}

func compileMapLocal(ctx context.Context, id string, rule option.MITMMapLocalRule) (mapRule, error) {
	re, err := compilePattern(rule.Pattern)
	if err != nil {
		return mapRule{}, err
	}
	status := rule.Status
	if status == 0 {
		status = 200
	}
	if status < 200 || status > 599 {
		return mapRule{}, E.New("status must be between 200 and 599")
	}
	var headers []flow.Header
	hasType := false
	for i, field := range rule.Headers {
		if issue := headerNameIssue(field.Name); issue != "" {
			return mapRule{}, E.New("header ", i+1, ": ", issue)
		}
		if issue := headerValueIssue(field.Value); issue != "" {
			return mapRule{}, E.New("header ", i+1, ": ", issue)
		}
		if strings.EqualFold(field.Name, "Content-Type") {
			hasType = true
		}
		headers = append(headers, flow.Header{Name: field.Name, Value: field.Value})
	}
	var body []byte
	switch {
	case rule.BodyPath != "":
		if rule.Body != "" || rule.BodyBase64 != "" {
			return mapRule{}, E.New("body_path cannot be combined with body or body_base64")
		}
		body, err = readBodyFile(ctx, rule.BodyPath)
		if err != nil {
			return mapRule{}, err
		}
	case rule.BodyBase64 != "":
		if base64.StdEncoding.DecodedLen(len(rule.BodyBase64)) > MaxBody+2 {
			return mapRule{}, E.New("body exceeds ", MaxBody>>20, " MiB")
		}
		body, err = base64.StdEncoding.DecodeString(rule.BodyBase64)
		if err != nil {
			return mapRule{}, E.Cause(err, "invalid body_base64")
		}
	default:
		body = []byte(rule.Body)
	}
	if len(body) > MaxBody {
		return mapRule{}, E.New("body exceeds ", MaxBody>>20, " MiB")
	}
	if len(body) > 0 && (status == 204 || status == 205 || status == 304) {
		return mapRule{}, E.New("status ", status, " cannot have a body")
	}
	if !hasType {
		headers = append(headers, flow.Header{Name: "Content-Type", Value: "text/plain; charset=utf-8"})
	}
	local := newLocal(KindMapLocal, id, "", status, headers, body)
	return mapRule{id: id, re: re, local: local}, nil
}

func readBodyFile(ctx context.Context, path string) ([]byte, error) {
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		return nil, E.New("body_path must be relative")
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return nil, E.New("body_path must not contain ..")
		}
	}
	file, err := filemanager.OpenFile(ctx, path, os.O_RDONLY, 0)
	if err != nil {
		return nil, E.Cause(err, "read body_path")
	}
	defer file.Close()
	// Stat first so that an oversize file is never loaded; the limit also covers a file that
	// grows or reports no size.
	info, err := file.Stat()
	if err != nil {
		return nil, E.Cause(err, "read body_path")
	}
	if info.Size() > MaxBody {
		return nil, E.New("body exceeds ", MaxBody>>20, " MiB")
	}
	body, err := io.ReadAll(io.LimitReader(file, MaxBody+1))
	if err != nil {
		return nil, E.Cause(err, "read body_path")
	}
	return body, nil
}
