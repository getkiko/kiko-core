package rewrite

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/stretchr/testify/require"
)

func compile(t *testing.T, options option.MITMHTTPRewriteOptions) *Set {
	t.Helper()
	set, err := Compile(context.Background(), &options)
	require.NoError(t, err)
	return set
}

func urlSet(t *testing.T, rules ...option.MITMURLRewriteRule) *Set {
	return compile(t, option.MITMHTTPRewriteOptions{URL: rules})
}

func TestTinyGIF(t *testing.T) {
	require.Len(t, TinyGIF, 43)
	require.Equal(t, "GIF89a", string(TinyGIF[:6]))
	require.Equal(t, byte(0x3b), TinyGIF[42])
}

func TestURLActions(t *testing.T) {
	cases := []struct {
		action      string
		status      int
		contentType string
		body        []byte
		abort       bool
	}{
		{"reject", 0, "", nil, true},
		{"reject-200", 200, "text/plain", nil, false},
		{"reject-img", 200, "image/gif", TinyGIF, false},
		{"reject-tinygif", 200, "image/gif", TinyGIF, false},
		{"reject-dict", 200, "application/json", []byte("{}"), false},
		{"reject-array", 200, "application/json", []byte("[]"), false},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			set := urlSet(t, option.MITMURLRewriteRule{Pattern: `^https?://ads\.example\.com/`, Action: c.action})
			plan := set.Plan("https", "ads.example.com", "/x?y=1")
			require.NotNil(t, plan)
			local := plan.Local()
			require.NotNil(t, local)
			require.Equal(t, c.abort, local.Abort)
			require.Equal(t, c.status, local.Status)
			require.Equal(t, c.body, local.Body)
			require.Equal(t, "url", local.Hit.Kind)
			require.Equal(t, "url#1", local.Hit.Rule)
			require.Equal(t, c.action, local.Hit.Action)
			if c.abort {
				return
			}
			require.Equal(t, c.status, local.Hit.Status)
			var ct, cl string
			for _, h := range local.Headers {
				switch h.Name {
				case "Content-Type":
					ct = h.Value
				case "Content-Length":
					cl = h.Value
				}
			}
			require.Equal(t, c.contentType, ct)
			require.Equal(t, itoa(len(c.body)), cl)
			require.Nil(t, set.Plan("https", "other.example.com", "/"))
		})
	}
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string(appendInt(nil, n)))
}

func appendInt(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return append(b, d...)
}

func TestRedirectExpansion(t *testing.T) {
	set := urlSet(t,
		option.MITMURLRewriteRule{ID: "r1", Pattern: `^https://old\.example\.com/(\w+)/(?P<id>\d+)`, Action: "302", Target: "https://new.example.com/$1?id=${id}"},
		option.MITMURLRewriteRule{ID: "r2", Pattern: `^https://go\.example\.com/\?u=(.+)$`, Action: "307", Target: "$1"},
		option.MITMURLRewriteRule{ID: "r3", Pattern: `^https://fixed\.example\.com/`, Action: "307", Target: "http://t.example.com/a b"},
	)
	local := set.Plan("https", "old.example.com", "/page/42?x=1").Local()
	require.Equal(t, 302, local.Status)
	require.Equal(t, "https://new.example.com/page?id=42", local.Hit.Target)
	require.Equal(t, flow.Header{Name: "Location", Value: "https://new.example.com/page?id=42"}, local.Headers[0])
	require.Equal(t, "0", local.Headers[1].Value)

	local = set.Plan("https", "go.example.com", "/?u=https://dest.example.com/p").Local()
	require.Equal(t, 307, local.Status)
	require.Equal(t, "https://dest.example.com/p", local.Hit.Target)

	// a capture that is not an absolute http(s) URL falls through
	require.Nil(t, set.Plan("https", "go.example.com", "/?u=javascript:alert(1)"))
	// control characters in the expansion are refused
	require.Nil(t, set.Plan("https", "go.example.com", "/?u=https://x/%0d\r\nSet-Cookie:a"))
}

func TestURLFirstMatchWins(t *testing.T) {
	set := urlSet(t,
		option.MITMURLRewriteRule{ID: "a", Pattern: `example\.com/x`, Action: "reject-dict"},
		option.MITMURLRewriteRule{ID: "b", Pattern: `example\.com`, Action: "reject-array"},
	)
	require.Equal(t, "a", set.Plan("https", "example.com", "/x").Local().Hit.Rule)
	require.Equal(t, "b", set.Plan("https", "example.com", "/y").Local().Hit.Rule)
}

func TestOrderURLThenMapLocalThenHeaders(t *testing.T) {
	set := compile(t, option.MITMHTTPRewriteOptions{
		URL:      []option.MITMURLRewriteRule{{Pattern: `/u$`, Action: "reject-200"}},
		MapLocal: []option.MITMMapLocalRule{{Pattern: `/m$`, Body: "m"}, {Pattern: `/u$`, Body: "never"}},
		Headers: []option.MITMHeaderRewriteRule{
			{Pattern: `/h$`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-A", Value: "1"}}},
			{Pattern: `/h$`, Scope: "response", Operations: []option.MITMHeaderRewriteEdit{{Action: "delete", Name: "X-B"}}},
			{Pattern: `/m$`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-A", Value: "1"}}},
		},
	})
	require.Equal(t, "url#1", set.Plan("https", "a", "/u").Local().Hit.Rule)
	local := set.Plan("https", "a", "/m").Local()
	require.Equal(t, "map_local#1", local.Hit.Rule)
	require.False(t, set.Plan("https", "a", "/m").HasRequestEdits(), "local answers are final")
	plan := set.Plan("https", "a", "/h")
	require.Nil(t, plan.Local())
	require.True(t, plan.HasRequestEdits())
	require.True(t, plan.HasResponseEdits())
	require.Nil(t, set.Plan("https", "a", "/none"))
}

func hdrs(kv ...string) []flow.Header {
	var out []flow.Header
	for i := 0; i < len(kv); i += 2 {
		out = append(out, flow.Header{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func headerPlan(t *testing.T, scope string, ops ...option.MITMHeaderRewriteEdit) *Plan {
	set := compile(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{{Pattern: `.`, Scope: scope, Operations: ops}}})
	return set.Plan("https", "a.example.com", "/")
}

func TestHeaderOperations(t *testing.T) {
	type op = option.MITMHeaderRewriteEdit
	cases := []struct {
		name    string
		ops     []op
		in      []flow.Header
		out     []flow.Header
		changes []flow.RewriteChange
	}{
		{
			name:    "add",
			ops:     []op{{Action: "add", Name: "X-A", Value: "2"}},
			in:      hdrs("x-a", "1"),
			out:     hdrs("x-a", "1", "X-A", "2"),
			changes: []flow.RewriteChange{{Op: "add", Name: "X-A", Before: "1", HadBefore: true, After: "1, 2", HasAfter: true}},
		},
		{
			name:    "delete all, case-insensitive",
			ops:     []op{{Action: "delete", Name: "x-a"}},
			in:      hdrs("X-A", "1", "Keep", "k", "X-a", "2"),
			out:     hdrs("Keep", "k"),
			changes: []flow.RewriteChange{{Op: "delete", Name: "x-a", Before: "1, 2", HadBefore: true}},
		},
		{
			name: "delete absent",
			ops:  []op{{Action: "delete", Name: "X-Z"}},
			in:   hdrs("Keep", "k"),
		},
		{
			name:    "replace collapses duplicates",
			ops:     []op{{Action: "replace", Name: "X-A", Value: "n"}},
			in:      hdrs("a", "1", "X-a", "1", "b", "2", "X-A", "3"),
			out:     hdrs("a", "1", "X-a", "n", "b", "2"),
			changes: []flow.RewriteChange{{Op: "replace", Name: "X-A", Before: "1, 3", HadBefore: true, After: "n", HasAfter: true}},
		},
		{
			name:    "replace appends when absent",
			ops:     []op{{Action: "replace", Name: "X-A", Value: "n"}},
			in:      hdrs("a", "1"),
			out:     hdrs("a", "1", "X-A", "n"),
			changes: []flow.RewriteChange{{Op: "replace", Name: "X-A", After: "n", HasAfter: true}},
		},
		{
			name: "replace same value is no change",
			ops:  []op{{Action: "replace", Name: "X-A", Value: "n"}},
			in:   hdrs("x-a", "n"),
		},
		{
			name:    "replace-regex",
			ops:     []op{{Action: "replace-regex", Name: "user-agent", Regex: `Chrome/(\d+)`, Value: "Safari/$1"}},
			in:      hdrs("User-Agent", "Mozilla Chrome/120", "User-agent", "other"),
			out:     hdrs("User-Agent", "Mozilla Safari/120", "User-agent", "other"),
			changes: []flow.RewriteChange{{Op: "replace-regex", Name: "user-agent", Before: "Mozilla Chrome/120, other", HadBefore: true, After: "Mozilla Safari/120, other", HasAfter: true}},
		},
		{
			name: "replace-regex without match",
			ops:  []op{{Action: "replace-regex", Name: "X-A", Regex: `zzz`, Value: "y"}},
			in:   hdrs("X-A", "abc"),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := headerPlan(t, "request", c.ops...)
			orig := append([]flow.Header(nil), c.in...)
			out, hits := plan.ApplyRequest(c.in)
			require.Equal(t, orig, c.in, "input untouched")
			if c.changes == nil {
				require.Nil(t, hits)
				require.Equal(t, c.in, out)
				return
			}
			require.Equal(t, c.out, out)
			require.Len(t, hits, 1)
			require.Equal(t, "header", hits[0].Kind)
			require.Equal(t, "headers#1", hits[0].Rule)
			require.Equal(t, "request", hits[0].Side)
			require.Equal(t, c.changes, hits[0].Changes)
			require.Equal(t, c.ops[0].Action, hits[0].Action)
		})
	}
}

func TestHeaderResponseScopeAndMultipleOps(t *testing.T) {
	plan := headerPlan(t, "response",
		option.MITMHeaderRewriteEdit{Action: "delete", Name: "Server"},
		option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Via", Value: "p"})
	require.False(t, plan.HasRequestEdits())
	out, hits := plan.ApplyResponse(hdrs("Server", "nginx"))
	require.Equal(t, hdrs("X-Via", "p"), out)
	require.Len(t, hits, 1)
	require.Equal(t, "response", hits[0].Side)
	require.Equal(t, "edit", hits[0].Action)
	require.Len(t, hits[0].Changes, 2)
	out, hits = plan.ApplyRequest(hdrs("A", "b"))
	require.Equal(t, hdrs("A", "b"), out)
	require.Nil(t, hits)
}

func TestHeaderRulesApplyInOrder(t *testing.T) {
	set := compile(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		{ID: "1", Pattern: `.`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "replace", Name: "X", Value: "one"}}},
		{ID: "2", Pattern: `.`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "replace-regex", Name: "X", Regex: "one", Value: "two"}}},
	}})
	out, hits := set.Plan("https", "a", "/").ApplyRequest(hdrs("X", "0"))
	require.Equal(t, hdrs("X", "two"), out)
	require.Len(t, hits, 2)
	require.Equal(t, "1", hits[0].Rule)
	require.Equal(t, "2", hits[1].Rule)
}

func TestMapLocal(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "body.json"), []byte(`{"a":1}`), 0o644))
	ctx := filemanager.WithDefault(context.Background(), dir, dir, -1, -1)
	set, err := Compile(ctx, &option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{
		{ID: "text", Pattern: `/text$`, Status: 404, Body: "nope"},
		{ID: "b64", Pattern: `/b64$`, Body: "ignored", BodyBase64: base64.StdEncoding.EncodeToString([]byte{0, 1, 2}),
			Headers: []option.MITMHeaderRewriteField{{Name: "content-type", Value: "application/octet-stream"}}},
		{ID: "path", Pattern: `/path$`, BodyPath: "body.json", Headers: []option.MITMHeaderRewriteField{{Name: "X-Y", Value: "z"}}},
		{ID: "none", Pattern: `/none$`, Status: 204},
	}})
	require.NoError(t, err)

	local := set.Plan("https", "a", "/text").Local()
	require.Equal(t, 404, local.Status)
	require.Equal(t, []byte("nope"), local.Body)
	require.Equal(t, hdrs("Content-Type", "text/plain; charset=utf-8", "Content-Length", "4"), local.Headers)
	require.Equal(t, flow.RewriteHit{Kind: "map_local", Rule: "text", Status: 404}, local.Hit)

	local = set.Plan("https", "a", "/b64").Local()
	require.Equal(t, 200, local.Status)
	require.Equal(t, []byte{0, 1, 2}, local.Body)
	require.Equal(t, hdrs("content-type", "application/octet-stream", "Content-Length", "3"), local.Headers)

	local = set.Plan("https", "a", "/path").Local()
	require.Equal(t, []byte(`{"a":1}`), local.Body)
	require.Equal(t, hdrs("X-Y", "z", "Content-Type", "text/plain; charset=utf-8", "Content-Length", "7"), local.Headers)

	local = set.Plan("https", "a", "/none").Local()
	require.Equal(t, 204, local.Status)
	require.Empty(t, local.Body)
}

func TestMapLocalErrors(t *testing.T) {
	big := strings.Repeat("a", MaxBody+1)
	cases := []struct {
		name string
		rule option.MITMMapLocalRule
		want string
	}{
		{"status low", option.MITMMapLocalRule{Pattern: `.`, Status: 100}, "status"},
		{"status high", option.MITMMapLocalRule{Pattern: `.`, Status: 600}, "status"},
		{"bad base64", option.MITMMapLocalRule{Pattern: `.`, BodyBase64: "***"}, "body_base64"},
		{"too big", option.MITMMapLocalRule{Pattern: `.`, Body: big}, "exceeds"},
		{"path and body", option.MITMMapLocalRule{Pattern: `.`, Body: "x", BodyPath: "a"}, "body_path"},
		{"absolute path", option.MITMMapLocalRule{Pattern: `.`, BodyPath: "/etc/passwd"}, "relative"},
		{"dotdot", option.MITMMapLocalRule{Pattern: `.`, BodyPath: "a/../../b"}, ".."},
		{"missing file", option.MITMMapLocalRule{Pattern: `.`, BodyPath: "nope.bin"}, "body_path"},
		{"204 body", option.MITMMapLocalRule{Pattern: `.`, Status: 204, Body: "x"}, "cannot have a body"},
		{"reserved header", option.MITMMapLocalRule{Pattern: `.`, Headers: []option.MITMHeaderRewriteField{{Name: "Content-Length", Value: "1"}}}, "Content-Length"},
		{"bad value", option.MITMMapLocalRule{Pattern: `.`, Headers: []option.MITMHeaderRewriteField{{Name: "X", Value: "a\r\nb"}}}, "line break"},
		{"bad pattern", option.MITMMapLocalRule{Pattern: `(`}, "pattern"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := filemanager.WithDefault(context.Background(), t.TempDir(), t.TempDir(), -1, -1)
			_, err := Compile(ctx, &option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{{Pattern: `.`}, c.rule}})
			require.Error(t, err)
			require.Contains(t, err.Error(), c.want)
			require.Contains(t, err.Error(), "map_local#2")
		})
	}
}

func TestMapLocalTotalLimit(t *testing.T) {
	body := strings.Repeat("a", MaxBody)
	var rules []option.MITMMapLocalRule
	for i := 0; i < 5; i++ {
		rules = append(rules, option.MITMMapLocalRule{Pattern: `.`, Body: body})
	}
	_, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{MapLocal: rules[:4]})
	require.NoError(t, err)
	_, err = Compile(context.Background(), &option.MITMHTTPRewriteOptions{MapLocal: rules})
	require.ErrorContains(t, err, "map_local#5")
	require.ErrorContains(t, err, "in total")
}

func TestValidationErrors(t *testing.T) {
	type edit = option.MITMHeaderRewriteEdit
	hdr := func(scope string, ops ...edit) option.MITMHeaderRewriteRule {
		return option.MITMHeaderRewriteRule{Pattern: `.`, Scope: scope, Operations: ops}
	}
	cases := []struct {
		name    string
		options option.MITMHTTPRewriteOptions
		want    []string
	}{
		{"url bad pattern", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: `.`, Action: "reject"}, {Pattern: `a(`, Action: "reject"}}}, []string{"url#2", "pattern"}},
		{"url empty pattern", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: ``, Action: "reject"}}}, []string{"url#1", "missing pattern"}},
		{"url unknown action", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{ID: "x", Pattern: `.`, Action: "boom"}}}, []string{"url x", "unknown action"}},
		{"url no action", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: `.`}}}, []string{"missing action"}},
		{"redirect no target", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: `.`, Action: "302"}}}, []string{"missing target"}},
		{"redirect relative target", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: `.`, Action: "302", Target: "/x"}}}, []string{"absolute"}},
		{"redirect ftp target", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: `.`, Action: "307", Target: "ftp://x/"}}}, []string{"absolute"}},
		{"redirect newline", option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{Pattern: `.`, Action: "307", Target: "https://x/\nA: b"}}}, []string{"invalid target"}},
		{"header bad scope", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("both", edit{Action: "delete", Name: "A"})}}, []string{"headers#1", "unknown scope"}},
		{"header no scope", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("", edit{Action: "delete", Name: "A"})}}, []string{"missing scope"}},
		{"header no ops", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request")}}, []string{"no operations"}},
		{"header unknown op", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "delete", Name: "A"}, edit{Action: "prepend", Name: "A"})}}, []string{"operation 2", "unknown action"}},
		{"add without value", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "add", Name: "A"})}}, []string{"needs a value"}},
		{"regex missing", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "replace-regex", Name: "A"})}}, []string{"needs a regex"}},
		{"regex invalid", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "replace-regex", Name: "A", Regex: "("})}}, []string{"invalid regex"}},
		{"bad name", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "delete", Name: "A B"})}}, []string{"invalid header name"}},
		{"colon name", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "delete", Name: ":path"})}}, []string{"invalid header name"}},
		{"empty name", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "delete"})}}, []string{"empty header name"}},
		{"value newline", option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{hdr("request", edit{Action: "add", Name: "A", Value: "x\r\ny"})}}, []string{"line break"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := Compile(context.Background(), &c.options)
			require.Error(t, err)
			require.Nil(t, set)
			for _, want := range c.want {
				require.Contains(t, err.Error(), want)
			}
		})
	}
	for _, name := range []string{"Content_Length", "Transfer_Encoding", "Expect", "EXPECT", "Keep_Alive"} {
		_, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
			hdr("request", edit{Action: "add", Name: name, Value: "x"})}})
		require.ErrorContains(t, err, "cannot be rewritten", name)
	}
	for name := range reservedHeaders {
		_, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
			hdr("request", edit{Action: "replace", Name: strings.ToUpper(name), Value: "x"})}})
		require.ErrorContains(t, err, "cannot be rewritten", name)
	}
}

func TestEmptyAndNil(t *testing.T) {
	var nilSet *Set
	require.True(t, nilSet.Empty())
	require.Nil(t, nilSet.Plan("https", "a", "/"))
	require.False(t, nilSet.AppliesToPlain())
	_, ok := nilSet.HostReject("a")
	require.False(t, ok)
	set, err := Compile(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, set.Empty())
	require.Nil(t, set.Plan("https", "a", "/"))
	var plan *Plan
	require.Nil(t, plan.Local())
	out, hits := plan.ApplyRequest(hdrs("a", "b"))
	require.Equal(t, hdrs("a", "b"), out)
	require.Nil(t, hits)
}

func TestAppliesToPlain(t *testing.T) {
	cases := []struct {
		pattern string
		plain   bool
	}{
		{`^https://ads\.example\.com/`, false},
		{`^https://`, false},
		{`^https?://ads\.example\.com/`, true},
		{`^http://ads\.example\.com/`, true},
		{`ads\.example\.com`, true},
		{`https://ads\.example\.com/`, true}, // unanchored: may match inside an http URL
		{`(?i)^https://a`, true},             // folded: no literal prefix
		{`^(https|http)://a`, true},
		{`a$`, true},
	}
	for _, c := range cases {
		set := urlSet(t, option.MITMURLRewriteRule{Pattern: c.pattern, Action: "reject"})
		require.Equal(t, c.plain, set.AppliesToPlain(), c.pattern)
	}
	set := urlSet(t,
		option.MITMURLRewriteRule{Pattern: `^https://a/`, Action: "reject"},
		option.MITMURLRewriteRule{Pattern: `^https://b/`, Action: "reject"})
	require.False(t, set.AppliesToPlain())
	set = compile(t, option.MITMHTTPRewriteOptions{
		URL:     []option.MITMURLRewriteRule{{Pattern: `^https://a/`, Action: "reject"}},
		Headers: []option.MITMHeaderRewriteRule{{Pattern: `^http://b/`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "delete", Name: "A"}}}},
	})
	require.True(t, set.AppliesToPlain())
	set = compile(t, option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{{Pattern: `^http://b/`}}})
	require.True(t, set.AppliesToPlain())
}

func TestHostReject(t *testing.T) {
	set := urlSet(t,
		option.MITMURLRewriteRule{ID: "path", Pattern: `^https://ads\.example\.com/banner/`, Action: "reject"},
		option.MITMURLRewriteRule{ID: "only-root", Pattern: `^https://root\.example\.com/$`, Action: "reject"},
		option.MITMURLRewriteRule{ID: "host", Pattern: `^https?://([a-z]+\.)?tracker\.example\.net(:\d+)?/`, Action: "reject"},
		option.MITMURLRewriteRule{ID: "redirect", Pattern: `^https://moved\.example\.org/`, Action: "302", Target: "https://x.example.org/"},
		option.MITMURLRewriteRule{ID: "shadowed", Pattern: `^https://moved\.example\.org/`, Action: "reject"},
		option.MITMURLRewriteRule{ID: "img", Pattern: `^https://img\.example\.io/`, Action: "reject-img"},
	)
	for host, want := range map[string]string{
		"tracker.example.net":     "host",
		"www.tracker.example.net": "host",
	} {
		id, ok := set.HostReject(host)
		require.True(t, ok, host)
		require.Equal(t, want, id, host)
	}
	for _, host := range []string{"ads.example.com", "root.example.com", "moved.example.org", "img.example.io", "other.example", ""} {
		_, ok := set.HostReject(host)
		require.False(t, ok, host)
	}
	only := urlSet(t, option.MITMURLRewriteRule{Pattern: `^https://a/`, Action: "reject-200"})
	_, ok := only.HostReject("a")
	require.False(t, ok)

	// The plain case: a single reject anchored on the host, other hosts' rules before it.
	plain := urlSet(t,
		option.MITMURLRewriteRule{ID: "other", Pattern: `^https://other\.com/`, Action: "302", Target: "https://x/"},
		option.MITMURLRewriteRule{ID: "unanchored", Pattern: `bad\.example\.io`, Action: "reject"},
	)
	id, ok := plain.HostReject("bad.example.io")
	require.True(t, ok)
	require.Equal(t, "unanchored", id)
	id, ok = urlSet(t, option.MITMURLRewriteRule{ID: "r", Pattern: `^https://example\.com/`, Action: "reject"}).HostReject("example.com")
	require.True(t, ok)
	require.Equal(t, "r", id)

	// First-match order: an earlier rule that could match some URL of the host keeps the
	// decision with the request-level engine.
	for name, rules := range map[string][]option.MITMURLRewriteRule{
		"narrower first": {
			{ID: "api", Pattern: `^https://example\.com/api/`, Action: "reject-dict"},
			{ID: "all", Pattern: `^https://example\.com/`, Action: "reject"},
		},
		"unanchored earlier": {
			{ID: "js", Pattern: `\.js$`, Action: "reject-200"},
			{ID: "all", Pattern: `^https://example\.com/`, Action: "reject"},
		},
		"alternation earlier": {
			{ID: "alt", Pattern: `^https?://(www\.)?example\.com/x`, Action: "302", Target: "https://y/"},
			{ID: "all", Pattern: `^https://example\.com/`, Action: "reject"},
		},
	} {
		_, ok = urlSet(t, rules...).HostReject("example.com")
		require.False(t, ok, name)
	}
}

func TestIDsByPosition(t *testing.T) {
	set := compile(t, option.MITMHTTPRewriteOptions{
		URL:      []option.MITMURLRewriteRule{{ID: "keep", Pattern: `/a`, Action: "reject"}, {Pattern: `/b`, Action: "reject"}},
		MapLocal: []option.MITMMapLocalRule{{Pattern: `/c`}},
		Headers:  []option.MITMHeaderRewriteRule{{Pattern: `/d`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "A", Value: "b"}}}},
	})
	require.Equal(t, "keep", set.Plan("https", "h", "/a").Local().Hit.Rule)
	require.Equal(t, "url#2", set.Plan("https", "h", "/b").Local().Hit.Rule)
	require.Equal(t, "map_local#1", set.Plan("https", "h", "/c").Local().Hit.Rule)
	_, hits := set.Plan("https", "h", "/d").ApplyRequest(nil)
	require.Equal(t, "headers#1", hits[0].Rule)
}

func TestMatchesURLShape(t *testing.T) {
	set := urlSet(t, option.MITMURLRewriteRule{Pattern: `^http://h:8080/p\?q=1$`, Action: "reject"})
	require.NotNil(t, set.Plan("http", "h:8080", "/p?q=1"))
	require.Nil(t, set.Plan("https", "h:8080", "/p?q=1"))
	require.Nil(t, set.Plan("http", "h", "/p?q=1"))
}

func TestZeroAllocMiss(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool is randomized under the race detector")
	}
	set := compile(t, option.MITMHTTPRewriteOptions{
		URL:      []option.MITMURLRewriteRule{{Pattern: `^https://ads\.example\.com/`, Action: "reject"}, {Pattern: `track(er)?\.`, Action: "302", Target: "https://x/"}},
		MapLocal: []option.MITMMapLocalRule{{Pattern: `/mock/(\d+)`, Body: "x"}},
		Headers:  []option.MITMHeaderRewriteRule{{Pattern: `^https://api\.example\.com/`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "A", Value: "b"}}}},
	})
	path := "/some/long/path/with/query?a=1&b=2&c=" + strings.Repeat("x", 300)
	require.Nil(t, set.Plan("https", "www.example.org", path))
	allocs := testing.AllocsPerRun(200, func() {
		if set.Plan("https", "www.example.org", path) != nil {
			panic("unexpected match")
		}
	})
	require.Zero(t, allocs)
	allocs = testing.AllocsPerRun(200, func() {
		if _, ok := set.HostReject("www.example.org"); ok {
			panic("unexpected match")
		}
	})
	require.Zero(t, allocs)
}

func TestConcurrentPlans(t *testing.T) {
	set := compile(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `^https://r\.example\.com/(\d+)`, Action: "302", Target: "https://t.example.com/$1"}},
		Headers: []option.MITMHeaderRewriteRule{
			{Pattern: `^https://h\.example\.com/`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "replace", Name: "X", Value: "1"}}},
			{Pattern: `^https://h\.example\.com/`, Scope: "response", Operations: []option.MITMHeaderRewriteEdit{{Action: "delete", Name: "Server"}}},
		},
	})
	shared := hdrs("x", "0", "Server", "s")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				plan := set.Plan("https", "r.example.com", "/"+itoa(i*1000+j))
				if plan.Local().Hit.Target != "https://t.example.com/"+itoa(i*1000+j) {
					panic("wrong redirect")
				}
				plan = set.Plan("https", "h.example.com", "/")
				out, _ := plan.ApplyRequest(shared)
				if out[0].Value != "1" {
					panic("not applied")
				}
				out, _ = plan.ApplyResponse(shared)
				if len(out) != 1 {
					panic("not applied")
				}
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, hdrs("x", "0", "Server", "s"), shared)
}

func FuzzPlan(f *testing.F) {
	set, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{
			{Pattern: `^https?://([^/]+)/r/(.*)$`, Action: "302", Target: "https://$1/$2"},
			{Pattern: `ads`, Action: "reject-img"},
		},
		MapLocal: []option.MITMMapLocalRule{{Pattern: `/m`, Body: "x"}},
		Headers: []option.MITMHeaderRewriteRule{
			{Pattern: `.`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{
				{Action: "replace", Name: "X-A", Value: "1"},
				{Action: "replace-regex", Name: "x-b", Regex: `(\w)(\w*)`, Value: "$2$1"},
				{Action: "delete", Name: "X-C"},
				{Action: "add", Name: "X-D", Value: "d"},
			}},
		},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("https", "a.com", "/r/x?y=1", "X-A", "v", "x-b", "hello")
	f.Add("http", "b.com:80", "/m", "X-C", "", "X-C", "z")
	f.Add("https", "", "", "", "", "", "")
	f.Fuzz(func(t *testing.T, scheme, authority, target, n1, v1, n2, v2 string) {
		headers := []flow.Header{{Name: n1, Value: v1}, {Name: n2, Value: v2}}
		orig := append([]flow.Header(nil), headers...)
		plan := set.Plan(scheme, authority, target)
		if plan == nil {
			return
		}
		if local := plan.Local(); local != nil {
			if !local.Abort && local.Status == 0 {
				t.Fatalf("local response without status: %+v", local)
			}
			if strings.ContainsAny(local.Hit.Target, "\r\n") {
				t.Fatalf("control characters in location %q", local.Hit.Target)
			}
			return
		}
		out, _ := plan.ApplyRequest(headers)
		if len(out) > 0 && len(headers) > 0 && &out[0] == &headers[0] && len(out) != len(headers) {
			t.Fatal("aliasing")
		}
		for i := range orig {
			if headers[i] != orig[i] {
				t.Fatalf("input modified: %v -> %v", orig, headers)
			}
		}
	})
}

func TestBodyPathOversize(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, MaxBody+1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.bin"), big, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.bin"), big[:MaxBody], 0o644))
	ctx := filemanager.WithDefault(context.Background(), dir, dir, -1, -1)
	_, err := Compile(ctx, &option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{{Pattern: `.`, BodyPath: "big.bin"}}})
	require.ErrorContains(t, err, "exceeds")
	set, err := Compile(ctx, &option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{{Pattern: `.`, BodyPath: "ok.bin"}}})
	require.NoError(t, err)
	require.Len(t, set.Plan("https", "a", "/").Local().Body, MaxBody)
}

func FuzzCompile(f *testing.F) {
	f.Add("^https://a/", "reject", "", "request", "add", "X-A", "v", "", "x")
	f.Add(`^https?://([^/]+)/(.*)$`, "302", "https://$1/$2", "response", "replace-regex", "x-b", "$1", `(\w+)`, "")
	f.Add("(", "bogus", "\r\n", "both", "nope", "Content_Length", "\x00", "[", "")
	f.Fuzz(func(t *testing.T, pattern, action, target, scope, op, name, value, regex, body string) {
		options := &option.MITMHTTPRewriteOptions{
			URL:      []option.MITMURLRewriteRule{{Pattern: pattern, Action: action, Target: target}},
			MapLocal: []option.MITMMapLocalRule{{Pattern: pattern, Body: body, Headers: []option.MITMHeaderRewriteField{{Name: name, Value: value}}}},
			Headers: []option.MITMHeaderRewriteRule{{Pattern: pattern, Scope: scope, Operations: []option.MITMHeaderRewriteEdit{
				{Action: op, Name: name, Value: value, Regex: regex}}}},
		}
		set, err := Compile(context.Background(), options)
		if err != nil {
			return
		}
		set.HostReject("a.com")
		set.AppliesToPlain()
		if plan := set.Plan("https", "a.com", "/p?q=1"); plan != nil {
			_, _ = plan.ApplyRequest([]flow.Header{{Name: name, Value: value}})
			_ = plan.Local()
		}
	})
}

func TestControlCharsRejected(t *testing.T) {
	type edit = option.MITMHeaderRewriteEdit
	hdr := func(scope string, ops ...edit) option.MITMHeaderRewriteRule {
		return option.MITMHeaderRewriteRule{Pattern: `.`, Scope: scope, Operations: ops}
	}
	for _, value := range []string{"a\x01b", "a\x7fb", "a\x1fb", "a\x00b", "a\rb"} {
		_, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
			hdr("request", edit{Action: "add", Name: "X-A", Value: value})}})
		require.Error(t, err, "%q", value)
		_, err = Compile(context.Background(), &option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{
			{Pattern: `.`, Headers: []option.MITMHeaderRewriteField{{Name: "X-A", Value: value}}}}})
		require.Error(t, err, "%q", value)
	}
	_, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		hdr("request", edit{Action: "add", Name: "X-A", Value: "a\tb \xc3\xa9"})}})
	require.NoError(t, err)
}

func TestChangeValuesClipped(t *testing.T) {
	set := compile(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{{Pattern: `.`, Scope: "request",
		Operations: []option.MITMHeaderRewriteEdit{{Action: "replace", Name: "X-A", Value: strings.Repeat("n", 5000)}}}}})
	_, hits := set.Plan("https", "a", "/").ApplyRequest(hdrs("X-A", strings.Repeat("o", 5000)))
	change := hits[0].Changes[0]
	require.Len(t, change.Before, 1<<10)
	require.Len(t, change.After, 1<<10)
}
