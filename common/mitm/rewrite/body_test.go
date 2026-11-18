package rewrite

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
)

func jsonEdit(t *testing.T, src, action, path, value string) (string, int) {
	t.Helper()
	p, err := parseJSONPath(path)
	if err != nil {
		t.Fatalf("path %q: %v", path, err)
	}
	doc, ok := newJSONDoc([]byte(src))
	if !ok {
		t.Fatalf("source %q does not parse", src)
	}
	var n int
	switch action {
	case EditJSONSet:
		n = doc.set(p, []byte(value))
	case EditJSONDelete:
		n = doc.remove(p)
	case EditJSONAppend:
		n = doc.appendTo(p, []byte(value))
	}
	out, ok := doc.bytes(1 << 30)
	if !ok {
		t.Fatal("limit")
	}
	return string(out), n
}

func TestJSONEdits(t *testing.T) {
	tests := []struct {
		name, src, action, path, value, want string
		count                                int
	}{
		{"set existing", `{"a":1,"b":2}`, EditJSONSet, "$.a", `"x"`, `{"a":"x","b":2}`, 1},
		{"set adds missing key", `{"a":1}`, EditJSONSet, "$.b", `true`, `{"a":1,"b":true}`, 1},
		{"set nested add", `{"o":{"k":1}}`, EditJSONSet, "$.o.n", `[1]`, `{"o":{"k":1,"n":[1]}}`, 1},
		{"set missing parent is no change", `{"a":1}`, EditJSONSet, "$.x.y", `1`, `{"a":1}`, 0},
		{"set index", `[1,2,3]`, EditJSONSet, "$[1]", `9`, `[1,9,3]`, 1},
		{"set negative index", `[1,2,3]`, EditJSONSet, "$[-1]", `9`, `[1,2,9]`, 1},
		{"set out of range", `[1,2,3]`, EditJSONSet, "$[3]", `9`, `[1,2,3]`, 0},
		{"set wildcard", `{"l":[{"p":1},{"p":2}]}`, EditJSONSet, "$.l[*].p", `0`, `{"l":[{"p":0},{"p":0}]}`, 2},
		{"set recursive", `{"a":{"id":1,"b":[{"id":2}]},"id":3}`, EditJSONSet, "$..id", `0`, `{"a":{"id":0,"b":[{"id":0}]},"id":0}`, 3},
		{"set union names", `{"a":1,"b":2,"c":3}`, EditJSONSet, "$['a','c']", `0`, `{"a":0,"b":2,"c":0}`, 2},
		{"set bracket key with dot", `{"a.b":1}`, EditJSONSet, "$['a.b']", `2`, `{"a.b":2}`, 1},
		{"set same scalar is no change", `{"a": 1}`, EditJSONSet, "$.a", `1`, `{"a": 1}`, 0},
		{"set root", ` {"a":1} `, EditJSONSet, "$", `[]`, ` [] `, 1},
		{"set keeps number text", `{"n":12345678901234567890123,"f":1.0E+400,"z":-0.10,"s":"é\/"}`, EditJSONSet, "$.t", `1`, `{"n":12345678901234567890123,"f":1.0E+400,"z":-0.10,"s":"é\/","t":1}`, 1},
		{"set keeps key order and untouched whitespace", "{\"z\": 1,\n \"a\": {\"k\":  2}}", EditJSONSet, "$.z", `3`, `{"z":3,"a":{"k":  2}}`, 1},
		{"set escaped key", `{"ab":1}`, EditJSONSet, "$.ab", `2`, `{"ab":2}`, 1},
		{"set duplicate keys", `{"a":1,"a":2}`, EditJSONSet, "$.a", `0`, `{"a":0,"a":0}`, 2},
		{"delete key", `{"a":1,"b":2}`, EditJSONDelete, "$.a", ``, `{"b":2}`, 1},
		{"delete index", `[1,2,3]`, EditJSONDelete, "$[0]", ``, `[2,3]`, 1},
		{"delete several indexes", `[0,1,2,3,4]`, EditJSONDelete, "$[0,2,-1]", ``, `[1,3]`, 3},
		{"delete duplicate union index once", `[0,1,2]`, EditJSONDelete, "$[1,1]", ``, `[0,2]`, 1},
		{"delete wildcard", `{"a":[1,2],"b":3}`, EditJSONDelete, "$.a[*]", ``, `{"a":[],"b":3}`, 2},
		{"delete recursive", `{"ad":1,"x":{"ad":2,"k":3},"l":[{"ad":4}]}`, EditJSONDelete, "$..ad", ``, `{"x":{"k":3},"l":[{}]}`, 3},
		{"delete root is ignored", `{"a":1}`, EditJSONDelete, "$", ``, `{"a":1}`, 0},
		{"delete missing", `{"a":1}`, EditJSONDelete, "$.b", ``, `{"a":1}`, 0},
		{"append", `{"l":[1]}`, EditJSONAppend, "$.l", `{"x":1}`, `{"l":[1,{"x":1}]}`, 1},
		{"append to empty array", `[]`, EditJSONAppend, "$", `1`, `[1]`, 1},
		{"append to non array", `{"l":1}`, EditJSONAppend, "$.l", `2`, `{"l":1}`, 0},
		{"append to many", `{"a":[],"b":[]}`, EditJSONAppend, "$.*", `0`, `{"a":[0],"b":[0]}`, 2},
		{"non json source parse failure handled elsewhere", `[1,2]`, EditJSONSet, "$[0]", `"a\"b"`, `["a\"b",2]`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n := jsonEdit(t, tt.src, tt.action, tt.path, tt.value)
			if got != tt.want || n != tt.count {
				t.Fatalf("got %s (%d), want %s (%d)", got, n, tt.want, tt.count)
			}
			if n > 0 && !json.Valid([]byte(got)) {
				t.Fatalf("invalid output %s", got)
			}
		})
	}
}

func TestJSONParseRejects(t *testing.T) {
	for _, src := range []string{``, `{`, `{"a":}`, `[1,]`, `{"a":1,}`, `01`, `1.`, `-`, `"\x"`, "\"a\nb\"", `{"a" 1}`, `[1 2]`, `tru`, `{}x`, `{1:2}`, `"\u12"`} {
		if _, ok := newJSONDoc([]byte(src)); ok {
			t.Errorf("accepted %q", src)
		}
	}
	deep := strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1)
	if _, ok := newJSONDoc([]byte(deep)); ok {
		t.Error("accepted over-deep document")
	}
	ok128 := strings.Repeat("[", maxJSONDepth) + strings.Repeat("]", maxJSONDepth)
	if _, ok := newJSONDoc([]byte(ok128)); !ok {
		t.Error("rejected document at the depth limit")
	}
	wide := "[" + strings.Repeat("1,", maxJSONNodes) + "1]"
	if _, ok := newJSONDoc([]byte(wide)); ok {
		t.Error("accepted over-large document")
	}
}

func TestJSONPathParse(t *testing.T) {
	good := []string{"$", "$.a", "$.a.b", "$['a']", `$["a"]`, "$[0]", "$[-1]", "$[*]", "$.*", "$..a", "$..['a']", "$[0,1]", "$['a','b']", "$.a[0].b[*]", "$['a\\'b']", "$[ 1 , 2 ]"}
	bad := []string{"", "a", "$.", "$..", "$[", "$[]", "$[?(@.a)]", "$[1:2]", "$[0,'a']", "$[*,1]", "$.a b", "$[abc]", "$.a[", "$x", "$['a'", "$..[0]", "$..*"}
	for _, s := range good {
		if _, err := parseJSONPath(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := parseJSONPath(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := parseJSONPath("$" + strings.Repeat(".a", maxPathSegments+1)); err == nil {
		t.Error("accepted too many segments")
	}
}

func bodyOptions(rules ...option.MITMBodyRewriteRule) *option.MITMHTTPRewriteOptions {
	return &option.MITMHTTPRewriteOptions{Body: rules}
}

func mustCompile(t *testing.T, options *option.MITMHTTPRewriteOptions) *Set {
	t.Helper()
	set, err := Compile(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestCompileBodyValidation(t *testing.T) {
	edit := option.MITMBodyRewriteEdit{Action: EditReplaceRegex, Regex: "a", Value: "b"}
	many := make([]option.MITMBodyRewriteEdit, maxEdits+1)
	for i := range many {
		many[i] = edit
	}
	tests := []struct {
		name string
		rule option.MITMBodyRewriteRule
		want string
	}{
		{"ok", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{edit}}, ""},
		{"no pattern", option.MITMBodyRewriteRule{Scope: "response", Edits: []option.MITMBodyRewriteEdit{edit}}, "missing pattern"},
		{"bad pattern", option.MITMBodyRewriteRule{Pattern: "(", Scope: "response", Edits: []option.MITMBodyRewriteEdit{edit}}, "invalid pattern"},
		{"bad scope", option.MITMBodyRewriteRule{Pattern: "x", Scope: "both", Edits: []option.MITMBodyRewriteEdit{edit}}, "unknown scope"},
		{"missing scope", option.MITMBodyRewriteRule{Pattern: "x", Edits: []option.MITMBodyRewriteEdit{edit}}, "missing scope"},
		{"no edits", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response"}, "no edits"},
		{"too many edits", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: many}, "too many edits"},
		{"bad regex", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditReplaceRegex, Regex: "("}}}, "invalid regex"},
		{"empty regex", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditReplaceRegex}}}, "needs a regex"},
		{"long regex", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditReplaceRegex, Regex: strings.Repeat("a", maxPattern+1)}}}, "regex too long"},
		{"long value", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditReplaceRegex, Regex: "a", Value: strings.Repeat("a", maxValue+1)}}}, "value too long"},
		{"bad path", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONDelete, Path: "$[?(@.a)]"}}}, "invalid path"},
		{"missing path", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONDelete}}}, "needs a path"},
		{"bad json value", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONSet, Path: "$.a", Value: "{bad"}}}, "not valid JSON"},
		{"empty json value", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONAppend, Path: "$.a"}}}, "not valid JSON"},
		{"unknown action", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: "zap"}}}, "unknown action"},
		{"missing action", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{}}}, "missing action"},
		{"empty content type", option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", ContentTypes: []string{" "}, Edits: []option.MITMBodyRewriteEdit{edit}}, "invalid content type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(context.Background(), bodyOptions(tt.rule))
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "body#1") {
				t.Fatalf("error does not name the rule: %v", err)
			}
		})
	}
}

func TestMaxBodySize(t *testing.T) {
	if got := mustCompile(t, &option.MITMHTTPRewriteOptions{}).MaxBodySize(); got != DefaultMaxBodySize {
		t.Fatalf("default %d", got)
	}
	var nilSet *Set
	if nilSet.MaxBodySize() != DefaultMaxBodySize {
		t.Fatal("nil set default")
	}
	size := memBytes(t, "4MB")
	if got := mustCompile(t, &option.MITMHTTPRewriteOptions{MaxBodySize: size}).MaxBodySize(); got != 4<<20 {
		t.Fatalf("got %d", got)
	}
	for _, text := range []string{"512B", "64MB"} {
		if _, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{MaxBodySize: memBytes(t, text)}); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
}

func memBytes(t *testing.T, text string) *byteformats.MemoryBytes {
	t.Helper()
	var value byteformats.MemoryBytes
	if err := json.Unmarshal([]byte(`"`+text+`"`), &value); err != nil {
		t.Fatal(err)
	}
	return &value
}

func regexRule(pattern, scope, regex, value string, types ...string) option.MITMBodyRewriteRule {
	return option.MITMBodyRewriteRule{Pattern: pattern, Scope: scope, ContentTypes: types, Edits: []option.MITMBodyRewriteEdit{{Action: EditReplaceRegex, Regex: regex, Value: value}}}
}

func TestBodyPlanAndContentTypes(t *testing.T) {
	set := mustCompile(t, bodyOptions(
		regexRule(`^https://a\.test/`, "response", "x", "y"),
		option.MITMBodyRewriteRule{Pattern: `^https://a\.test/`, Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONDelete, Path: "$.k"}}},
		regexRule(`^https://a\.test/`, "request", "x", "y", "Octet"),
	))
	if set.Plan("https", "b.test", "/") != nil {
		t.Fatal("matched the wrong host")
	}
	plan := set.Plan("https", "a.test", "/p")
	if plan == nil {
		t.Fatal("no plan")
	}
	cases := []struct {
		scope, ct string
		want      bool
	}{
		{"response", "text/html; charset=utf-8", true},
		{"response", "TEXT/PLAIN", true},
		{"response", "application/json", true},
		{"response", "application/vnd.api+json", true},
		{"response", "application/xml", true},
		{"response", "application/javascript", true},
		{"response", "application/x-www-form-urlencoded", true},
		{"response", "image/png", false},
		{"response", "", false},
		{"request", "application/octet-stream", true},
		{"request", "application/json", false},
		{"request", "", false},
	}
	for _, c := range cases {
		if got := plan.NeedsBody(c.scope, c.ct); got != c.want {
			t.Errorf("NeedsBody(%s, %q) = %v", c.scope, c.ct, got)
		}
	}
	if !plan.HasBodyRules("request") || !plan.HasBodyRules("response") {
		t.Error("HasBodyRules")
	}
	var nilPlan *Plan
	if nilPlan.NeedsBody("response", "text/plain") || nilPlan.HasBodyRules("response") {
		t.Error("nil plan")
	}
	hits := plan.SkipHits("response", "application/json", SkipStream)
	if len(hits) != 2 || hits[0].Kind != KindBody || hits[0].Action != ActionSkipped || hits[0].Target != SkipStream || hits[0].Side != "response" {
		t.Fatalf("skip hits %+v", hits)
	}
}

func TestJSONEditOnlyAppliesToJSONTypes(t *testing.T) {
	set := mustCompile(t, bodyOptions(option.MITMBodyRewriteRule{Pattern: ".", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONDelete, Path: "$.a"}}}))
	plan := set.Plan("https", "h", "/")
	if plan.NeedsBody("response", "text/html") {
		t.Fatal("json edit selected html")
	}
	res := plan.ApplyBody("response", "text/html", "", []byte(`{"a":1}`), 0)
	if res.Changed || len(res.Hits) != 0 {
		t.Fatalf("%+v", res)
	}
}

func applyOne(t *testing.T, rule option.MITMBodyRewriteRule, ct, encoding string, data []byte, max int64) BodyResult {
	t.Helper()
	set := mustCompile(t, bodyOptions(rule))
	plan := set.Plan("https", "h.test", "/")
	if plan == nil {
		t.Fatal("no plan")
	}
	return plan.ApplyBody(rule.Scope, ct, encoding, data, max)
}

func TestApplyBodyRegex(t *testing.T) {
	rule := regexRule(".", "response", `(?P<k>\w+)=(\d+)`, "${k}:[$2]")
	res := applyOne(t, rule, "text/plain", "", []byte("a=1 b=22 c=x"), 0)
	if !res.Changed || string(res.Data) != "a:[1] b:[22] c=x" {
		t.Fatalf("%q", res.Data)
	}
	if len(res.Hits) != 1 {
		t.Fatal(res.Hits)
	}
	h := res.Hits[0]
	if h.Kind != KindBody || h.Action != ActionEdit || h.Side != "response" || len(h.Changes) != 1 || h.Changes[0].Op != EditReplaceRegex || h.Changes[0].After != "2" || !h.Changes[0].HasAfter {
		t.Fatalf("%+v", h)
	}
	input := []byte("zzz")
	res = applyOne(t, rule, "text/plain", "", input, 0)
	if res.Changed || res.Hits != nil || &res.Data[0] != &input[0] {
		t.Fatalf("no-op result %+v", res)
	}
}

func TestApplyBodyMultipleEditsAndRules(t *testing.T) {
	options := bodyOptions(
		option.MITMBodyRewriteRule{ID: "one", Pattern: ".", Scope: "response", ContentTypes: []string{"json"}, Edits: []option.MITMBodyRewriteEdit{
			{Action: EditJSONSet, Path: "$.a", Value: "2"},
			{Action: EditJSONAppend, Path: "$.l", Value: `"z"`},
			{Action: EditReplaceRegex, Regex: `"z"`, Value: `"zz"`},
			{Action: EditJSONDelete, Path: "$.gone"},
			{Action: EditJSONSet, Path: "$.b", Value: "true"},
		}},
		regexRule(".", "response", `"zz"`, `"last"`, "json"),
	)
	set := mustCompile(t, options)
	plan := set.Plan("https", "h", "/")
	res := plan.ApplyBody("response", "application/json", "", []byte(`{"a":1,"l":[]}`), 0)
	if string(res.Data) != `{"a":2,"l":["last"],"b":true}` {
		t.Fatalf("%s", res.Data)
	}
	if len(res.Hits) != 2 || res.Hits[0].Rule != "one" || len(res.Hits[0].Changes) != 4 {
		t.Fatalf("%+v", res.Hits)
	}
}

func TestApplyBodyEncodings(t *testing.T) {
	rule := regexRule(".", "response", "secret", "xxxxxx")
	plain := []byte(strings.Repeat("a secret value ", 50))
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd", "gzip, br", "x-gzip"} {
		enc := encoding
		if enc == "x-gzip" {
			enc = "gzip"
		}
		wire, err := body.Encode(enc, plain)
		if err != nil {
			t.Fatal(err)
		}
		res := applyOne(t, rule, "text/plain", encoding, wire, 0)
		if !res.Changed {
			t.Fatalf("%s: unchanged %+v", encoding, res.Hits)
		}
		back, err := body.Decode(encoding, bytes.NewReader(res.Data), body.Limits{})
		if err != nil || string(back) != strings.ReplaceAll(string(plain), "secret", "xxxxxx") {
			t.Fatalf("%s: %v %q", encoding, err, back)
		}
	}
	// A rule that finds nothing sends the original compressed bytes.
	wire, _ := body.Encode("gzip", []byte("nothing here"))
	res := applyOne(t, rule, "text/plain", "gzip", wire, 0)
	if res.Changed || &res.Data[0] != &wire[0] {
		t.Fatal("recompressed an unchanged body")
	}
}

func TestApplyBodySkips(t *testing.T) {
	rule := regexRule(".", "response", "a", "b")
	good, _ := body.Encode("gzip", []byte("aaa"))
	bomb, _ := body.Encode("gzip", bytes.Repeat([]byte("a"), 3<<20))
	tests := []struct {
		name, encoding string
		data           []byte
		max            int64
		reason         string
	}{
		{"unknown coding", "compress", []byte("aaa"), 0, SkipEncoding},
		{"unknown in chain", "gzip, snappy", good, 0, SkipEncoding},
		{"corrupt", "gzip", []byte("not gzip at all"), 0, SkipDecode},
		{"truncated", "gzip", good[:len(good)-6], 0, SkipDecode},
		{"decoded too large", "gzip", bomb, 1 << 20, SkipDecodedSize},
		{"declared wrong", "br", good, 0, SkipDecode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := applyOne(t, rule, "text/plain", tt.encoding, tt.data, tt.max)
			if res.Changed || &res.Data[0] != &tt.data[0] || len(res.Hits) != 1 || res.Hits[0].Action != ActionSkipped || res.Hits[0].Target != tt.reason {
				t.Fatalf("%+v", res)
			}
		})
	}
}

func TestApplyBodyGrowthLimit(t *testing.T) {
	rule := regexRule(".", "response", "a", strings.Repeat("b", 100))
	res := applyOne(t, rule, "text/plain", "", bytes.Repeat([]byte("a"), 4096), 1024)
	if res.Changed || len(res.Hits) != 1 || res.Hits[0].Action != ActionSkipped || res.Hits[0].Target != SkipLimit {
		t.Fatalf("grew past the limit: %d", len(res.Data))
	}
}

func TestApplyBodyNonJSONPayload(t *testing.T) {
	rule := option.MITMBodyRewriteRule{Pattern: ".", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONSet, Path: "$.a", Value: "1"}}}
	input := []byte("<html>")
	res := applyOne(t, rule, "application/json", "", input, 0)
	if res.Changed || len(res.Hits) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestRequestScope(t *testing.T) {
	rule := regexRule(".", "request", "a", "b")
	set := mustCompile(t, bodyOptions(rule))
	plan := set.Plan("https", "h", "/")
	if plan.NeedsBody("response", "text/plain") || !plan.NeedsBody("request", "text/plain") {
		t.Fatal("scope")
	}
	if res := plan.ApplyBody("response", "text/plain", "", []byte("a"), 0); res.Changed {
		t.Fatal("applied response scope")
	}
}

func TestStreamingMessage(t *testing.T) {
	tests := []struct {
		scope, method string
		status        int
		ct            string
		ranged        bool
		want          bool
	}{
		{"response", "GET", 200, "text/event-stream; charset=utf-8", false, true},
		{"response", "GET", 200, "application/grpc", false, true},
		{"response", "POST", 200, "application/grpc-web+proto", false, true},
		{"request", "POST", 0, "application/grpc", false, true},
		{"request", "POST", 0, "application/json", false, false},
		{"request", "CONNECT", 0, "", false, true},
		{"response", "GET", 101, "", false, true},
		{"response", "GET", 100, "", false, true},
		{"response", "GET", 204, "", false, true},
		{"response", "GET", 304, "", false, true},
		{"response", "HEAD", 200, "text/html", false, true},
		{"response", "GET", 206, "text/html", true, true},
		{"response", "GET", 206, "text/html", false, false},
		{"response", "GET", 200, "text/html", false, false},
		{"response", "GET", 404, "application/json", false, false},
	}
	for _, tt := range tests {
		if got := StreamingMessage(tt.scope, tt.method, tt.status, tt.ct, tt.ranged); got != tt.want {
			t.Errorf("%+v = %v", tt, got)
		}
	}
}

func TestUnmatchedBodyPlanDoesNotAllocate(t *testing.T) {
	set := mustCompile(t, bodyOptions(regexRule(`^https://never\.test/`, "response", "a", "b")))
	if raceEnabled {
		t.Skip("allocation counts differ under the race detector")
	}
	allocs := testing.AllocsPerRun(100, func() {
		if set.Plan("https", "other.test", "/index.html?x=1") != nil {
			t.Fatal("matched")
		}
	})
	if allocs != 0 {
		t.Fatalf("%v allocs", allocs)
	}
}

func TestInternalRule(t *testing.T) {
	options := &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{
			{ID: "r", Pattern: `^https://old\.test/api/(.*)$`, Action: ActionHeader, Target: "https://new.test:8443/v2/$1"},
			{Pattern: `^https://pre\.test/`, Action: ActionHeader, Target: "http://other.test"},
			{Pattern: `^https://v6\.test/`, Action: ActionHeader, Target: "https://[::1]:444/x"},
		},
		Headers: []option.MITMHeaderRewriteRule{
			{Pattern: `^https://new\.test:8443/`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-New", Value: "1"}}},
			{Pattern: `^https://old\.test/`, Scope: "request", Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-Old", Value: "1"}}},
		},
		Body: []option.MITMBodyRewriteRule{regexRule(`^https://new\.test:8443/v2/`, "response", "a", "b")},
	}
	set := mustCompile(t, options)
	plan := set.Plan("https", "old.test", "/api/users?id=3")
	in := plan.Internal()
	if in == nil || plan.Local() != nil || plan.HasRequestEdits() {
		t.Fatalf("%+v", plan)
	}
	if in.Scheme != "https" || in.Host != "new.test" || in.Port != 8443 || in.Authority != "new.test:8443" || in.Target != "/v2/users?id=3" || in.URL != "https://new.test:8443/v2/users?id=3" {
		t.Fatalf("%+v", in)
	}
	if in.Hit.Kind != KindURL || in.Hit.Action != ActionHeader || in.Hit.Rule != "r" || in.Hit.Target != in.URL {
		t.Fatalf("%+v", in.Hit)
	}
	if !in.SameOrigin("https", "NEW.test", 8443) || in.SameOrigin("http", "new.test", 8443) || in.SameOrigin("https", "new.test", 443) {
		t.Fatal("SameOrigin")
	}
	next := set.PlanAfterInternal(in)
	if next == nil || next.Internal() != nil || !next.HasRequestEdits() || !next.NeedsBody("response", "text/plain") {
		t.Fatalf("%+v", next)
	}
	req, hits := next.ApplyRequest(nil)
	if len(req) != 1 || req[0].Name != "X-New" || len(hits) != 1 {
		t.Fatalf("old url header rule leaked: %+v", req)
	}

	// Without a path in the target the original path and query stay.
	in = set.Plan("https", "pre.test", "/a/b?q=1").Internal()
	if in == nil || in.Scheme != "http" || in.Port != 80 || in.Authority != "other.test" || in.Target != "/a/b?q=1" || in.URL != "http://other.test/a/b?q=1" {
		t.Fatalf("%+v", in)
	}
	in = set.Plan("https", "v6.test", "/").Internal()
	if in == nil || in.Host != "::1" || in.Authority != "[::1]:444" || in.Port != 444 {
		t.Fatalf("%+v", in)
	}
}

func TestInternalGuardAndInvalidTargets(t *testing.T) {
	options := &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{
		{Pattern: `^https://x\.test/(.*)`, Action: ActionHeader, Target: "$1"},
		{Pattern: `^https://x\.test/`, Action: "302", Target: "https://fallback.test/"},
	}}
	set := mustCompile(t, options)
	set.SetInternalGuard(func(host string, port int) bool { return host == "127.0.0.1" && port == 9090 })
	for _, target := range []string{"/", "ftp://a.test/", "https://u:p@a.test/", "https:///x", "https://a.test:99999/", "https://a.test:/", "http://a.test/x y", "https://a.test%2f/", "javascript:1"} {
		if plan := set.Plan("https", "x.test", "/"+target); plan != nil && plan.Internal() != nil {
			t.Errorf("accepted %q", target)
		}
	}
	// A vetoed target falls through to the next rule.
	plan := set.Plan("https", "x.test", "/http://127.0.0.1:9090/")
	if plan == nil || plan.Internal() != nil || plan.Local() == nil || plan.Local().Status != 302 {
		t.Fatalf("%+v", plan)
	}
	if plan := set.Plan("https", "x.test", "/http://127.0.0.1:9091/"); plan.Internal() == nil {
		t.Fatal("guard vetoed another port")
	}
	if _, ok := set.HostReject("x.test"); ok {
		t.Fatal("HostReject must not fire for header rules")
	}
}

func TestInternalCompile(t *testing.T) {
	bad := []option.MITMURLRewriteRule{
		{Pattern: "x", Action: ActionHeader},
		{Pattern: "x", Action: ActionHeader, Target: "ftp://a.test/"},
		{Pattern: "x", Action: ActionHeader, Target: "/relative"},
		{Pattern: "x", Action: ActionHeader, Target: "https://u@a.test/"},
		{Pattern: "x", Action: ActionHeader, Target: "https://a.test/\r\nX: y"},
		{Pattern: "x", Action: ActionHeader, Target: "https://a b.test/"},
		{Pattern: "x", Action: ActionHeader, Target: "https://" + strings.Repeat("a", maxPattern) + ".test/"},
	}
	for _, rule := range bad {
		if _, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{rule}}); err == nil {
			t.Errorf("accepted %q", rule.Target)
		}
	}
	good := option.MITMURLRewriteRule{Pattern: "x", Action: ActionHeader, Target: "https://a.test/p"}
	if _, err := Compile(context.Background(), &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{good}}); err != nil {
		t.Fatal(err)
	}
}

func FuzzJSONPath(f *testing.F) {
	for _, seed := range []string{"$", "$.a.b", "$..a", "$[0,1]", "$['a','b']", "$[*]", "$[-1]", "$[?(@.a)]", "$['", "$..[", "$.a[", "", "$[1:2]"} {
		f.Add(seed, `{"a":{"b":[1,2,{"a":3}]},"c":[true,null]}`)
	}
	f.Fuzz(func(t *testing.T, path, src string) {
		p, err := parseJSONPath(path)
		if err != nil {
			return
		}
		for _, action := range []string{EditJSONSet, EditJSONDelete, EditJSONAppend} {
			doc, ok := newJSONDoc([]byte(src))
			if !ok {
				return
			}
			var n int
			switch action {
			case EditJSONSet:
				n = doc.set(p, []byte(`{"v":[1]}`))
			case EditJSONDelete:
				n = doc.remove(p)
			default:
				n = doc.appendTo(p, []byte(`0`))
			}
			out, ok := doc.bytes(1 << 30)
			if !ok {
				t.Fatal("limit")
			}
			if n > 0 && !json.Valid(out) {
				t.Fatalf("%s %q on %q produced invalid JSON %q", action, path, src, out)
			}
			if n == 0 && string(out) != src {
				t.Fatalf("no-op changed bytes: %q -> %q", src, out)
			}
		}
	})
}

func FuzzBodyEdit(f *testing.F) {
	f.Add([]byte(`{"a":1,"l":[1,2]}`), "$.a", `2`, `\d`, "<$0>", uint8(0))
	f.Add([]byte(`plain text a=1`), "$..a", `[]`, `(\w)=(\d)`, "$2$1", uint8(1))
	f.Add([]byte(`[1,[2,[3]]]`), "$[*]", `null`, `.`, "", uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, path, value, regex, repl string, mode uint8) {
		var edits []option.MITMBodyRewriteEdit
		switch mode % 4 {
		case 0:
			edits = []option.MITMBodyRewriteEdit{{Action: EditJSONSet, Path: path, Value: value}, {Action: EditReplaceRegex, Regex: regex, Value: repl}}
		case 1:
			edits = []option.MITMBodyRewriteEdit{{Action: EditJSONDelete, Path: path}, {Action: EditJSONAppend, Path: path, Value: value}}
		case 2:
			edits = []option.MITMBodyRewriteEdit{{Action: EditReplaceRegex, Regex: regex, Value: repl}}
		default:
			edits = []option.MITMBodyRewriteEdit{{Action: EditJSONSet, Path: path, Value: value}}
		}
		set, err := Compile(context.Background(), bodyOptions(option.MITMBodyRewriteRule{Pattern: ".", Scope: "response", ContentTypes: []string{"x"}, Edits: edits}))
		if err != nil {
			return
		}
		plan := set.Plan("https", "h", "/")
		input := append([]byte(nil), data...)
		res := plan.ApplyBody("response", "x", "", data, 1<<16)
		if !bytes.Equal(input, data) {
			t.Fatal("input modified")
		}
		if !res.Changed && !bytes.Equal(res.Data, data) {
			t.Fatal("unchanged result differs")
		}
		if res.Changed && len(res.Hits) == 0 {
			t.Fatal("change without hit")
		}
		if mode%4 == 3 && res.Changed && !json.Valid(res.Data) {
			t.Fatalf("invalid JSON %q from %q", res.Data, data)
		}
	})
}

func TestJSONAppendAmplificationIsBounded(t *testing.T) {
	// 100k empty arrays, each receiving a 30 KB string, would produce about 3 GB.
	value := `"` + strings.Repeat("x", 30<<10) + `"`
	rule := option.MITMBodyRewriteRule{Pattern: "x", Scope: "response", Edits: []option.MITMBodyRewriteEdit{{Action: EditJSONAppend, Path: "$[*]", Value: value}}}
	set := mustCompile(t, bodyOptions(rule))
	plan := set.Plan("https", "x", "/")
	src := []byte("[" + strings.TrimSuffix(strings.Repeat("[],", 100000), ",") + "]")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	result := plan.ApplyBody(ScopeResponse, "application/json", "", src, 1<<20)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if result.Changed || len(result.Hits) != 1 || result.Hits[0].Action != ActionSkipped || result.Hits[0].Target != SkipLimit {
		t.Fatalf("result %+v", result)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 256<<20 || elapsed > 5*time.Second {
		t.Fatalf("allocated %d MiB in %v", grown>>20, elapsed)
	}
}

func TestCanonicalIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1": "127.0.0.1", "127.1": "127.0.0.1", "2130706433": "127.0.0.1", "0x7f000001": "127.0.0.1",
		"0177.0.0.1": "127.0.0.1", "0": "0.0.0.0", "0x7f.1": "127.0.0.1", "169.254.169.254": "169.254.169.254",
		"2852039166": "169.254.169.254", "10.1": "10.0.0.1",
	} {
		got, ok := canonicalIPv4(in)
		if !ok || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"example.com", "1.2.3.4.5", "256.1.1.1", "4294967296", "1..2", "0x", "08.1", "a.1"} {
		if got, ok := canonicalIPv4(in); ok {
			t.Errorf("%s accepted as %q", in, got)
		}
	}
	in, err := parseInternal("http://0x7f.1:9090/x", "/")
	if err != nil || in.Host != "127.0.0.1" || in.Port != 9090 {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestRegexTooManyMatchesIsRecorded(t *testing.T) {
	set := mustCompile(t, bodyOptions(regexRule("x", "response", "a", "b")))
	plan := set.Plan("https", "x", "/")
	result := plan.ApplyBody(ScopeResponse, "text/plain", "", []byte(strings.Repeat("a", maxRegexMatches+10)), 1<<20)
	if result.Changed || len(result.Hits) != 1 || result.Hits[0].Action != ActionSkipped || result.Hits[0].Target != SkipLimit {
		t.Fatalf("result %+v", result.Hits)
	}
}

func TestCanonicalIPv4TrailingDot(t *testing.T) {
	in, err := parseInternal("http://127.1.:9090/x", "/")
	if err != nil || in.Host != "127.0.0.1" {
		t.Fatalf("%+v %v", in, err)
	}
}
