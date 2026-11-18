//go:build go1.26

package h2

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/option"
)

func compileSet(t testing.TB, options option.MITMHTTPRewriteOptions) *rewrite.Set {
	t.Helper()
	set, err := rewrite.Compile(t.Context(), &options)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func withRewrite(m *capture.Manager, set *rewrite.Set) func(*Options) {
	return func(o *Options) {
		if m != nil {
			observe(m)(o)
		}
		o.Rewrite = func() *rewrite.Set { return set }
	}
}

func noRedirects(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func urlRules(rules ...option.MITMURLRewriteRule) option.MITMHTTPRewriteOptions {
	return option.MITMHTTPRewriteOptions{URL: rules}
}

func headerRule(id, pattern, scope string, ops ...option.MITMHeaderRewriteEdit) option.MITMHeaderRewriteRule {
	return option.MITMHeaderRewriteRule{ID: id, Pattern: pattern, Scope: scope, Operations: ops}
}

func TestRewriteLocalResponses(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rule        option.MITMURLRewriteRule
		status      int
		contentType string
		body        string
		location    string
	}{
		{name: "reject-200", rule: option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-200"}, status: 200, contentType: "text/plain"},
		{name: "reject-img", rule: option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-img"}, status: 200, contentType: "image/gif", body: string(rewrite.TinyGIF)},
		{name: "reject-dict", rule: option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-dict"}, status: 200, contentType: "application/json", body: "{}"},
		{name: "reject-array", rule: option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-array"}, status: 200, contentType: "application/json", body: "[]"},
		{name: "302", rule: option.MITMURLRewriteRule{Pattern: `^https://example\.test/x/(\w+)\?id=(\d+)`, Action: "302", Target: "https://b.example/n/$1?id=$2"}, status: 302, location: "https://b.example/n/foo?id=7"},
		{name: "307", rule: option.MITMURLRewriteRule{Pattern: `^https://example\.test/x/(?P<name>\w+)\?id=(?P<id>\d+)`, Action: "307", Target: "https://b.example/${id}/${name}"}, status: 307, location: "https://b.example/7/foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstream atomic.Int32
			m := newCapture(true)
			_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstream.Add(1)
				w.Write([]byte("upstream"))
			}), withRewrite(m, compileSet(t, urlRules(tc.rule))))
			client := noRedirects(e.client())
			resp, err := client.Get(e.url("/x/foo?id=7"))
			if err != nil {
				t.Fatal(err)
			}
			got := string(readAll(t, resp.Body))
			if resp.StatusCode != tc.status || got != tc.body || resp.Header.Get("Location") != tc.location {
				t.Fatalf("status %d body %q location %q", resp.StatusCode, got, resp.Header.Get("Location"))
			}
			if tc.contentType != "" && resp.Header.Get("Content-Type") != tc.contentType {
				t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
			}
			if resp.Header.Get("Content-Length") != "" && resp.ContentLength != int64(len(tc.body)) {
				t.Fatalf("content length %d", resp.ContentLength)
			}
			// The same connection serves a request that goes upstream.
			resp, err = client.Get(e.url("/other"))
			if err != nil {
				t.Fatal(err)
			}
			if string(readAll(t, resp.Body)) != "upstream" || upstream.Load() != 1 {
				t.Fatalf("upstream calls %d", upstream.Load())
			}
			records := waitRecords(t, m, 2)
			var local capture.Record
			for _, r := range records {
				if strings.HasPrefix(r.Path, "/x/") {
					local = r
				}
			}
			if !local.Rewritten || len(local.Rewrites) != 1 || local.Rewrites[0].Action != tc.rule.Action || local.Status != tc.status {
				t.Fatalf("record %+v", local)
			}
			if tc.body != "" && body(t, m, local.ID, flow.Response) != tc.body {
				t.Fatalf("recorded body %q", body(t, m, local.ID, flow.Response))
			}
			if e.forward.Load() != 2 {
				t.Fatalf("forward count %d", e.forward.Load())
			}
		})
	}
}

func TestRewriteHeadRequest(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream reached")
	}), withRewrite(nil, compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-dict"}))))
	resp, err := e.client().Head(e.url("/x"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.ContentLength != 2 || len(readAll(t, resp.Body)) != 0 {
		t.Fatalf("status %d length %d", resp.StatusCode, resp.ContentLength)
	}
}

func TestRewriteAbortResetsStream(t *testing.T) {
	m := newCapture(false)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}), withRewrite(m, compileSet(t, urlRules(option.MITMURLRewriteRule{ID: "drop", Pattern: `^https://example\.test/x`, Action: "reject"}))))
	client := e.client()
	if resp, err := client.Get(e.url("/x")); err == nil {
		resp.Body.Close()
		t.Fatalf("expected a stream error, got %d", resp.StatusCode)
	}
	// The connection survives: other streams still work.
	resp, err := client.Get(e.url("/y"))
	if err != nil {
		t.Fatal(err)
	}
	if string(readAll(t, resp.Body)) != "ok" {
		t.Fatal("body")
	}
	records := waitRecords(t, m, 2)
	var aborted capture.Record
	for _, r := range records {
		if r.Path == "/x" {
			aborted = r
		}
	}
	if !aborted.Rewritten || aborted.Rewrites[0].Rule != "drop" || aborted.Rewrites[0].Action != "reject" || aborted.Status != 0 {
		t.Fatalf("record %+v", aborted)
	}
	if e.forward.Load() != 2 {
		t.Fatalf("forward count %d", e.forward.Load())
	}
}

func TestRewriteMapLocal(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{
		{Pattern: `^https://example\.test/text`, Status: 201, Body: "hello", Headers: []option.MITMHeaderRewriteField{{Name: "X-Mock", Value: "1"}}},
		{Pattern: `^https://example\.test/bin`, Status: 200, BodyBase64: base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255}),
			Headers: []option.MITMHeaderRewriteField{{Name: "Content-Type", Value: "application/octet-stream"}}},
	}})
	m := newCapture(true)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream reached")
	}), withRewrite(m, set))
	client := e.client()
	resp, err := client.Get(e.url("/text"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 || resp.Header.Get("X-Mock") != "1" || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || string(readAll(t, resp.Body)) != "hello" {
		t.Fatalf("response %d %v", resp.StatusCode, resp.Header)
	}
	resp, err = client.Get(e.url("/bin"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, resp.Body); string(got) != "\x00\x01\x02\xff" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("body %q %v", got, resp.Header)
	}
	records := waitRecords(t, m, 2)
	for _, r := range records {
		if r.Rewrites[0].Kind != "map_local" {
			t.Fatalf("hit %+v", r.Rewrites)
		}
	}
}

func TestRewriteRequestHeaders(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("h1", `^https://example\.test/`, "request",
			option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Added", Value: "1"},
			option.MITMHeaderRewriteEdit{Action: "delete", Name: "x-secret"},
			option.MITMHeaderRewriteEdit{Action: "replace", Name: "User-Agent", Value: "kiko"},
			option.MITMHeaderRewriteEdit{Action: "replace-regex", Name: "Accept", Regex: "json", Value: "xml"}),
	}})
	m := newCapture(false)
	var got atomic.Pointer[http.Header]
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Clone()
		got.Store(&h)
		w.Write([]byte("ok"))
	}), withRewrite(m, set))
	req, _ := http.NewRequest("GET", e.url("/p"), nil)
	req.Header.Set("X-Secret", "s")
	req.Header.Set("User-Agent", "curl")
	req.Header.Set("Accept", "application/json")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	h := got.Load()
	if h == nil || h.Get("X-Added") != "1" || h.Get("X-Secret") != "" || h.Get("User-Agent") != "kiko" || h.Get("Accept") != "application/xml" {
		t.Fatalf("upstream saw %v", h)
	}
	r := waitRecords(t, m, 1)[0]
	if !r.Rewritten || len(r.Rewrites) != 1 || r.Rewrites[0].Side != "request" || len(r.Rewrites[0].Changes) != 4 {
		t.Fatalf("hits %+v", r.Rewrites)
	}
	if v := headerOf(r.RequestHeaders, "user-agent"); len(v) != 1 || v[0] != "kiko" {
		t.Fatalf("recorded request head %+v", r.RequestHeaders)
	}
	if len(headerOf(r.RequestHeaders, "x-secret")) != 0 || len(headerOf(r.RequestHeaders, "x-added")) != 1 {
		t.Fatalf("recorded request head %+v", r.RequestHeaders)
	}
	for _, c := range r.Rewrites[0].Changes {
		if c.Op == "delete" && (c.Before != "s" || !c.HadBefore || c.HasAfter) {
			t.Fatalf("delete change %+v", c)
		}
	}
}

func TestRewriteResponseHeaders(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("r1", `^https://example\.test/`, "response",
			option.MITMHeaderRewriteEdit{Action: "delete", Name: "Server"},
			option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Seen", Value: "yes"},
			option.MITMHeaderRewriteEdit{Action: "replace", Name: "Cache-Control", Value: "no-store"}),
	}})
	m := newCapture(false)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Cache-Control", "max-age=5")
		w.Write([]byte("ok"))
	}), withRewrite(m, set))
	resp, err := e.client().Get(e.url("/p"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if resp.Header.Get("Server") != "" || resp.Header.Get("X-Seen") != "yes" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("client saw %v", resp.Header)
	}
	r := waitRecords(t, m, 1)[0]
	if len(r.Rewrites) != 1 || r.Rewrites[0].Side != "response" || len(headerOf(r.ResponseHeaders, "server")) != 0 || len(headerOf(r.ResponseHeaders, "x-seen")) != 1 {
		t.Fatalf("record %+v", r)
	}
}

// Header rules do not buffer: the first chunk reaches the client before the handler finished.
func TestRewriteStreamingKeepsStreaming(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("resp", `^https://example\.test/`, "response", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Resp", Value: "1"}),
		headerRule("req", `^https://example\.test/`, "request", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Req", Value: "1"}),
	}})
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Saw-Req", r.Header.Get("X-Req"))
		w.Write([]byte("data: 1\n\n"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("data: 2\n\n"))
	}), withRewrite(nil, set))
	resp, err := e.client().Get(e.url("/events"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Resp") != "1" || resp.Header.Get("X-Saw-Req") != "1" {
		t.Fatalf("headers %v", resp.Header)
	}
	first := make([]byte, 9)
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "data: 1\n\n" {
		t.Fatalf("first chunk %q %v", first, err)
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if string(rest) != "data: 2\n\n" {
		t.Fatalf("rest %q", rest)
	}
}

func TestRewriteLargeBodyStreams(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("resp", `^https://example\.test/`, "response", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Resp", Value: "1"}),
	}})
	const size = 16 << 20
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("z", 64<<10))
		for i := 0; i < size/len(chunk); i++ {
			w.Write(chunk)
		}
	}), withRewrite(nil, set))
	resp, err := e.client().Get(e.url("/big"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != size || resp.Header.Get("X-Resp") != "1" {
		t.Fatalf("copied %d: %v", n, err)
	}
}

func TestRewriteHotSwap(t *testing.T) {
	var current atomic.Pointer[rewrite.Set]
	current.Store(compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-dict"})))
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream"))
	}), func(o *Options) { o.Rewrite = current.Load })
	client := e.client()
	get := func() string {
		resp, err := client.Get(e.url("/x"))
		if err != nil {
			t.Fatal(err)
		}
		return string(readAll(t, resp.Body))
	}
	if got := get(); got != "{}" {
		t.Fatalf("first %q", got)
	}
	current.Store(compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://example\.test/x`, Action: "reject-array"})))
	if got := get(); got != "[]" {
		t.Fatalf("second %q", got)
	}
	current.Store(compileSet(t, option.MITMHTTPRewriteOptions{}))
	if got := get(); got != "upstream" {
		t.Fatalf("third %q", got)
	}
}
