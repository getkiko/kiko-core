package h1

import (
	"context"
	"encoding/base64"
	"io"
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
	set, err := rewrite.Compile(context.Background(), &options)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func rewriteOptions(m *capture.Manager, set *rewrite.Set) Options {
	options := Options{Rewrite: func() *rewrite.Set { return set }}
	if m != nil {
		options.Observer = m.Observer()
		options.Connection = &flow.ConnectionInfo{ID: "c1", Host: "a"}
	}
	return options
}

func urlRules(rules ...option.MITMURLRewriteRule) option.MITMHTTPRewriteOptions {
	return option.MITMHTTPRewriteOptions{URL: rules}
}

func TestRewriteLocalResponses(t *testing.T) {
	gif := string(rewrite.TinyGIF)
	for _, tc := range []struct {
		name string
		rule option.MITMURLRewriteRule
		want string
	}{
		{"reject-200", option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-200"},
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"},
		{"reject-img", option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-img"},
			"HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: 43\r\n\r\n" + gif},
		{"reject-tinygif", option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-tinygif"},
			"HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: 43\r\n\r\n" + gif},
		{"reject-dict", option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-dict"},
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"},
		{"reject-array", option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-array"},
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]"},
		{"302", option.MITMURLRewriteRule{Pattern: `^https://a/x/(\w+)\?id=(\d+)`, Action: "302", Target: "https://b.example/n/$1?id=$2"},
			"HTTP/1.1 302 Found\r\nLocation: https://b.example/n/foo?id=7\r\nContent-Length: 0\r\n\r\n"},
		{"307", option.MITMURLRewriteRule{Pattern: `^https://a/x/(?P<name>\w+)\?id=(?P<id>\d+)`, Action: "307", Target: "https://b.example/${id}/${name}"},
			"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://b.example/7/foo\r\nContent-Length: 0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := capture.New(capture.Options{Enabled: true, Body: true})
			h := newHarnessOptions(t, rewriteOptions(m, compileSet(t, urlRules(tc.rule))))
			h.send("GET /x/foo?id=7 HTTP/1.1\r\nHost: a\r\n\r\n")
			h.expectClient(tc.want)
			// Keep-alive: the next request, no rule, reaches the upstream on the same connection.
			h.send("GET /y HTTP/1.1\r\nHost: a\r\n\r\n")
			h.expectUpstream("GET /y HTTP/1.1\r\nHost: a\r\n\r\n")
			h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			h.client.Close()
			h.wait()
			if h.requests.Load() != 2 {
				t.Fatalf("requests %d", h.requests.Load())
			}
			records := captured(t, m, 2)
			r := records[0]
			if !r.Rewritten || len(r.Rewrites) != 1 || r.Rewrites[0].Kind != "url" || r.Rewrites[0].Action != tc.rule.Action {
				t.Fatalf("hits %+v", r)
			}
			if r.Status != 200 && r.Status != 302 && r.Status != 307 {
				t.Fatalf("status %d", r.Status)
			}
			if r.Path != "/x/foo?id=7" || r.State != capture.StateComplete {
				t.Fatalf("record %+v", r)
			}
			tm := r.Timing
			if tm.Start.IsZero() || tm.ResponseHeaders.IsZero() || tm.End.IsZero() {
				t.Fatalf("timing %+v", tm)
			}
			if body := tc.want[strings.Index(tc.want, "\r\n\r\n")+4:]; body != "" {
				if got := bodyOf(t, m, r.ID, flow.Response); got != body {
					t.Fatalf("recorded body %q", got)
				}
			}
			if records[1].Rewritten {
				t.Fatalf("unmatched request marked rewritten: %+v", records[1])
			}
		})
	}
}

func TestRewriteRedirectHit(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true})
	set := compileSet(t, urlRules(option.MITMURLRewriteRule{ID: "r1", Pattern: `^https://a/(\w+)`, Action: "302", Target: "https://c/$1"}))
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /abc HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 302 Found\r\nLocation: https://c/abc\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	hit := captured(t, m, 1)[0].Rewrites[0]
	if hit.Rule != "r1" || hit.Target != "https://c/abc" || hit.Status != 302 {
		t.Fatalf("hit %+v", hit)
	}
}

func TestRewriteHead(t *testing.T) {
	set := compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-dict"}))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n")
	h.send("HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n")
	h.client.Close()
	h.wait()
}

func TestRewriteLocalClosesWithBody(t *testing.T) {
	set := compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-200"}))
	for name, request := range map[string]string{
		"body":      "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
		"chunked":   "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"expect":    "GET /x HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
		"close":     "GET /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
		"http/1.0":  "GET /x HTTP/1.0\r\nHost: a\r\n\r\n",
		"head body": "HEAD /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessOptions(t, rewriteOptions(nil, set))
			h.send(request)
			h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			expectEOF(t, "client", h.clientR)
			if err := h.wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRewriteAbort(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true})
	set := compileSet(t, urlRules(option.MITMURLRewriteRule{ID: "drop", Pattern: `^https://a/x`, Action: "reject"}))
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	r := captured(t, m, 1)[0]
	if !r.Rewritten || r.Rewrites[0].Action != "reject" || r.Rewrites[0].Rule != "drop" || r.Status != 0 {
		t.Fatalf("record %+v", r)
	}
	if h.requests.Load() != 1 {
		t.Fatalf("requests %d", h.requests.Load())
	}
}

func TestRewriteMapLocal(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{MapLocal: []option.MITMMapLocalRule{
		{Pattern: `^https://a/text`, Status: 201, Body: "hello", Headers: []option.MITMHeaderRewriteField{{Name: "X-Mock", Value: "1"}}},
		{Pattern: `^https://a/bin`, Status: 200, BodyBase64: base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255}),
			Headers: []option.MITMHeaderRewriteField{{Name: "Content-Type", Value: "application/octet-stream"}}},
	}})
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /text HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 201 Created\r\nX-Mock: 1\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello")
	h.send("GET /bin HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n\x00\x01\x02\xff")
	h.client.Close()
	h.wait()
	records := captured(t, m, 2)
	if records[0].Rewrites[0].Kind != "map_local" || records[0].Rewrites[0].Status != 201 {
		t.Fatalf("hit %+v", records[0].Rewrites)
	}
	if got := bodyOf(t, m, records[1].ID, flow.Response); got != "\x00\x01\x02\xff" {
		t.Fatalf("body %q", got)
	}
}

func headerRule(id, pattern, scope string, ops ...option.MITMHeaderRewriteEdit) option.MITMHeaderRewriteRule {
	return option.MITMHeaderRewriteRule{ID: id, Pattern: pattern, Scope: scope, Operations: ops}
}

func TestRewriteRequestHeaders(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("h1", `^https://a/`, "request",
			option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Added", Value: "1"},
			option.MITMHeaderRewriteEdit{Action: "delete", Name: "x-secret"},
			option.MITMHeaderRewriteEdit{Action: "replace", Name: "User-Agent", Value: "kiko"},
			option.MITMHeaderRewriteEdit{Action: "replace-regex", Name: "Accept", Regex: "json", Value: "xml"}),
	}})
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /p HTTP/1.1\r\nHost: a\r\nX-Secret: s\r\nUser-Agent: curl\r\nAccept: application/json\r\n\r\n")
	h.expectUpstream("GET /p HTTP/1.1\r\nHost: a\r\nUser-Agent: kiko\r\nAccept: application/xml\r\nX-Added: 1\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if !r.Rewritten || len(r.Rewrites) != 1 || r.Rewrites[0].Kind != "header" || r.Rewrites[0].Side != "request" || r.Rewrites[0].Rule != "h1" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
	changes := r.Rewrites[0].Changes
	if len(changes) != 4 {
		t.Fatalf("changes %+v", changes)
	}
	for _, c := range changes {
		switch c.Name {
		case "x-secret", "X-Secret":
			if !c.HadBefore || c.Before != "s" || c.HasAfter {
				t.Fatalf("delete change %+v", c)
			}
		case "User-Agent":
			if c.Before != "curl" || c.After != "kiko" {
				t.Fatalf("replace change %+v", c)
			}
		}
	}
	var names []string
	for _, f := range r.RequestHeaders {
		names = append(names, f.Name+"="+f.Value)
	}
	if got := strings.Join(names, ","); got != "Host=a,User-Agent=kiko,Accept=application/xml,X-Added=1" {
		t.Fatalf("recorded request head %s", got)
	}
}

func TestRewriteResponseHeaders(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("r1", `^https://a/`, "response",
			option.MITMHeaderRewriteEdit{Action: "delete", Name: "Server"},
			option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Seen", Value: "yes"},
			option.MITMHeaderRewriteEdit{Action: "replace", Name: "Cache-Control", Value: "no-store"}),
	}})
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /p HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /p HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nServer: nginx\r\nCache-Control: max-age=5\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Length: 2\r\nX-Seen: yes\r\n\r\nok")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if len(r.Rewrites) != 1 || r.Rewrites[0].Side != "response" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
	for _, f := range r.ResponseHeaders {
		if strings.EqualFold(f.Name, "server") {
			t.Fatalf("recorded response head keeps Server: %+v", r.ResponseHeaders)
		}
	}
	if len(r.ResponseHeaders) != 3 {
		t.Fatalf("recorded response head %+v", r.ResponseHeaders)
	}
}

// A header rule that matches nothing to change leaves the exchange unmarked.
func TestRewriteNoChangeNoHit(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("h", `^https://a/`, "request", option.MITMHeaderRewriteEdit{Action: "delete", Name: "X-None"}),
	}})
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /p HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /p HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	if r := captured(t, m, 1)[0]; r.Rewritten {
		t.Fatalf("record %+v", r)
	}
}

// The edited request head is what a retry on a redialed connection sends.
func TestRewriteRequestHeadersOnRedial(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("h", `^https://a/two`, "request", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Once", Value: "1"}),
	}})
	m := capture.New(capture.Options{Enabled: true})
	r := newRedialHarnessOptions(t, rewriteOptions(m, set))
	r.roundTrip("/one")
	r.send("GET /two HTTP/1.1\r\nHost: a\r\n\r\n")
	want := "GET /two HTTP/1.1\r\nHost: a\r\nX-Once: 1\r\n\r\n"
	r.expectUpstream(want)
	r.upstream.Close()
	r.switchUpstream()
	r.expectUpstream(want)
	r.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	r.client.Close()
	r.wait()
	records := captured(t, m, 2)
	if len(records[1].Rewrites) != 1 {
		t.Fatalf("hits %+v", records[1].Rewrites)
	}
	if r.requests.Load() != 2 {
		t.Fatalf("requests %d", r.requests.Load())
	}
}

func TestRewriteUpgradeNotRewritten(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("req", `^https://a/`, "request", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Req", Value: "1"}),
		headerRule("resp", `^https://a/`, "response", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Resp", Value: "1"}),
	}})
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	// The request head is rewritten before it goes upstream; the 101 is not.
	h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Req: 1\r\n\r\n")
	h.reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	h.expectClient("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	h.send("ping")
	got := make([]byte, 4)
	io.ReadFull(h.upstreamR, got)
	h.client.Close()
	h.upstream.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	for _, hit := range r.Rewrites {
		if hit.Side == "response" {
			t.Fatalf("101 rewritten: %+v", r.Rewrites)
		}
	}
}

func TestRewriteConnectNotRewritten(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("resp", `.`, "response", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Resp", Value: "1"}),
	}})
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n")
	h.expectUpstream("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n")
	h.reply("HTTP/1.1 200 Connection established\r\n\r\n")
	h.expectClient("HTTP/1.1 200 Connection established\r\n\r\n")
	h.client.Close()
	h.upstream.Close()
	h.wait()
}

// A streamed response with header rules keeps streaming: the first chunk reaches the client
// before the upstream finished the body.
func TestRewriteStreamingKeepsStreaming(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("resp", `^https://a/`, "response", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Resp", Value: "1"}),
		headerRule("req", `^https://a/`, "request", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Req", Value: "1"}),
	}})
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /events HTTP/1.1\r\nHost: a\r\nAccept: text/event-stream\r\n\r\n")
	h.expectUpstream("GET /events HTTP/1.1\r\nHost: a\r\nAccept: text/event-stream\r\nX-Req: 1\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ndata:1\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-Resp: 1\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ndata:1\r\n")
	h.reply("6\r\ndata:2\r\n0\r\n\r\n")
	h.expectClient("6\r\ndata:2\r\n0\r\n\r\n")
	h.client.Close()
	h.wait()
}

// A large body is streamed, not buffered, with rules active.
func TestRewriteLargeBodyStreams(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{Headers: []option.MITMHeaderRewriteRule{
		headerRule("resp", `^https://a/`, "response", option.MITMHeaderRewriteEdit{Action: "add", Name: "X-Resp", Value: "1"}),
	}})
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	const size = 8 << 20
	h.send("GET /big HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /big HTTP/1.1\r\nHost: a\r\n\r\n")
	go func() {
		io.WriteString(h.upstream, "HTTP/1.1 200 OK\r\nContent-Length: 8388608\r\n\r\n")
		chunk := []byte(strings.Repeat("z", 64<<10))
		for i := 0; i < size/len(chunk); i++ {
			if _, err := h.upstream.Write(chunk); err != nil {
				return
			}
		}
	}()
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 8388608\r\nX-Resp: 1\r\n\r\n")
	n, err := io.CopyN(io.Discard, h.clientR, size)
	if err != nil || n != size {
		t.Fatalf("copied %d: %v", n, err)
	}
	h.client.Close()
	h.wait()
}

// The set is read per request: a swap applies to the next request of a running connection.
func TestRewriteHotSwap(t *testing.T) {
	var current atomic.Pointer[rewrite.Set]
	current.Store(compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-dict"})))
	h := newHarnessOptions(t, Options{Rewrite: current.Load})
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	current.Store(compileSet(t, urlRules(option.MITMURLRewriteRule{Pattern: `^https://a/x`, Action: "reject-array"})))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]")
	current.Store(compileSet(t, option.MITMHTTPRewriteOptions{}))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
}

// Scheme "http" is what rules see and what records show.
func TestRewritePlainScheme(t *testing.T) {
	set := compileSet(t, urlRules(
		option.MITMURLRewriteRule{Pattern: `^https://`, Action: "reject-dict"},
		option.MITMURLRewriteRule{Pattern: `^http://a/x$`, Action: "reject-array"}))
	m := capture.New(capture.Options{Enabled: true})
	options := rewriteOptions(m, set)
	options.Scheme = "http"
	h := newHarnessOptions(t, options)
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]")
	h.client.Close()
	h.wait()
	if r := captured(t, m, 1)[0]; r.Scheme != "http" {
		t.Fatalf("scheme %q", r.Scheme)
	}
}
