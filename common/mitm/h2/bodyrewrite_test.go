//go:build go1.26

package h2

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

func bodyRule(id, pattern, scope, regex, value string, types ...string) option.MITMBodyRewriteRule {
	return option.MITMBodyRewriteRule{
		ID: id, Pattern: pattern, Scope: scope, ContentTypes: badoption.Listable[string](types),
		Edits: []option.MITMBodyRewriteEdit{{Action: "replace-regex", Regex: regex, Value: value}},
	}
}

func bodyOptions(maxSize string, rules ...option.MITMBodyRewriteRule) option.MITMHTTPRewriteOptions {
	options := option.MITMHTTPRewriteOptions{Body: rules}
	if maxSize != "" {
		var value byteformats.MemoryBytes
		if err := json.Unmarshal([]byte(`"`+maxSize+`"`), &value); err != nil {
			panic(err)
		}
		options.MaxBodySize = &value
	}
	return options
}

func TestBodyResponseRewritten(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "response", `hello`, `goodbye!`)))
	m := newCapture(true)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "11")
		w.Header().Set("Digest", "sha-256=abc")
		w.Write([]byte("hello world"))
	}), withRewrite(m, set))
	resp, err := e.client().Get(e.url("/x"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(readAll(t, resp.Body))
	if got != "goodbye! world" || resp.ContentLength != 14 || resp.Header.Get("Digest") != "" {
		t.Fatalf("body %q length %d head %v", got, resp.ContentLength, resp.Header)
	}
	r := waitRecords(t, m, 1)[0]
	if len(r.Rewrites) != 1 || r.Rewrites[0].Kind != "body" || r.Rewrites[0].Action != "edit" || r.Rewrites[0].Side != "response" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
	if v := headerOf(r.ResponseHeaders, "content-length"); len(v) != 1 || v[0] != "14" {
		t.Fatalf("recorded head %+v", r.ResponseHeaders)
	}
	if body := bodyOfRecord(t, m, r.ID, flow.Response); body != "goodbye! world" {
		t.Fatalf("recorded body %q", body)
	}
}

func bodyOfRecord(t testing.TB, m interface {
	GetBody(capture.BodyRequest) (capture.BodyResult, error)
}, id string, side flow.Side) string {
	t.Helper()
	result, err := m.GetBody(capture.BodyRequest{ID: id, Side: side})
	if err != nil {
		t.Fatal(err)
	}
	return string(result.Data)
}

func TestBodyResponseUnknownLengthAndGzip(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "response", `hello`, `bye`)))
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var packed bytes.Buffer
		zw := gzip.NewWriter(&packed)
		zw.Write([]byte("hello hello"))
		zw.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(packed.Bytes()[:5])
		w.(http.Flusher).Flush()
		w.Write(packed.Bytes()[5:])
	}), withRewrite(nil, set))
	resp, err := e.client().Get(e.url("/x"))
	if err != nil {
		t.Fatal(err)
	}
	raw := readAll(t, resp.Body)
	if resp.ContentLength != int64(len(raw)) {
		t.Fatalf("content length %d for %d bytes", resp.ContentLength, len(raw))
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if string(plain) != "bye bye" {
		t.Fatalf("decoded %q", plain)
	}
}

func TestBodyResponseTooLargePassesThrough(t *testing.T) {
	set := compileSet(t, bodyOptions("1KB", bodyRule("b1", `^https://example\.test/`, "response", `a`, `b`)))
	m := newCapture(false)
	payload := strings.Repeat("a", 5000)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/known" {
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		}
		w.Write([]byte(payload[:2500]))
		w.(http.Flusher).Flush()
		w.Write([]byte(payload[2500:]))
	}), withRewrite(m, set))
	for _, path := range []string{"/known", "/unknown"} {
		resp, err := e.client().Get(e.url(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(readAll(t, resp.Body)); got != payload {
			t.Fatalf("%s: passthrough changed the body (%d bytes)", path, len(got))
		}
	}
	for _, r := range waitRecords(t, m, 2) {
		if len(r.Rewrites) != 1 || r.Rewrites[0].Action != "skipped" || r.Rewrites[0].Target != "size" {
			t.Fatalf("hits %+v", r.Rewrites)
		}
	}
}

func TestBodyStreamsAreNotBuffered(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "response", `data`, `DATA`, "event-stream", "grpc")))
	m := newCapture(false)
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: 1\n\n"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("data: 2\n\n"))
	}), withRewrite(m, set))
	resp, err := e.client().Get(e.url("/events"))
	if err != nil {
		t.Fatal(err)
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
	r := waitRecords(t, m, 1)[0]
	if len(r.Rewrites) != 1 || r.Rewrites[0].Action != "skipped" || r.Rewrites[0].Target != "stream" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
}

func TestBodyGRPCRequestIsNotBuffered(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "request", `a`, `b`, "grpc")))
	got := make(chan string, 1)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4)
		io.ReadFull(r.Body, buf)
		got <- string(buf)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(200)
		io.Copy(io.Discard, r.Body)
	}), withRewrite(nil, set))
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", e.url("/g"), pr)
	req.Header.Set("Content-Type", "application/grpc")
	done := make(chan error, 1)
	go func() {
		resp, err := e.client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	pw.Write([]byte("aaaa"))
	select {
	case s := <-got:
		if s != "aaaa" {
			t.Fatalf("origin saw %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first request frame was held back")
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBodyRequestRewritten(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "request", `"id":\d+`, `"id":1234567`)))
	m := newCapture(true)
	type seenBody struct {
		body   string
		length int64
		header http.Header
	}
	seenCh := make(chan seenBody, 1)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seenCh <- seenBody{string(b), r.ContentLength, r.Header.Clone()}
	}), withRewrite(m, set))
	req, _ := http.NewRequest("POST", e.url("/x"), strings.NewReader(`{"id":7}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest", "sha-256=abc")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	seen := <-seenCh
	if seen.body != `{"id":1234567}` || seen.length != 14 || seen.header.Get("Digest") != "" {
		t.Fatalf("origin saw %+v", seen)
	}
	r := waitRecords(t, m, 1)[0]
	if got := bodyOfRecord(t, m, r.ID, flow.Request); got != `{"id":1234567}` {
		t.Fatalf("recorded request body %q", got)
	}
	if v := headerOf(r.RequestHeaders, "content-length"); len(v) != 1 || v[0] != "14" {
		t.Fatalf("recorded head %+v", r.RequestHeaders)
	}
}

func TestBodyRequestUnknownLengthRewritten(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "request", `cat`, `tiger`)))
	seenCh := make(chan string, 1)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seenCh <- string(b) + "|" + strconv.FormatInt(r.ContentLength, 10)
	}), withRewrite(nil, set))
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", e.url("/x"), pr)
	req.Header.Set("Content-Type", "text/plain")
	done := make(chan error, 1)
	go func() {
		resp, err := e.client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	pw.Write([]byte("a ca"))
	pw.Write([]byte("t!"))
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-seenCh; got != "a tiger!|8" {
		t.Fatalf("origin saw %q", got)
	}
}

func TestBodyBufferTimeoutPassesThrough(t *testing.T) {
	old := rewrite.BufferTimeout
	rewrite.BufferTimeout = 150 * time.Millisecond
	defer func() { rewrite.BufferTimeout = old }()
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://example\.test/`, "response", `a`, `b`)))
	m := newCapture(false)
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("aaa"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("aaa"))
	}), withRewrite(m, set))
	resp, err := e.client().Get(e.url("/poll"))
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 3)
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "aaa" {
		t.Fatalf("first %q %v", first, err)
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if string(rest) != "aaa" {
		t.Fatalf("rest %q", rest)
	}
	r := waitRecords(t, m, 1)[0]
	if len(r.Rewrites) != 1 || r.Rewrites[0].Target != "timeout" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
}

// internalOrigin serves HTTP/1.1 over TLS and records what it saw.
type internalOrigin struct {
	srv  *httptest.Server
	seen chan seenRequest
}

type seenRequest struct{ host, uri string }

func newInternalOrigin(t *testing.T, secure bool) *internalOrigin {
	o := &internalOrigin{seen: make(chan seenRequest, 64)}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.seen <- seenRequest{r.Host, r.RequestURI}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("internal " + r.URL.Path))
	})
	if secure {
		o.srv = httptest.NewTLSServer(handler)
	} else {
		o.srv = httptest.NewServer(handler)
	}
	t.Cleanup(o.srv.Close)
	return o
}

func (o *internalOrigin) dialer(secure bool, dials *atomic.Int32) func(context.Context, *rewrite.Internal) (net.Conn, error) {
	return func(ctx context.Context, in *rewrite.Internal) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		raw, err := d.DialContext(ctx, "tcp", o.srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		if !secure || in.Scheme != "https" {
			return raw, nil
		}
		conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: in.Host, NextProtos: []string{"http/1.1"}})
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
}

func TestInternalRewriteToOtherOrigins(t *testing.T) {
	for _, secure := range []bool{true, false} {
		name := "http"
		target := "http://other.example:8080/new/$1"
		if secure {
			name = "https"
			target = "https://other.example/new/$1"
		}
		t.Run(name, func(t *testing.T) {
			internal := newInternalOrigin(t, secure)
			set := compileSet(t, option.MITMHTTPRewriteOptions{
				URL: []option.MITMURLRewriteRule{{ID: "i1", Pattern: `^https://example\.test/old/(.*)`, Action: "header", Target: target}},
				Body: []option.MITMBodyRewriteRule{
					bodyRule("b1", `^https?://other\.example[:/]`, "response", `internal`, `INTERNAL`),
				},
			})
			var dials atomic.Int32
			var original atomic.Int32
			m := newCapture(false)
			_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				original.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("original"))
			}), func(o *Options) {
				withRewrite(m, set)(o)
				o.Internal = internal.dialer(secure, &dials)
			})
			client := e.client()
			resp, err := client.Get(e.url("/old/p?q=1"))
			if err != nil {
				t.Fatal(err)
			}
			if got := string(readAll(t, resp.Body)); got != "INTERNAL /new/p" {
				t.Fatalf("body %q", got)
			}
			seen := <-internal.seen
			wantHost := "other.example"
			if !secure {
				wantHost = "other.example:8080"
			}
			if seen.host != wantHost || seen.uri != "/new/p?q=1" {
				t.Fatalf("internal origin saw %+v", seen)
			}
			// A request without a match still goes to the original origin.
			resp, err = client.Get(e.url("/plain"))
			if err != nil {
				t.Fatal(err)
			}
			if got := string(readAll(t, resp.Body)); got != "original" {
				t.Fatalf("plain body %q", got)
			}
			if original.Load() != 1 || dials.Load() != 1 {
				t.Fatalf("original %d dials %d", original.Load(), dials.Load())
			}
			// The connection to the internal origin is kept for the session.
			resp, err = client.Get(e.url("/old/again"))
			if err != nil {
				t.Fatal(err)
			}
			readAll(t, resp.Body)
			if dials.Load() != 1 {
				t.Fatalf("dials %d", dials.Load())
			}
			records := waitRecords(t, m, 3)
			var hit *flow.RewriteHit
			for i := range records {
				if len(records[i].Rewrites) > 0 && records[i].Rewrites[0].Kind == "url" {
					hit = &records[i].Rewrites[0]
					if records[i].Authority != wantHost {
						t.Fatalf("recorded authority %q", records[i].Authority)
					}
					break
				}
			}
			if hit == nil || hit.Action != "header" || !strings.Contains(hit.Target, "other.example") {
				t.Fatalf("hit %+v", hit)
			}
		})
	}
}

func TestInternalRewriteSameOriginReusesUpstream(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `^https://example\.test/old`, Action: "header", Target: "https://EXAMPLE.test/new"}},
	})
	var dials atomic.Int32
	seen := make(chan string, 2)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host + r.RequestURI
		w.Write([]byte("ok"))
	}), func(o *Options) {
		o.Rewrite = func() *rewrite.Set { return set }
		o.Internal = func(context.Context, *rewrite.Internal) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("must not dial")
		}
	})
	resp, err := e.client().Get(e.url("/old"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if got := <-seen; got != "example.test/new" || dials.Load() != 0 {
		t.Fatalf("origin saw %q dials %d", got, dials.Load())
	}
}

func TestInternalRewriteFailureIs502(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `^https://example\.test/old`, Action: "header", Target: "https://other.example/new"}},
	})
	var original atomic.Int32
	m := newCapture(false)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original.Add(1)
	}), func(o *Options) {
		withRewrite(m, set)(o)
		o.Internal = func(context.Context, *rewrite.Internal) (net.Conn, error) { return nil, errors.New("refused") }
	})
	resp, err := e.client().Get(e.url("/old"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 || original.Load() != 0 {
		t.Fatalf("status %d original %d", resp.StatusCode, original.Load())
	}
	waitRecords(t, m, 1)
}

func TestInternalRewriteOriginsPerSessionAreBounded(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `^https://example\.test/(\d+)`, Action: "header", Target: "http://h$1.example/x"}},
	})
	internal := newInternalOrigin(t, false)
	var dials atomic.Int32
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), func(o *Options) {
		withRewrite(nil, set)(o)
		o.Internal = internal.dialer(false, &dials)
	})
	client := e.client()
	for i := 0; i < maxInternalOrigins+2; i++ {
		resp, err := client.Get(e.url("/" + strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusOK
		if i >= maxInternalOrigins {
			want = http.StatusBadGateway
		}
		if resp.StatusCode != want {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
}
