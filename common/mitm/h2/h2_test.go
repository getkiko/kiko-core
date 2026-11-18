//go:build go1.26

package h2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func httpProxy(t testing.TB, h http.Handler, mod func(*Options)) (*origin, *proxyEnv) {
	o := newOrigin(t, h)
	return o, startProxy(t, proxyConfig{dial: o.dial, mod: mod})
}

func readAll(t testing.TB, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

type seen struct {
	Method, URI, Host, Proto string
	Header                   http.Header
	ContentLength            int64
	Body                     string
	Trailer                  http.Header
}

func echoSeen(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header()["Content-Type"] = nil
	w.Header().Set("X-Reply", "yes")
	w.Header().Add("Set-Cookie", "a=1")
	w.Header().Add("Set-Cookie", "b=2")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(seen{r.Method, r.RequestURI, r.Host, r.Proto, r.Header, r.ContentLength, string(body), r.Trailer})
}

func TestRoundTripFidelity(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(echoSeen), nil)
	c := e.client()

	req, _ := http.NewRequest("GET", e.url("/a/b%2Fc?q=1&r=%20x"), nil)
	req.Header.Set("User-Agent", "")
	req.Header.Set("X-Custom", "Value")
	req.Header.Add("X-Multi", "one")
	req.Header.Add("X-Multi", "two")
	req.Header.Set("Accept-Encoding", "br")
	req.Header.Set("Te", "trailers")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 || resp.Header.Get("X-Reply") != "yes" {
		t.Fatalf("status %d header %v", resp.StatusCode, resp.Header)
	}
	if got := resp.Header.Values("Set-Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Fatalf("set-cookie %v", got)
	}
	if _, ok := resp.Header["Content-Type"]; ok {
		t.Fatalf("content type invented: %v", resp.Header["Content-Type"])
	}
	var s seen
	if err := json.Unmarshal(readAll(t, resp.Body), &s); err != nil {
		t.Fatal(err)
	}
	if s.Method != "GET" || s.URI != "/a/b%2Fc?q=1&r=%20x" || s.Host != testHost || s.Proto != "HTTP/2.0" {
		t.Fatalf("seen %+v", s)
	}
	if _, ok := s.Header["User-Agent"]; ok {
		t.Fatalf("user agent invented: %v", s.Header["User-Agent"])
	}
	if s.Header.Get("X-Custom") != "Value" || strings.Join(s.Header["X-Multi"], ",") != "one,two" {
		t.Fatalf("headers %v", s.Header)
	}
	if s.Header.Get("Accept-Encoding") != "br" || s.Header.Get("Te") != "trailers" {
		t.Fatalf("headers %v", s.Header)
	}
	if _, ok := s.Header["Content-Length"]; ok {
		t.Fatalf("content-length invented: %v", s.Header)
	}

	// No Accept-Encoding when the client sent none.
	req, _ = http.NewRequest("GET", e.url("/"), nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	s = seen{}
	json.Unmarshal(readAll(t, resp.Body), &s)
	if _, ok := s.Header["Accept-Encoding"]; ok {
		t.Fatalf("accept-encoding invented: %v", s.Header)
	}

	// POST keeps the content length.
	req, _ = http.NewRequest("POST", e.url("/post"), strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	s = seen{}
	json.Unmarshal(readAll(t, resp.Body), &s)
	if s.Body != "hello" || s.ContentLength != 5 || s.Header.Get("Content-Length") != "5" || s.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("post seen %+v", s)
	}

	// POST without a length is streamed with none added.
	req, _ = http.NewRequest("POST", e.url("/post"), io.NopCloser(strings.NewReader("chunked")))
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	s = seen{}
	json.Unmarshal(readAll(t, resp.Body), &s)
	if s.Body != "chunked" || s.ContentLength != -1 {
		t.Fatalf("stream post seen %+v", s)
	}
	if e.forward.Load() != 4 || e.sessions.Load() != 1 {
		t.Fatalf("forwarded %d sessions %d", e.forward.Load(), e.sessions.Load())
	}
}

func TestLargeBodies(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			// 8 MiB of a repeating pattern.
			chunk := bytes.Repeat([]byte("0123456789abcdef"), 4096)
			for i := 0; i < 128; i++ {
				w.Write(chunk)
			}
			return
		}
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
	}), nil)
	c := e.client()

	payload := make([]byte, 8<<20)
	rand.Read(payload)
	resp, err := c.Post(e.url("/up"), "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if got := string(readAll(t, resp.Body)); got != fmt.Sprintf("%d %x", len(payload), sum) {
		t.Fatalf("upload digest %s", got)
	}

	resp, err = c.Get(e.url("/down"))
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, resp.Body)
	if len(got) != 8<<20 || !bytes.Equal(got[:16], []byte("0123456789abcdef")) || !bytes.Equal(got[len(got)-16:], []byte("0123456789abcdef")) {
		t.Fatalf("download %d bytes", len(got))
	}
}

func TestResponseTrailers(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Declared")
		w.Write([]byte("body"))
		w.Header().Set("X-Declared", "d")
		w.Header().Set(http.TrailerPrefix+"X-Late", "l")
	}), nil)
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	if string(readAll(t, resp.Body)) != "body" {
		t.Fatal("body")
	}
	if resp.Trailer.Get("X-Declared") != "d" || resp.Trailer.Get("X-Late") != "l" {
		t.Fatalf("trailers %v", resp.Trailer)
	}
}

func TestRequestTrailers(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s|%s|%s", body, r.Trailer.Get("X-Tr"), r.Trailer.Get("X-Tr2"))
	}), nil)
	req, _ := http.NewRequest("POST", e.url("/"), io.NopCloser(strings.NewReader("payload")))
	req.Trailer = http.Header{"X-Tr": {"v1"}, "X-Tr2": {"v2"}}
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readAll(t, resp.Body)); got != "payload|v1|v2" {
		t.Fatalf("got %q", got)
	}
}

func TestServerStreamingFlush(t *testing.T) {
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
		io.WriteString(w, "second")
	}), nil)
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "first" {
		t.Fatalf("first chunk %q %v", buf, err)
	}
	close(release)
	if rest := readAll(t, resp.Body); string(rest) != "second" {
		t.Fatalf("rest %q", rest)
	}
}

func TestHeadersBeforeFirstByte(t *testing.T) {
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "late")
	}), nil)
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	if string(readAll(t, resp.Body)) != "late" {
		t.Fatal("body")
	}
}

func TestBidirectionalEcho(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}), nil)
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", e.url("/"), pr)
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		msg := fmt.Sprintf("message-%d", i)
		if _, err := io.WriteString(pw, msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != msg {
			t.Fatalf("echo %q %v", buf, err)
		}
	}
	pw.Close()
	if rest := readAll(t, resp.Body); len(rest) != 0 {
		t.Fatalf("rest %q", rest)
	}
}

func TestClientCancelMidResponse(t *testing.T) {
	cancelled := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			return
		}
		buf := bytes.Repeat([]byte("x"), 8192)
		for {
			if _, err := w.Write(buf); err != nil {
				break
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				close(cancelled)
				return
			case <-time.After(time.Millisecond):
			}
		}
		close(cancelled)
	}), nil)
	c := e.client()
	warm, err := c.Get(e.url("/warm"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, warm.Body)
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", e.url("/stream"), nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("origin did not see the cancellation")
	}
	resp.Body.Close()
	settleGoroutines(t, base)
	// The session is still usable.
	resp, err = c.Get(e.url("/warm"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if e.sessions.Load() != 1 {
		t.Fatalf("sessions %d", e.sessions.Load())
	}
}

func TestClientCancelMidUpload(t *testing.T) {
	readErr := make(chan error, 1)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			return
		}
		_, err := io.Copy(io.Discard, r.Body)
		readErr <- err
	}), nil)
	c := e.client()
	warm, err := c.Get(e.url("/warm"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, warm.Body)
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", e.url("/up"), pr)
	done := make(chan error, 1)
	go func() {
		resp, err := c.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	pw.Write(bytes.Repeat([]byte("u"), 100000))
	cancel()
	pw.CloseWithError(context.Canceled)
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("origin read the whole body")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin did not see the reset")
	}
	<-done
	settleGoroutines(t, base)
}

func TestUpstreamAbort(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/before":
			panic(http.ErrAbortHandler)
		case "/mid":
			io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
	}), nil)
	c := e.client()
	resp, err := c.Get(e.url("/before"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 502 || len(readAll(t, resp.Body)) != 0 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp, err = c.Get(e.url("/mid"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err == nil || string(b) != "partial" {
		t.Fatalf("mid-body abort read %q err %v", b, err)
	}
	if e.sessions.Load() != 1 {
		t.Fatalf("sessions %d", e.sessions.Load())
	}
}

func TestMisdirected(t *testing.T) {
	var hits atomic.Int32
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "ok")
	}), nil)
	c := e.client()
	for _, tc := range []struct {
		host string
		code int
	}{
		{testHost, 200},
		{testHost + ":8443", 200},
		{"EXAMPLE.Test", 200},
		{"example.test.", 200},
		{"other.test", 421},
		{"other.test:443", 421},
		{"sub.example.test", 421},
		{"127.0.0.1", 421},
		{"[::1]:443", 421},
	} {
		req, _ := http.NewRequest("GET", e.url("/"), nil)
		req.Host = tc.host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		body := readAll(t, resp.Body)
		if resp.StatusCode != tc.code {
			t.Fatalf("%s: status %d", tc.host, resp.StatusCode)
		}
		if tc.code == 421 && len(body) != 0 {
			t.Fatalf("%s: body %q", tc.host, body)
		}
	}
	if hits.Load() != 4 || e.forward.Load() != 4 {
		t.Fatalf("origin hits %d forwarded %d", hits.Load(), e.forward.Load())
	}
}

func TestMisdirectedIPLiteral(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), func(o *Options) { o.ServerName = "2001:db8::1" })
	c := e.client()
	for host, code := range map[string]int{
		"[2001:db8::1]:443":                200,
		"[2001:DB8:0:0:0:0:0:1]":           200,
		"[::ffff:1.2.3.4]":                 421,
		"[2001:db8::2]":                    421,
		"example.test":                     421,
		"[0:0:0:0:0:ffff:102:304]:443":     421,
		"[2001:db8:0000:0000:0000::1]:443": 200,
	} {
		req, _ := http.NewRequest("GET", e.url("/"), nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		readAll(t, resp.Body)
		if resp.StatusCode != code {
			t.Fatalf("%s: status %d want %d", host, resp.StatusCode, code)
		}
	}
}

func TestSameHost(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"a.test", "a.test", true},
		{"A.test:443", "a.TEST", true},
		{"a.test.", "a.test", true},
		{"1.2.3.4:80", "1.2.3.4", true},
		{"[::1]", "::1", true},
		{"[::ffff:1.2.3.4]", "1.2.3.4", true},
		{"a.test", "b.test", false},
		{"1.2.3.4", "1.2.3.5", false},
		{"", "a.test", false},
	} {
		if got := sameHost(tc.a, tc.b); got != tc.want {
			t.Errorf("sameHost(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

// rawConn is a minimal HTTP/2 client for frames x/net would not send.
type rawConn struct {
	t   testing.TB
	c   *tls.Conn
	fr  *http2.Framer
	dec *hpack.Decoder
	// Settings is the first SETTINGS frame of the server.
	Settings map[http2.SettingID]uint32
	// endStream reports whether the last response HEADERS frame ended the stream.
	endStream bool
}

func (e *proxyEnv) raw() *rawConn {
	e.t.Helper()
	c, err := tls.Dial("tcp", e.addr, &tls.Config{InsecureSkipVerify: true, ServerName: testHost, NextProtos: []string{"h2"}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	r := &rawConn{t: e.t, c: c, fr: http2.NewFramer(c, c), dec: hpack.NewDecoder(4096, nil), Settings: map[http2.SettingID]uint32{}}
	io.WriteString(c, http2.ClientPreface)
	r.fr.WriteSettings()
	for len(r.Settings) == 0 {
		f := r.next()
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			sf.ForeachSetting(func(s http2.Setting) error { r.Settings[s.ID] = s.Val; return nil })
			r.fr.WriteSettingsAck()
		}
	}
	return r
}

func (r *rawConn) next() http2.Frame {
	r.t.Helper()
	r.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := r.fr.ReadFrame()
	if err != nil {
		r.t.Fatalf("read frame: %v", err)
	}
	return f
}

// request sends the fields on stream id (no body) and returns the response
// fields, or the RST_STREAM code.
func (r *rawConn) request(id uint32, fields ...hpack.HeaderField) (map[string]string, http2.ErrCode) {
	r.t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		enc.WriteField(f)
	}
	r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: buf.Bytes(), EndStream: true, EndHeaders: true})
	for {
		switch f := r.next().(type) {
		case *http2.HeadersFrame:
			if f.StreamID != id {
				continue
			}
			hf, err := r.dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				r.t.Fatal(err)
			}
			r.endStream = f.StreamEnded()
			m := map[string]string{}
			for _, h := range hf {
				m[h.Name] = h.Value
			}
			return m, 0
		case *http2.RSTStreamFrame:
			if f.StreamID == id {
				return nil, f.ErrCode
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				r.fr.WritePing(true, f.Data)
			}
		case *http2.GoAwayFrame:
			r.t.Fatalf("goaway %v", f.ErrCode)
		}
	}
}

func TestSettingsNoConnectProtocol(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)
	r := e.raw()
	if v, ok := r.Settings[0x8]; ok {
		t.Fatalf("SETTINGS_ENABLE_CONNECT_PROTOCOL advertised: %d", v)
	}
	if got := r.Settings[http2.SettingMaxConcurrentStreams]; got != maxStreams {
		t.Fatalf("max concurrent streams %d", got)
	}
	if got := r.Settings[http2.SettingInitialWindowSize]; got != streamWindow {
		t.Fatalf("initial window %d", got)
	}
	t.Logf("server settings: %v", r.Settings)
	// An extended CONNECT is refused.
	_, code := r.request(1,
		hpack.HeaderField{Name: ":method", Value: "CONNECT"},
		hpack.HeaderField{Name: ":protocol", Value: "websocket"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":path", Value: "/ws"},
		hpack.HeaderField{Name: ":authority", Value: testHost})
	if code == 0 {
		t.Fatal("extended CONNECT accepted")
	}
}

func TestConnectMethod(t *testing.T) {
	var hits atomic.Int32
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }), nil)
	r := e.raw()
	m, code := r.request(1,
		hpack.HeaderField{Name: ":method", Value: "CONNECT"},
		hpack.HeaderField{Name: ":authority", Value: testHost + ":443"})
	if code != 0 || m[":status"] != "405" {
		t.Fatalf("plain CONNECT: %v %v", m, code)
	}
	if hits.Load() != 0 || e.forward.Load() != 0 {
		t.Fatal("CONNECT reached the origin")
	}
}

func TestMissingAuthority(t *testing.T) {
	var hits atomic.Int32
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }), nil)
	r := e.raw()
	m, code := r.request(1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":path", Value: "/"})
	t.Logf("no :authority, no host: %v %v", m, code)
	if code == 0 && m[":status"] != "400" {
		t.Fatalf("status %v", m)
	}
	// Host stands in for :authority.
	m, code = r.request(3,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":path", Value: "/"},
		hpack.HeaderField{Name: "host", Value: testHost})
	if code != 0 || m[":status"] != "200" {
		t.Fatalf("host only: %v %v", m, code)
	}
	m, _ = r.request(5,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":path", Value: "/"},
		hpack.HeaderField{Name: "host", Value: "other.test"})
	if m[":status"] != "421" {
		t.Fatalf("other host: %v", m)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
}

func TestHeaderFilters(t *testing.T) {
	in := http.Header{
		"Connection":        {"keep-alive, X-Drop"},
		"Keep-Alive":        {"timeout=5"},
		"Proxy-Connection":  {"keep-alive"},
		"Upgrade":           {"websocket"},
		"Transfer-Encoding": {"chunked"},
		"Te":                {"gzip, trailers"},
		"X-Drop":            {"1"},
		"X-Keep":            {"a", "b"},
		"Trailer":           {"X-Tr"},
	}
	out := requestHeader(in)
	for _, k := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Upgrade", "Transfer-Encoding", "X-Drop", "Trailer"} {
		if _, ok := out[k]; ok {
			t.Errorf("request header %s kept", k)
		}
	}
	if out.Get("Te") != "trailers" || strings.Join(out["X-Keep"], ",") != "a,b" {
		t.Errorf("request header %v", out)
	}
	if v, ok := out["User-Agent"]; !ok || len(v) != 1 || v[0] != "" {
		t.Errorf("user agent %v", out["User-Agent"])
	}
	in.Set("Te", "gzip")
	if _, ok := requestHeader(in)["Te"]; ok {
		t.Error("te without trailers kept")
	}

	resp := http.Header{
		"Connection":        {"close"},
		"Keep-Alive":        {"1"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"h2c"},
		"Trailer":           {"X-Tr"},
		"Content-Length":    {"3"},
		"X-Keep":            {"v"},
	}
	dst := http.Header{}
	copyResponseHeader(dst, resp)
	if len(dst) != 2 || dst.Get("Content-Length") != "3" || dst.Get("X-Keep") != "v" {
		t.Errorf("response header %v", dst)
	}
}

func TestAltSvc(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mixed":
			w.Header().Set("Alt-Svc", `h3=":443"; ma=86400, h2=":443"; ma=60`)
		case "/h3":
			w.Header().Set("Alt-Svc", `h3=":443"; ma=86400, h3-29=":443"`)
		case "/clear":
			w.Header().Set("Alt-Svc", `clear`)
		}
	}), nil)
	c := e.client()
	for path, want := range map[string]string{"/mixed": `h2=":443"; ma=60`, "/h3": "", "/clear": "clear", "/none": ""} {
		resp, err := c.Get(e.url(path))
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp.Body)
		got, present := resp.Header["Alt-Svc"]
		if want == "" && present {
			t.Errorf("%s: Alt-Svc kept: %v", path, got)
		}
		if want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("%s: Alt-Svc %v want %q", path, got, want)
		}
	}
}

func TestEarlyHints(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("X-Final", "1")
		io.WriteString(w, "done")
	}), nil)
	var hints atomic.Int32
	var link atomic.Value
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		if code == 103 {
			hints.Add(1)
			link.Store(h.Get("Link"))
		}
		return nil
	}}
	req, _ := http.NewRequest("GET", e.url("/"), nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(readAll(t, resp.Body)) != "done" || resp.Header.Get("X-Final") != "1" {
		t.Fatal("final response")
	}
	t.Logf("103 Early Hints relayed: %d (link %v)", hints.Load(), link.Load())
	if hints.Load() != 1 {
		t.Fatalf("103 relayed %d times", hints.Load())
	}
	if resp.Header.Get("Link") != "" {
		t.Fatalf("hint header leaked into the final response: %v", resp.Header)
	}
}

func TestPushDisabledUpstream(t *testing.T) {
	reached := make(chan struct{}, 1)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		p, ok := w.(http.Pusher)
		if !ok {
			io.WriteString(w, "nopusher")
			return
		}
		fmt.Fprintf(w, "push:%v", p.Push("/x", nil))
	}), nil)
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(readAll(t, resp.Body))
	select {
	case <-reached:
	default:
		t.Fatal("the origin handler never ran")
	}
	if got != "nopusher" && !strings.HasPrefix(got, "push:") {
		t.Fatalf("unexpected origin reply %q", got)
	}
	if got == "push:<nil>" {
		t.Fatalf("origin could push: %s", got)
	}
}

func TestConcurrentStreamsAboveLimit(t *testing.T) {
	var cur, peak atomic.Int32
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		defer cur.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		io.WriteString(w, "ok")
	}), nil)
	cc := e.clientConn(0)
	const total = 150
	var wg sync.WaitGroup
	errs := make(chan error, total)
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", e.url("/"), nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || string(b) != "ok" {
				errs <- fmt.Errorf("status %d body %q", resp.StatusCode, b)
			}
		}()
	}
	eventually(t, "100 streams at the origin", func() bool { return cur.Load() >= 100 })
	time.Sleep(100 * time.Millisecond)
	if got := cur.Load(); got > 100 {
		t.Fatalf("%d concurrent streams reached the origin", got)
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if peak.Load() > 100 {
		t.Fatalf("peak %d", peak.Load())
	}
	if e.sessions.Load() != 1 {
		t.Fatalf("sessions %d", e.sessions.Load())
	}
}

func TestSlowClientWindow(t *testing.T) {
	var written atomic.Int64
	started := make(chan struct{})
	finish := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("s"), 16<<10)
		close(started)
		for i := 0; i < 4096; i++ { // up to 64 MiB
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				break
			}
			select {
			case <-r.Context().Done():
			default:
			}
		}
		close(finish)
	}), nil)
	const clientWindow = 64 << 10
	cc := e.clientConn(clientWindow)
	req, _ := http.NewRequest("GET", e.url("/"), nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	// The client reads nothing; wait until the origin cannot write any more.
	last := int64(-1)
	for stable := 0; stable < 15; {
		time.Sleep(20 * time.Millisecond)
		now := written.Load()
		if now == last {
			stable++
		} else {
			stable, last = 0, now
		}
	}
	// Client window + proxy copy buffer + upstream stream window + framing slack.
	upstreamWindow := int64(streamWindow)
	if os.Getenv("MITM_H2_PROFILE") == ProfileChrome {
		// Chrome's 6 MiB stream window; the memory the relay keeps stays capped
		// by chromeBufferCap (see TestChromeBufferCap).
		upstreamWindow = chromeStreamWindow
	}
	limit := int64(clientWindow+copyBufferSize+128<<10) + upstreamWindow
	t.Logf("origin wrote %d bytes against a %d byte limit", last, limit)
	if last > limit {
		t.Fatalf("origin wrote %d bytes into a stalled stream (limit %d)", last, limit)
	}
	if last < streamWindow {
		t.Fatalf("origin only wrote %d bytes", last)
	}
	resp.Body.Close()
	select {
	case <-finish:
	case <-time.After(10 * time.Second):
		t.Fatal("origin handler did not finish after the reset")
	}
}

func TestManyParallelStreams(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Len", fmt.Sprint(len(b)))
		w.Write(b)
		w.(http.Flusher).Flush()
		w.Write([]byte(r.URL.Path))
	}), nil)
	c := e.client()
	c.Transport.(*http.Transport).MaxConnsPerHost = 4
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte(i)}, i*997)
			path := fmt.Sprintf("/p%d", i)
			req, _ := http.NewRequest("POST", e.url(path), bytes.NewReader(payload))
			resp, err := c.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(b, append(payload, path...)) {
				t.Errorf("stream %d: %d bytes, %v", i, len(b), err)
			}
		}()
	}
	wg.Wait()
}

func TestHandlerPanicKeepsSession(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), func(o *Options) {
		var n atomic.Int32
		o.OnRequest = func() {
			if n.Add(1) == 2 {
				panic("boom")
			}
		}
	})
	c := e.client()
	for i := 1; i <= 3; i++ {
		resp, err := c.Get(e.url("/"))
		if i == 2 {
			if err == nil {
				readAll(t, resp.Body)
				t.Fatal("panicking request succeeded")
			}
			continue
		}
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		readAll(t, resp.Body)
	}
	if e.sessions.Load() != 1 {
		t.Fatalf("sessions %d", e.sessions.Load())
	}
}

func TestIdleTimeout(t *testing.T) {
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			<-release
		}
		io.WriteString(w, "ok")
	}), func(o *Options) { o.IdleTimeout = 300 * time.Millisecond })
	c := e.client()
	// A stream open for longer than the idle timeout keeps the connection.
	done := make(chan error, 1)
	go func() {
		resp, err := c.Get(e.url("/hold"))
		if err == nil {
			_, err = io.ReadAll(resp.Body)
		}
		done <- err
	}()
	time.Sleep(900 * time.Millisecond)
	select {
	case err := <-e.done:
		t.Fatalf("session ended while a stream was open: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-e.done:
		if err != nil {
			t.Fatalf("Serve after idle close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection was not closed")
	}
}

func TestContextCancelEndsServe(t *testing.T) {
	o := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cl, srv := net.Pipe()
	_ = cl
	up, err := o.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, up, Options{ServerName: testHost}) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestUpstreamStartFailure(t *testing.T) {
	cl, srv := net.Pipe()
	up1, up2 := net.Pipe()
	up2.Close()
	if err := Serve(context.Background(), srv, up1, Options{ServerName: testHost}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := cl.Write([]byte("x")); err == nil {
		t.Fatal("client conn left open")
	}
}

// --- GOAWAY, loss and redial ---

func switchingDial(first, later *origin) func(ctx context.Context) (net.Conn, error) {
	var n atomic.Int32
	return func(ctx context.Context) (net.Conn, error) {
		if n.Add(1) == 1 {
			return first.dial(ctx)
		}
		return later.dial(ctx)
	}
}

func TestGoAwayRedial(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var posts atomic.Int32
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			close(started)
			<-release
			io.WriteString(w, "slow-done")
		default:
			io.WriteString(w, "A")
		}
	}))
	b := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts.Add(1)
		}
		io.WriteString(w, "B")
	}))
	e := startProxy(t, proxyConfig{dial: switchingDial(a, b)})
	c := e.client()

	slowDone := make(chan string, 1)
	go func() {
		resp, err := c.Get(e.url("/slow"))
		if err != nil {
			slowDone <- "error: " + err.Error()
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slowDone <- "error: " + err.Error()
			return
		}
		slowDone <- string(body)
	}()
	<-started

	go a.srv.Config.Shutdown(context.Background())
	eventually(t, "a request served by the redialed origin", func() bool {
		resp, err := c.Get(e.url("/fast"))
		if err != nil {
			t.Fatal(err)
		}
		return string(readAll(t, resp.Body)) == "B"
	})
	if got := e.dials.Load(); got != 2 {
		t.Fatalf("dials %d", got)
	}
	// The in-flight stream finishes on the old connection.
	select {
	case got := <-slowDone:
		t.Fatalf("slow request ended early: %s", got)
	default:
	}
	close(release)
	select {
	case got := <-slowDone:
		if got != "slow-done" {
			t.Fatalf("slow request: %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("slow request did not finish")
	}

	// Concurrent streams share the new connection.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Post(e.url("/p"), "text/plain", strings.NewReader("x"))
			if err != nil {
				t.Error(err)
				return
			}
			if got := string(readAll(t, resp.Body)); got != "B" {
				t.Errorf("post served by %q", got)
			}
		}()
	}
	wg.Wait()
	if got := e.dials.Load(); got != 2 {
		t.Fatalf("dials %d", got)
	}
	if posts.Load() != 20 || e.sessions.Load() != 1 {
		t.Fatalf("posts %d sessions %d", posts.Load(), e.sessions.Load())
	}
}

func TestConcurrentRedialDialsOnce(t *testing.T) {
	var gate sync.WaitGroup
	gate.Add(1)
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		killConn(r)
	}))
	b := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "B")
	}))
	var n atomic.Int32
	slowDial := func(ctx context.Context) (net.Conn, error) {
		if n.Add(1) == 1 {
			return a.dial(ctx)
		}
		time.Sleep(200 * time.Millisecond)
		return b.dial(ctx)
	}
	e := startProxy(t, proxyConfig{dial: slowDial})
	cc := e.clientConn(0)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", e.url("/"), nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			if string(b) != "B" {
				t.Errorf("body %q status %d", b, resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if got := e.dials.Load(); got != 2 {
		t.Fatalf("dials %d, want 1 initial + 1 redial", got)
	}
	if got := e.forward.Load(); got != 10 {
		t.Fatalf("forwarded %d", got)
	}
}

func TestRetryIdempotentAfterConnLoss(t *testing.T) {
	var bPosts atomic.Int32
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		killConn(r)
	}))
	b := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			bPosts.Add(1)
		}
		io.WriteString(w, "B")
	}))
	// GET is retried on the redialed connection and counted once.
	e := startProxy(t, proxyConfig{dial: switchingDial(a, b)})
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readAll(t, resp.Body)); resp.StatusCode != 200 || got != "B" {
		t.Fatalf("status %d body %q", resp.StatusCode, got)
	}
	if e.forward.Load() != 1 {
		t.Fatalf("forwarded %d", e.forward.Load())
	}

	// POST that may have reached the origin is not retried.
	e = startProxy(t, proxyConfig{dial: switchingDial(a, b)})
	resp, err = e.client().Post(e.url("/"), "text/plain", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if resp.StatusCode != 502 || bPosts.Load() != 0 {
		t.Fatalf("status %d, retried posts %d", resp.StatusCode, bPosts.Load())
	}
	if e.forward.Load() != 1 {
		t.Fatalf("forwarded %d", e.forward.Load())
	}
}

func TestNoRedialClosesClient(t *testing.T) {
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		killConn(r)
	}))
	e := startProxy(t, proxyConfig{dial: a.dial, noRedial: true})
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
		t.Fatal("client connection left open after the upstream was lost")
	}
}

func TestRedialFailure(t *testing.T) {
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		killConn(r)
	}))
	e := startProxy(t, proxyConfig{dial: a.dial, redial: func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("dial refused")
	}})
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
		t.Fatal("client connection left open")
	}
}

func TestUpstreamBodyNotConsumedRetry(t *testing.T) {
	// A POST refused before any byte left (GOAWAY at connect time) goes to the
	// redialed connection with its body intact.
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "A")
	}))
	b := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "B:%s", body)
	}))
	e := startProxy(t, proxyConfig{dial: switchingDial(a, b)})
	c := e.client()
	resp, err := c.Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	// Make A refuse new streams with a graceful GOAWAY while the client conn
	// stays up.
	go a.srv.Config.Shutdown(context.Background())
	eventually(t, "redialed upstream", func() bool {
		resp, err := c.Post(e.url("/"), "text/plain", strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		return string(readAll(t, resp.Body)) == "B:payload"
	})
}

func TestTrailersOnlyFrame(t *testing.T) {
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "5")
		w.Header().Set("Grpc-Message", "gone")
	}), nil)
	r := e.raw()
	m, code := r.request(1,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":path", Value: "/t.Test/Unary"},
		hpack.HeaderField{Name: ":authority", Value: testHost},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
		hpack.HeaderField{Name: "te", Value: "trailers"})
	if code != 0 || m["grpc-status"] != "5" || m["grpc-message"] != "gone" || m[":status"] != "200" {
		t.Fatalf("response %v %v", m, code)
	}
	if !r.endStream {
		t.Fatal("trailers-only response did not end the stream on its HEADERS frame")
	}
	t.Logf("trailers-only response fields: %v", m)
}

// The HTTP/2 server rejects connection-specific fields before the relay sees
// them: the client gets 400 and the origin gets nothing.
func TestConnectionSpecificRequestFields(t *testing.T) {
	var hits atomic.Int32
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}), nil)
	r := e.raw()
	for i, extra := range [][]hpack.HeaderField{
		{{Name: "connection", Value: "keep-alive"}},
		{{Name: "te", Value: "gzip"}},
		{{Name: "transfer-encoding", Value: "chunked"}},
	} {
		fields := append([]hpack.HeaderField{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"}, {Name: ":authority", Value: testHost},
		}, extra...)
		m, code := r.request(uint32(2*i+1), fields...)
		if code != 0 || m[":status"] != "400" {
			t.Errorf("%s: response %v reset %v, want 400", extra[0].Name, m, code)
		}
	}
	// A valid request on the same connection still works and is the only one
	// that reaches the origin.
	m, code := r.request(7,
		hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":path", Value: "/"}, hpack.HeaderField{Name: ":authority", Value: testHost})
	if code != 0 || m[":status"] != "200" {
		t.Fatalf("valid request: %v %v", m, code)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("origin saw %d requests, want 1", n)
	}
}

// requestHeader drops the fields that describe one HTTP connection, whatever
// the server in front of it let through.
func TestRequestHeaderHopByHop(t *testing.T) {
	r := &http.Request{
		Method: "POST",
		Host:   testHost,
		Header: http.Header{
			"Connection":        {"keep-alive, X-Named"},
			"Proxy-Connection":  {"keep-alive"},
			"Keep-Alive":        {"timeout=5"},
			"Upgrade":           {"websocket"},
			"Transfer-Encoding": {"chunked"},
			"Te":                {"gzip"},
			"Host":              {"other.test"},
			"Trailer":           {"X-Tr"},
			"X-Named":           {"1"},
			"X-Keep":            {"v"},
		},
	}
	got := requestHeader(r.Header)
	want := http.Header{"X-Keep": {"v"}, "User-Agent": {""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requestHeader = %v, want %v", got, want)
	}
	r.Header.Set("Te", "gzip, Trailers")
	if got := requestHeader(r.Header); !reflect.DeepEqual(got["Te"], []string{"trailers"}) {
		t.Fatalf("te = %v", got["Te"])
	}
	if r.Header.Get("Connection") == "" {
		t.Fatal("requestHeader modified its input")
	}
}

// A handler that starts after shutdown must not reach the callbacks or join a
// wait group whose Wait has already returned.
func TestHandlerAfterShutdown(t *testing.T) {
	for i := 0; i < 300; i++ {
		var waited, late atomic.Bool
		hit := func() {
			if waited.Load() {
				late.Store(true)
			}
		}
		clientEnd, peer := net.Pipe()
		defer peer.Close()
		s := &session{
			ctx:    context.Background(),
			client: clientEnd,
			opts:   Options{ServerName: testHost, OnRequest: hit, Redial: func(context.Context) (net.Conn, error) { hit(); return nil, errors.New("no") }},
			conns:  make(map[*upConn]struct{}),
		}
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/", nil)
				req.Host = testHost
				s.ServeHTTP(httptest.NewRecorder(), req)
			}()
		}
		s.shutdown()
		s.wg.Wait()
		waited.Store(true)
		wg.Wait()
		if late.Load() {
			t.Fatal("a handler ran its callbacks after the session was waited for")
		}
	}
}

// A failed redial marks the upstream gone; a later successful one clears it, so
// the client connection stays open when the streams end.
func TestRedialRecoversAfterFailure(t *testing.T) {
	old := goneGrace
	goneGrace = 50 * time.Millisecond
	t.Cleanup(func() { goneGrace = old })
	a := newOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kill" {
			killConn(r)
			return
		}
		io.WriteString(w, "ok")
	}))
	var redials atomic.Int32
	e := startProxy(t, proxyConfig{dial: a.dial, redial: func(ctx context.Context) (net.Conn, error) {
		if redials.Add(1) == 1 {
			return nil, errors.New("dial refused")
		}
		return a.dial(ctx)
	}})
	c := e.client()
	resp, err := c.Get(e.url("/kill"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp, err = c.Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readAll(t, resp.Body)); resp.StatusCode != 200 || got != "ok" {
		t.Fatalf("second request: %d %q", resp.StatusCode, got)
	}
	select {
	case <-e.done:
		t.Fatal("client connection closed although the upstream recovered")
	case <-time.After(10 * goneGrace):
	}
	resp, err = c.Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	if n := e.sessions.Load(); n != 1 {
		t.Fatalf("%d sessions, want the client connection reused", n)
	}
}
