//go:build go1.26

package h2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// refusingUpstream is a plain-TCP prior-knowledge HTTP/2 server that resets
// streams: every HEADERS frame when onData is false, otherwise the first DATA
// frame of a stream.
type refusingUpstream struct {
	ln      net.Listener
	onData  bool
	headers atomic.Int32
}

func newRefusingUpstream(t *testing.T, onData bool) *refusingUpstream {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &refusingUpstream{ln: ln, onData: onData}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c)
		}
	}()
	return u
}

func (u *refusingUpstream) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", u.ln.Addr().String())
}

func (u *refusingUpstream) serve(c net.Conn) {
	defer c.Close()
	buf := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			u.headers.Add(1)
			if !u.onData {
				fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream)
			}
		case *http2.DataFrame:
			if u.onData {
				fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream)
			}
		}
	}
}

func postIdle(t *testing.T, e *proxyEnv, prefix string) (*http.Response, error) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	if prefix != "" {
		go pw.Write([]byte(prefix))
	}
	req, _ := http.NewRequest("POST", e.url("/"), pr)
	c := e.client()
	c.Timeout = 4 * time.Second
	return c.Do(req)
}

// A refused stream whose request body is idle must still end the attempt: the
// request is sent again on a fresh connection, and 502 follows when that is
// refused too.
func TestRefusedStreamIdleBodyRetries(t *testing.T) {
	up := newRefusingUpstream(t, false)
	e := startProxy(t, proxyConfig{dial: up.dial})
	resp, err := postIdle(t, e, "")
	if err != nil {
		t.Fatalf("request hung or failed: %v", err)
	}
	readAll(t, resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := e.dials.Load(); n != 2 {
		t.Fatalf("%d dials, want the initial one and one redial", n)
	}
	if n := up.headers.Load(); n != 2 {
		t.Fatalf("upstream saw %d requests, want 2", n)
	}
}

// Once a body byte reached the upstream the request is never sent again.
func TestRefusedStreamConsumedBodyNoRetry(t *testing.T) {
	up := newRefusingUpstream(t, true)
	e := startProxy(t, proxyConfig{dial: up.dial})
	resp, err := postIdle(t, e, "x")
	if err != nil {
		t.Fatalf("request hung or failed: %v", err)
	}
	readAll(t, resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := e.dials.Load(); n != 1 {
		t.Fatalf("%d dials, want no redial", n)
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (failingBody) Close() error             { return nil }

type fakeConn struct{}

func (fakeConn) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: -1, Body: failingBody{}}, nil
}
func (fakeConn) Err() error   { return nil }
func (fakeConn) Close() error { return nil }

// An aborted response must still drop the stream's reference on its upstream
// connection.
func TestAbortedResponseReleasesUpstream(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	u := &upConn{cc: fakeConn{}, nc: a}
	s := &session{ctx: context.Background(), client: a, opts: Options{ServerName: testHost}, cur: u, conns: map[*upConn]struct{}{u: {}}}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = testHost
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("expected ErrAbortHandler")
			}
		}()
		s.ServeHTTP(httptest.NewRecorder(), req)
	}()
	s.mu.Lock()
	refs := u.refs
	s.mu.Unlock()
	if refs != 0 {
		t.Fatalf("refs = %d after an aborted response", refs)
	}
}

type panicWriter struct {
	http.ResponseWriter
	writes atomic.Int32
}

func (w *panicWriter) Header() http.Header { w.writes.Add(1); panic("writer used") }
func (w *panicWriter) WriteHeader(int)     { w.writes.Add(1); panic("writer used") }

// The 1xx hook runs on a transport goroutine: it leaves the writer alone after
// the handler returned and never panics out.
func TestEarlyHintsHookGuard(t *testing.T) {
	s := &session{}
	hdr := textproto.MIMEHeader{"Link": {"</a>; rel=preload"}}
	hook := func(g *hookGuard, w http.ResponseWriter) func(int, textproto.MIMEHeader) error {
		ctx := s.traceContext(context.Background(), w, g, nil)
		return httptrace.ContextClientTrace(ctx).Got1xxResponse
	}
	w := &panicWriter{}
	g := &hookGuard{}
	g.finish()
	if err := hook(g, w)(103, hdr); err != nil || w.writes.Load() != 0 {
		t.Fatalf("hook after the handler: err %v, writer used %d times", err, w.writes.Load())
	}
	w = &panicWriter{}
	if err := hook(&hookGuard{}, w)(103, hdr); err != nil {
		t.Fatalf("hook with a panicking writer: %v", err)
	}
	if w.writes.Load() == 0 {
		t.Fatal("hook did not use the writer while the handler ran")
	}
}

// Bytes fetched from the client but not delivered when an attempt closes go to
// the next attempt exactly once.
func TestBodyReplayedToRetry(t *testing.T) {
	pr, pw := io.Pipe()
	body := &requestBody{src: pr}
	a1 := body.attempt()
	errc := make(chan error, 1)
	go func() {
		_, err := a1.Read(make([]byte, 16))
		errc <- err
	}()
	eventually(t, "a fetch in flight", func() bool {
		body.mu.Lock()
		defer body.mu.Unlock()
		return body.wait != nil
	})
	a1.Close()
	if err := <-errc; err != errBodyClosed {
		t.Fatalf("closed attempt read: %v", err)
	}
	if _, err := pw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := a1.Read(make([]byte, 16)); err != errBodyClosed {
		t.Fatalf("read after close: %v", err)
	}
	if n := body.read.Load(); n != 0 {
		t.Fatalf("%d bytes counted as delivered", n)
	}
	a2 := body.attempt()
	go pw.Close()
	got, err := io.ReadAll(a2)
	if err != nil || string(got) != "hello" {
		t.Fatalf("retry body %q, %v", got, err)
	}
	if n := body.read.Load(); n != 5 {
		t.Fatalf("%d bytes counted, want 5", n)
	}
}
