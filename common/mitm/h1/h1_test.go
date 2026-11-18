package h1

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tcpPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	if conn == nil {
		t.Fatal("accept failed")
	}
	return dialed, conn
}

type harness struct {
	t         *testing.T
	client    net.Conn // test side of the client connection
	upstream  net.Conn // test side of the upstream connection
	clientR   *bufio.Reader
	upstreamR *bufio.Reader
	requests  atomic.Int32
	done      chan error
	cancel    context.CancelFunc
}

func newHarness(t *testing.T) *harness {
	return newHarnessOptions(t, Options{})
}

// newHarnessOptions starts Serve with options; OnRequest is replaced by the harness counter.
func newHarnessOptions(t *testing.T, options Options) *harness {
	client, proxyClient := tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)
	deadline := time.Now().Add(10 * time.Second)
	client.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{
		t:         t,
		client:    client,
		upstream:  upstream,
		clientR:   bufio.NewReader(client),
		upstreamR: bufio.NewReader(upstream),
		done:      make(chan error, 1),
		cancel:    cancel,
	}
	options.OnRequest = func() { h.requests.Add(1) }
	go func() {
		h.done <- Serve(ctx, proxyClient, proxyUpstream, options)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		upstream.Close()
	})
	return h
}

func (h *harness) send(raw string) {
	h.t.Helper()
	if _, err := io.WriteString(h.client, raw); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) reply(raw string) {
	h.t.Helper()
	if _, err := io.WriteString(h.upstream, raw); err != nil {
		h.t.Fatal(err)
	}
}

func expect(t *testing.T, side string, r *bufio.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	n, err := io.ReadFull(r, got)
	if err != nil || string(got) != want {
		t.Fatalf("%s: got %q (%v), want %q", side, got[:n], err, want)
	}
}

func expectEOF(t *testing.T, side string, r *bufio.Reader) {
	t.Helper()
	extra, err := r.ReadByte()
	if err != io.EOF {
		t.Fatalf("%s: expected EOF, got %q %v", side, extra, err)
	}
}

func (h *harness) expectUpstream(want string) {
	h.t.Helper()
	expect(h.t, "upstream", h.upstreamR, want)
}
func (h *harness) expectClient(want string) { h.t.Helper(); expect(h.t, "client", h.clientR, want) }

func (h *harness) wait() error {
	h.t.Helper()
	select {
	case err := <-h.done:
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatal("Serve did not return")
		return nil
	}
}

// exchange is one request / response pair, with what each far end should see.
type exchange struct {
	clientSends   string
	upstreamGets  string
	upstreamSends string
	clientGets    string
}

func TestFraming(t *testing.T) {
	for _, tc := range []struct {
		name      string
		exchanges []exchange
		// closeUpstream closes the upstream after the last reply (close-delimited bodies).
		closeUpstream bool
		// closed means Serve ends the connection after the last exchange.
		closed bool
		err    bool
	}{
		{name: "content-length", exchanges: []exchange{{
			"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
			"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		}}},
		{name: "identical content-lengths", exchanges: []exchange{{
			"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\nhello",
			"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
			"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		}}},
		{name: "chunked request", exchanges: []exchange{{
			"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nX: 1\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
			"POST / HTTP/1.1\r\nHost: a\r\nX: 1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			"HTTP/1.1 204 No Content\r\n\r\n",
			"HTTP/1.1 204 No Content\r\n\r\n",
		}}},
		{name: "chunked response with trailers", exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X\r\nContent-Length: 99\r\n\r\n3\r\nabc\r\n0\r\nX: y\r\n\r\n",
			"HTTP/1.1 200 OK\r\nTrailer: X\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: y\r\n\r\n",
		}}},
		{name: "close-delimited response", closeUpstream: true, closed: true, exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nstream-body",
			"HTTP/1.1 200 OK\r\nServer: x\r\nConnection: close\r\n\r\nstream-body",
		}}},
		{name: "head then get", exchanges: []exchange{{
			"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
		}, {
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
		}}},
		{name: "204 and 304 have no body", exchanges: []exchange{{
			"GET /a HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET /a HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n",
			"HTTP/1.1 204 No Content\r\n\r\n",
		}, {
			"GET /b HTTP/1.1\r\nHost: a\r\nIf-None-Match: \"x\"\r\n\r\n",
			"GET /b HTTP/1.1\r\nHost: a\r\nIf-None-Match: \"x\"\r\n\r\n",
			"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\nETag: \"x\"\r\n\r\n",
			"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\nETag: \"x\"\r\n\r\n",
		}, {
			"GET /c HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET /c HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		}}},
		{name: "1xx then 200", exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		}}},
		{name: "keep-alive", exchanges: []exchange{{
			"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1",
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1",
		}, {
			"GET /2 HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
			"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\n2",
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2",
		}}},
		{name: "HTTP/1.0", closed: true, exchanges: []exchange{{
			"GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
			"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
			"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc",
		}}},
		{name: "HTTP/1.0 response", closed: true, exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
			"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
		}}},
		{name: "client connection close", closed: true, exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
		}}},
		{name: "upstream connection close", closed: true, exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
		}}},
		{name: "header order and case", exchanges: []exchange{{
			"GET / HTTP/1.1\r\nhost: a\r\nx-lower: 1\r\nX-UPPER: 2\r\nConnection: X-Hop\r\nX-Hop: drop\r\nMixed-Case: 3\r\nKeep-Alive: 1\r\nProxy-Connection: keep-alive\r\nTE: trailers\r\nx-lower: 4\r\n\r\n",
			"GET / HTTP/1.1\r\nhost: a\r\nx-lower: 1\r\nX-UPPER: 2\r\nMixed-Case: 3\r\nx-lower: 4\r\n\r\n",
			"HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\nX-Z: z\r\nx-a: a\r\nContent-Length: 0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\nX-Z: z\r\nx-a: a\r\nContent-Length: 0\r\n\r\n",
		}}},
		{name: "h2c upgrade stripped", exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nAccept: */*\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		}}},
		{name: "invalid response framing", closed: true, err: true, exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
			badGateway,
		}}},
		{name: "unsolicited 101", closed: true, err: true, exchanges: []exchange{{
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
			badGateway,
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			for i, e := range tc.exchanges {
				h.send(e.clientSends)
				h.expectUpstream(e.upstreamGets)
				h.reply(e.upstreamSends)
				if i == len(tc.exchanges)-1 && tc.closeUpstream {
					h.upstream.Close()
				}
				h.expectClient(e.clientGets)
			}
			if tc.closed {
				expectEOF(t, "client", h.clientR)
			} else {
				h.client.Close()
			}
			err := h.wait()
			if tc.err != (err != nil) {
				t.Fatalf("Serve = %v", err)
			}
			if int(h.requests.Load()) != len(tc.exchanges) {
				t.Fatalf("OnRequest called %d times", h.requests.Load())
			}
		})
	}
}

func TestBadRequest(t *testing.T) {
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
		"GARBAGE\r\n\r\n",
		"GET / HTTP/1.1\nHost: a\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
	} {
		h := newHarness(t)
		h.send(raw)
		h.expectClient(badRequest)
		expectEOF(t, "client", h.clientR)
		h.client.Close()
		expectEOF(t, "upstream", h.upstreamR)
		if err := h.wait(); err == nil {
			t.Fatalf("%q: Serve returned nil", raw)
		}
		if h.requests.Load() != 0 {
			t.Fatalf("%q: forwarded", raw)
		}
	}
}

func TestExpectContinue(t *testing.T) {
	h := newHarness(t)
	h.send("POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.expectUpstream("POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.reply("HTTP/1.1 100 Continue\r\n\r\n")
	h.expectClient("HTTP/1.1 100 Continue\r\n\r\n")
	h.send("hello")
	h.expectUpstream("hello")
	h.reply("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

func TestExpectContinueRejected(t *testing.T) {
	h := newHarness(t)
	h.send("POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.expectUpstream("POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.reply("HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n")
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

func TestLargeBodies(t *testing.T) {
	h := newHarness(t)
	body := strings.Repeat("0123456789abcdef", 64*1024)
	go io.WriteString(h.client, "PUT /big HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"100000\r\n"+body+"\r\n0\r\n\r\n")
	head := "PUT /big HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
	h.expectUpstream(head)
	req := &bytes.Buffer{}
	reader := newChunkedBody(h.upstreamR)
	if _, err := io.Copy(req, reader); err != nil {
		t.Fatal(err)
	}
	if req.String() != body {
		t.Fatalf("request body length %d", req.Len())
	}
	go io.WriteString(h.upstream, "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n"+body)
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n" + body)
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeEcho(t *testing.T) {
	h := newHarness(t)
	h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\nearly")
	h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n")
	h.reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\nhi")
	h.expectClient("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\nhi")
	h.expectUpstream("early")
	for _, message := range []string{"ping", "second message"} {
		h.send(message)
		got := make([]byte, len(message))
		if _, err := io.ReadFull(h.upstreamR, got); err != nil {
			t.Fatal(err)
		}
		h.reply(strings.ToUpper(string(got)))
		h.expectClient(strings.ToUpper(message))
	}
	h.client.Close()
	expectEOF(t, "upstream", h.upstreamR)
	h.upstream.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

func TestContextCancel(t *testing.T) {
	h := newHarness(t)
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.cancel()
	if err := h.wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v", err)
	}
	expectEOF(t, "client", h.clientR)
	expectEOF(t, "upstream", h.upstreamR)
}

func TestUpstreamClosedEarly(t *testing.T) {
	h := newHarness(t)
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.upstream.Close()
	h.expectClient(badGateway)
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err == nil {
		t.Fatal("expected error")
	}
}

type chunkedBody struct {
	r *bufio.Reader
	n int
}

// newChunkedBody is an independent minimal decoder so the test does not rely on httpx alone.
func newChunkedBody(r *bufio.Reader) io.Reader {
	return &chunkedBody{r: r}
}

func (c *chunkedBody) Read(p []byte) (int, error) {
	if c.n == 0 {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		var size int
		for _, ch := range strings.TrimSpace(line) {
			switch {
			case ch >= '0' && ch <= '9':
				size = size*16 + int(ch-'0')
			case ch >= 'a' && ch <= 'f':
				size = size*16 + int(ch-'a'+10)
			}
		}
		if size == 0 {
			c.r.ReadString('\n')
			return 0, io.EOF
		}
		c.n = size
	}
	if len(p) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= n
	if c.n == 0 {
		c.r.Discard(2)
	}
	return n, err
}

func BenchmarkKeepAliveGET(b *testing.B) {
	const request = "GET /bench HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 16384\r\n\r\n" + strings.Repeat("x", 16384)
	client, proxyClient := tcpPair(b)
	proxyUpstream, upstream := tcpPair(b)
	defer client.Close()
	defer upstream.Close()
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), proxyClient, proxyUpstream, Options{OnRequest: func() {}})
	}()
	go func() {
		requestBuffer := make([]byte, len(request))
		responseBytes := []byte(response)
		for {
			if _, err := io.ReadFull(upstream, requestBuffer); err != nil {
				return
			}
			if _, err := upstream.Write(responseBytes); err != nil {
				return
			}
		}
	}()
	requestBytes := []byte(request)
	responseBuffer := make([]byte, len(response))
	roundTrip := func() {
		if _, err := client.Write(requestBytes); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(client, responseBuffer); err != nil {
			b.Fatal(err)
		}
	}
	roundTrip()
	if string(responseBuffer) != response {
		b.Fatal("response mismatch")
	}
	b.SetBytes(int64(len(response)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		roundTrip()
	}
	b.StopTimer()
	client.Close()
	<-done
}

func TestAltSvcFiltered(t *testing.T) {
	for _, test := range []struct {
		name string
		in   string
		out  string
	}{
		{"single h3", "Alt-Svc: h3=\":443\"; ma=86400\r\n", ""},
		{"mixed", "Alt-Svc: h3=\":443\", h2=\":8443\"\r\n", "Alt-Svc: h2=\":8443\"\r\n"},
		{"multiple fields", "Alt-Svc: h3=\":443\"\r\nAlt-Svc: h2=\":8443\"\r\nAlt-Svc: h3-29=\":443\"\r\n", "Alt-Svc: h2=\":8443\"\r\n"},
		{"clear", "Alt-Svc: clear\r\n", "Alt-Svc: clear\r\n"},
		{"untouched", "Alt-Svc: h2=\"alt.example.com:443\"\r\n", "Alt-Svc: h2=\"alt.example.com:443\"\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
			h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
			h.reply("HTTP/1.1 200 OK\r\n" + test.in + "Content-Length: 0\r\n\r\n")
			h.expectClient("HTTP/1.1 200 OK\r\n" + test.out + "Content-Length: 0\r\n\r\n")
			h.client.Close()
			if err := h.wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
