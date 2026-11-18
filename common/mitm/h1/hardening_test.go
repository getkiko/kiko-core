package h1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio/deadline"
)

// expectNothing checks that the client connection closes without a single byte.
func expectNothing(t *testing.T, side string, r *bufio.Reader) {
	t.Helper()
	got, _ := io.ReadAll(r)
	if len(got) != 0 {
		t.Fatalf("%s: got %q, want a plain close", side, got)
	}
}

// Rejected request heads are answered with the status matching the error (RFC 9112 / 9110),
// then the connection closes; nothing reaches the upstream.
func TestRequestErrorReplies(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		reply string
	}{
		{"GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\nHost: a\r\n\r\n", uriTooLong},
		{"GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("a", 70000) + "\r\n\r\n", headerTooLarge},
		{"GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("A: b\r\n", 129) + "\r\n", headerTooLarge},
		{"GET / HTTP/2.0\r\nHost: a\r\n\r\n", versionNotSupported},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", notImplemented},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", badRequest},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", badRequest},
		{"GET / HTTP/1.1\r\n\r\n", badRequest},
		{"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", badRequest},
		{"GET / HTTP/1.1\r\nHost: a b\r\n\r\n", badRequest},
		{"GET / HTTP/1.1\r\nHost : a\r\n\r\n", badRequest},
		{"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n", badRequest},
		{"GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n", badRequest},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nhello", badRequest},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n", badRequest},
		{"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\nContent-Length: 5\r\n\r\nhello", badRequest},
		{"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", badRequest},
	} {
		h := newHarness(t)
		h.send(tc.raw)
		h.expectClient(tc.reply)
		expectEOF(t, "client", h.clientR)
		h.client.Close()
		expectEOF(t, "upstream", h.upstreamR)
		if err := h.wait(); err == nil {
			t.Fatalf("%.50q: Serve returned nil", tc.raw)
		}
		if h.requests.Load() != 0 {
			t.Fatalf("%.50q: forwarded", tc.raw)
		}
	}
}

// A request head cut short by the client gets no reply.
func TestTruncatedRequestSendsNothing(t *testing.T) {
	h := newHarness(t)
	h.send("GET / HTTP/1.1\r\nHost: a\r\n")
	h.client.(*net.TCPConn).CloseWrite()
	expectNothing(t, "client", h.clientR)
	h.wait()
}

// A zero Content-Length, however repeated, is forwarded as one "Content-Length: 0" on both sides;
// non-canonical values are rewritten, also on bodiless responses.
func TestZeroContentLengthNormalized(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ request, response string }{
		{"Content-Length: 0, 0\r\n", "Content-Length: 0\r\nContent-Length: 0\r\n"},
		{"Content-Length: 0\r\ncontent-length: 0\r\n", "Content-Length: 0,0\r\n"},
		{"Content-Length: 00\r\n", "Content-Length: 000\r\n"},
	} {
		h.send("POST /a HTTP/1.1\r\nHost: a\r\n" + tc.request + "\r\n")
		h.expectUpstream("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n")
		h.reply("HTTP/1.1 200 OK\r\n" + tc.response + "X: y\r\n\r\n")
		h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: y\r\n\r\n")
	}
	h.send("POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: 05\r\n\r\nhello")
	h.expectUpstream("POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.send("HEAD /c HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("HEAD /c HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0, 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

// An HTTP/1.0 response with Transfer-Encoding has faulty framing (RFC 9112 section 6.1): the
// body runs until close and is forwarded verbatim with its Transfer-Encoding, without
// Content-Length, and the connection closes.
func TestHTTP10ResponseTransferEncoding(t *testing.T) {
	h := newHarness(t)
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\nX: y\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	h.upstream.Close()
	h.expectClient("HTTP/1.0 200 OK\r\nX: y\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

// Transfer codings before the final chunked stay declared while only chunked is re-encoded;
// a list not ending in chunked delimits the body by close and is forwarded verbatim.
func TestResponseTransferCodings(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nGZ!\r\n0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nGZ!\r\n0\r\n\r\n")
	h.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 1\r\n\r\nraw bytes")
	h.upstream.Close()
	h.expectClient("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nConnection: close\r\n\r\nraw bytes")
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
	if h.requests.Load() != 2 {
		t.Fatalf("requests = %d", h.requests.Load())
	}

	// An HTTP/1.0 client cannot receive transfer codings.
	for _, response := range []string{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nGZ!\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nGZ!",
	} {
		h = newHarness(t)
		h.send("GET / HTTP/1.0\r\nHost: a\r\n\r\n")
		h.expectUpstream("GET / HTTP/1.0\r\nHost: a\r\n\r\n")
		h.reply(response)
		h.expectClient(badGateway)
		expectEOF(t, "client", h.clientR)
		if err := h.wait(); err == nil {
			t.Fatal("expected error")
		}
	}
}

// Trailer fields are forwarded when the outgoing body is chunked, minus the fields a trailer
// must not carry; an HTTP/1.0 client gets the decoded body without them.
func TestTrailers(t *testing.T) {
	h := newHarness(t)
	h.send("POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n" +
		"3\r\nabc\r\n0\r\nX-Sum: 1\r\nHost: evil\r\nContent-Length: 5\r\nAuthorization: x\r\n\r\n")
	h.expectUpstream("POST /u HTTP/1.1\r\nHost: a\r\nTrailer: X-Sum\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTrailer: Grpc-Status, grpc-message\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nGrpc-Status: 0\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=b\r\ngrpc-message: fine\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nTrailer: Grpc-Status, grpc-message\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nGrpc-Status: 0\r\ngrpc-message: fine\r\n\r\n")
	// Only denied fields: a bare last chunk.
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nContent-Length: 2\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}

	h = newHarness(t)
	h.send("GET / HTTP/1.0\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.0\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTrailer: X-Sum\r\nTransfer-Encoding: chunked\r\nX: y\r\n\r\n2\r\nok\r\n0\r\nX-Sum: 1\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nX: y\r\nConnection: close\r\n\r\nok")
	expectEOF(t, "client", h.clientR)
	h.wait()

	// A malformed trailer section is a broken body: the session ends.
	h = newHarness(t)
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX : 1\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n")
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err == nil {
		t.Fatal("expected error")
	}
}

// Expect is removed from HTTP/1.0 requests (RFC 9110 section 10.1.1).
func TestExpectStrippedFromHTTP10(t *testing.T) {
	h := newHarness(t)
	h.send("POST / HTTP/1.0\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi")
	h.expectUpstream("POST / HTTP/1.0\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi")
	h.reply("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	expectEOF(t, "client", h.clientR)
	h.wait()
}

// An upstream answering an Expect: 100-continue request with a final status before the body
// is relayed, and the connection closes since the body may never come.
func TestExpectContinueEarlyFinal(t *testing.T) {
	for _, status := range []string{"417 Expectation Failed", "401 Unauthorized"} {
		h := newHarness(t)
		h.send("PUT /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
		h.expectUpstream("PUT /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
		h.reply("HTTP/1.1 " + status + "\r\nContent-Length: 4\r\n\r\ndeny")
		h.expectClient("HTTP/1.1 " + status + "\r\nContent-Length: 4\r\n\r\ndeny")
		expectEOF(t, "client", h.clientR)
		if err := h.wait(); err != nil {
			t.Fatal(err)
		}
	}
}

// A client that stops waiting for 100 sends its body anyway; it reaches the upstream.
func TestExpectContinueWithoutInterim(t *testing.T) {
	h := newHarness(t)
	h.send("PUT /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.expectUpstream("PUT /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	time.Sleep(50 * time.Millisecond)
	h.send("hello")
	h.expectUpstream("hello")
	h.reply("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

// Interim responses before a 101 or a CONNECT 2xx are relayed, then the tunnel starts.
func TestInterimBeforeSwitch(t *testing.T) {
	h := newHarness(t)
	h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.reply("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	h.expectClient("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	tunnelEcho(t, h)

	h = newHarness(t)
	h.send("CONNECT inner:443 HTTP/1.1\r\nHost: inner:443\r\n\r\n")
	h.expectUpstream("CONNECT inner:443 HTTP/1.1\r\nHost: inner:443\r\n\r\n")
	h.reply("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n")
	h.expectClient("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n")
	tunnelEcho(t, h)
}

// A 101 that switches to a protocol the client did not offer is refused.
func TestUnofferedSwitchRefused(t *testing.T) {
	for _, upgrade := range []string{"Upgrade: h2c\r\n", "Upgrade: websocket, h2c\r\n", ""} {
		h := newHarness(t)
		h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		h.reply("HTTP/1.1 101 Switching Protocols\r\n" + upgrade + "Connection: Upgrade\r\n\r\n")
		h.expectClient(badGateway)
		expectEOF(t, "client", h.clientR)
		if err := h.wait(); err == nil {
			t.Fatalf("%q: Serve returned nil", upgrade)
		}
	}
}

// A refused upgrade is a normal response and the connection keeps working; Upgrade without a
// Connection: upgrade token, or in an HTTP/1.0 request, is removed.
func TestUpgradeNotSwitched(t *testing.T) {
	h := newHarness(t)
	h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.reply("HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\nno")
	h.expectClient("HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\nno")
	h.send("GET /plain HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n")
	h.expectUpstream("GET /plain HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}

	h = newHarness(t)
	h.send("GET / HTTP/1.0\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.0\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
	h.expectClient(badGateway)
	h.wait()
}

// The client may stay silent for IdleTimeout between requests; then the session ends
// normally without a byte written.
func TestIdleTimeout(t *testing.T) {
	h := newHarnessOptions(t, Options{IdleTimeout: 100 * time.Millisecond})
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	start := time.Now()
	expectNothing(t, "client", h.clientR)
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("closed after %v", elapsed)
	}
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, "upstream", h.upstreamR)

	// Also before the first request.
	h = newHarnessOptions(t, Options{IdleTimeout: 50 * time.Millisecond})
	expectNothing(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

// A request head that stalls past HeaderTimeout ends the connection without a reply.
func TestHeaderTimeout(t *testing.T) {
	h := newHarnessOptions(t, Options{HeaderTimeout: 100 * time.Millisecond})
	h.send("GET / HTTP/1.1\r\nHost: a\r\n")
	start := time.Now()
	expectNothing(t, "client", h.clientR)
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("closed after %v", elapsed)
	}
	if err := h.wait(); err == nil {
		t.Fatal("expected error")
	}
	expectEOF(t, "upstream", h.upstreamR)
	if h.requests.Load() != 0 {
		t.Fatal("forwarded")
	}
}

// The timeouts only cover reading request heads: a slow response, a slow request body and a
// silent tunnel all outlast them, and the client watch (which also uses read deadlines) keeps
// working around them.
func TestTimeoutsSpareBodiesAndTunnels(t *testing.T) {
	options := Options{IdleTimeout: 60 * time.Millisecond, HeaderTimeout: 60 * time.Millisecond}
	h := newHarnessOptions(t, options)
	h.send("GET /poll HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /poll HTTP/1.1\r\nHost: a\r\n\r\n")
	time.Sleep(250 * time.Millisecond)
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
	time.Sleep(250 * time.Millisecond)
	h.reply("1\r\nb\r\n0\r\n\r\n")
	h.expectClient("1\r\nb\r\n0\r\n\r\n")
	h.send("POST /slow HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nab")
	h.expectUpstream("POST /slow HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nab")
	time.Sleep(250 * time.Millisecond)
	h.send("cd")
	h.expectUpstream("cd")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	h.expectClient("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	time.Sleep(250 * time.Millisecond)
	h.send("ping")
	h.expectUpstream("ping")
	h.reply("pong")
	h.expectClient("pong")
	h.client.Close()
	expectEOF(t, "upstream", h.upstreamR)
	h.upstream.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
	if h.requests.Load() != 3 {
		t.Fatalf("requests = %d", h.requests.Load())
	}
}

// Upstream bytes beyond a complete response are never relayed as the answer to the next
// request: without Redial the client connection closes, with Redial the upstream is replaced.
func TestUnsolicitedUpstreamBytes(t *testing.T) {
	const extra = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED"
	for _, response := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
	} {
		forwarded := response
		h := newHarness(t)
		h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
		h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
		h.reply(response + extra)
		h.expectClient(forwarded)
		expectNothing(t, "client", h.clientR)
		h.wait()

		r := newRedialHarness(t)
		r.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
		r.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
		r.reply(response + extra)
		r.expectClient(forwarded)
		r.switchUpstream()
		r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
		r.reply("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nreal")
		r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nreal")
		r.client.Close()
		if err := r.wait(); err != nil {
			t.Fatal(err)
		}
	}
}

// redialHarness hands each redialed upstream connection's far end to the test.
type redialHarness struct {
	*harness
	dials     atomic.Int32
	fail      atomic.Bool
	upstreams chan net.Conn
}

func newRedialHarness(t *testing.T) *redialHarness {
	return newRedialHarnessOptions(t, Options{})
}

func newRedialHarnessOptions(t *testing.T, options Options) *redialHarness {
	r := &redialHarness{upstreams: make(chan net.Conn, 4)}
	options.Redial = func(ctx context.Context) (net.Conn, error) {
		r.dials.Add(1)
		if r.fail.Load() {
			return nil, errors.New("dial failed")
		}
		proxySide, far := tcpPair(t)
		far.SetDeadline(time.Now().Add(10 * time.Second))
		t.Cleanup(func() { far.Close() })
		r.upstreams <- far
		return proxySide, nil
	}
	r.harness = newHarnessOptions(t, options)
	return r
}

// switchUpstream makes the harness talk to the latest redialed upstream.
func (r *redialHarness) switchUpstream() {
	r.t.Helper()
	select {
	case conn := <-r.upstreams:
		r.upstream = conn
		r.upstreamR = bufio.NewReader(conn)
	case <-time.After(5 * time.Second):
		r.t.Fatal("no redial")
	}
}

func (r *redialHarness) roundTrip(path string) {
	r.t.Helper()
	r.send("GET " + path + " HTTP/1.1\r\nHost: a\r\n\r\n")
	r.expectUpstream("GET " + path + " HTTP/1.1\r\nHost: a\r\n\r\n")
	r.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
}

// With Redial, an upstream that closes while idle is replaced on the next request (whatever
// its method) and the client connection stays.
func TestRedialAfterIdleClose(t *testing.T) {
	r := newRedialHarness(t)
	r.roundTrip("/1")
	r.upstream.Close()
	time.Sleep(50 * time.Millisecond)
	r.send("POST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi")
	r.switchUpstream()
	r.expectUpstream("POST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi")
	r.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	// The new connection is watched and reused like the first.
	r.roundTrip("/3")
	r.upstream.Write([]byte("HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n"))
	time.Sleep(50 * time.Millisecond)
	r.send("GET /4 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.switchUpstream()
	r.expectUpstream("GET /4 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	r.client.Close()
	if err := r.wait(); err != nil {
		t.Fatal(err)
	}
	if r.dials.Load() != 2 || r.requests.Load() != 4 {
		t.Fatalf("dials %d requests %d", r.dials.Load(), r.requests.Load())
	}
}

// An idempotent request without content that meets a reused upstream closing before any
// response byte is resent once on a redialed connection; OnRequest counts it once.
func TestRedialRetriesIdempotentRequest(t *testing.T) {
	for _, head := range []string{
		"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n",
		"DELETE /2 HTTP/1.1\r\nHost: a\r\n\r\n",
		"POST /2 HTTP/1.1\r\nHost: a\r\nIdempotency-Key: k\r\n\r\n",
	} {
		r := newRedialHarness(t)
		r.roundTrip("/1")
		r.send(head)
		r.expectUpstream(head)
		r.upstream.Close()
		r.switchUpstream()
		r.expectUpstream(head)
		r.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		r.roundTrip("/3")
		r.client.Close()
		if err := r.wait(); err != nil {
			t.Fatal(err)
		}
		if r.dials.Load() != 1 || r.requests.Load() != 3 {
			t.Fatalf("%q: dials %d requests %d", head, r.dials.Load(), r.requests.Load())
		}
	}
}

// A non-idempotent request, or one with content, is not resent: the client connection closes
// so that the client decides (A's behaviour).
func TestRedialSkipsUnsafeRequests(t *testing.T) {
	for _, request := range []string{
		"POST /2 HTTP/1.1\r\nHost: a\r\n\r\n",
		"PUT /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi",
	} {
		r := newRedialHarness(t)
		r.roundTrip("/1")
		r.send(request)
		r.expectUpstream(request)
		r.upstream.Close()
		expectNothing(t, "client", r.clientR)
		r.wait()
		if r.dials.Load() != 0 {
			t.Fatalf("%q: redialed", request)
		}
	}
}

// A request that failed on a redialed connection is not retried again: 502.
func TestRedialOnce(t *testing.T) {
	r := newRedialHarness(t)
	r.roundTrip("/1")
	r.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.upstream.Close()
	r.switchUpstream()
	r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.upstream.Close()
	r.expectClient(badGateway)
	expectEOF(t, "client", r.clientR)
	if err := r.wait(); err == nil {
		t.Fatal("expected error")
	}
	if r.dials.Load() != 1 {
		t.Fatalf("dials %d", r.dials.Load())
	}
}

// A failed redial on a reused session closes the client connection without an answer, both
// when the upstream died while idle and when a sent request is to be retried.
func TestRedialFailure(t *testing.T) {
	r := newRedialHarness(t)
	r.fail.Store(true)
	r.roundTrip("/1")
	r.upstream.Close()
	time.Sleep(50 * time.Millisecond)
	r.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	expectNothing(t, "client", r.clientR)
	if err := r.wait(); err != nil {
		t.Fatal(err)
	}
	if r.dials.Load() != 1 {
		t.Fatalf("dials %d", r.dials.Load())
	}

	r = newRedialHarness(t)
	r.fail.Store(true)
	r.roundTrip("/1")
	r.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.upstream.Close()
	expectNothing(t, "client", r.clientR)
	r.wait()
	if r.dials.Load() != 1 {
		t.Fatalf("dials %d", r.dials.Load())
	}
}

// Without Redial an upstream idle close still ends the client connection (A's behaviour).
func TestNoRedialKeepsBehaviour(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.upstream.Close()
	expectNothing(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

// Cancelling the context during a redial closes the connection the dial returns, and the
// session's current upstream.
func TestRedialCancelled(t *testing.T) {
	client, proxyClient := tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)
	defer client.Close()
	defer upstream.Close()
	ctx, cancel := context.WithCancel(context.Background())
	dialing := make(chan struct{})
	late := make(chan net.Conn, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, proxyClient, proxyUpstream, Options{Redial: func(ctx context.Context) (net.Conn, error) {
			close(dialing)
			<-ctx.Done()
			proxySide, far := tcpPair(t)
			late <- far
			return proxySide, nil
		}})
	}()
	clientR := bufio.NewReader(client)
	upstreamR := bufio.NewReader(upstream)
	io.WriteString(client, "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	expect(t, "upstream", upstreamR, "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	io.WriteString(upstream, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	expect(t, "client", clientR, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	upstream.Close()
	time.Sleep(50 * time.Millisecond)
	io.WriteString(client, "GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	<-dialing
	cancel()
	if err := waitServe(t, done, 3*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v", err)
	}
	far := <-late
	defer far.Close()
	far.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := far.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late connection not closed: %d %v", n, err)
	}
}

// Sessions with redials leave no goroutine behind.
func TestRedialNoGoroutineLeak(t *testing.T) {
	settle := func() int {
		n := runtime.NumGoroutine()
		for i := 0; i < 50; i++ {
			time.Sleep(20 * time.Millisecond)
			if m := runtime.NumGoroutine(); m == n {
				return n
			} else {
				n = m
			}
		}
		return n
	}
	before := settle()
	for i := 0; i < 5; i++ {
		t.Run("", func(t *testing.T) {
			r := newRedialHarness(t)
			r.roundTrip("/1")
			r.upstream.Close()
			time.Sleep(20 * time.Millisecond)
			r.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
			r.switchUpstream()
			r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
			r.upstream.Close()
			r.expectClient(badGateway)
			r.wait()
		})
	}
	if after := settle(); after > before+2 {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines %d -> %d\n%s", before, after, buf[:runtime.Stack(buf, true)])
	}
}

func BenchmarkKeepAliveChunked(b *testing.B) {
	const request = "GET /bench HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n"
	const head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
	body := strings.Repeat("x", 16384)
	response := head + "4000\r\n" + body + "\r\n0\r\n\r\n"
	benchRelay(b, request, len(request), response, int64(len(body)), func(r *bufio.Reader) error {
		if _, err := r.Discard(len(head)); err != nil {
			return err
		}
		for {
			line, err := r.ReadSlice('\n')
			if err != nil {
				return err
			}
			size := 0
			for _, c := range line[:len(line)-2] {
				switch {
				case c >= '0' && c <= '9':
					size = size<<4 | int(c-'0')
				case c >= 'a' && c <= 'f':
					size = size<<4 | int(c-'a'+10)
				}
			}
			if _, err = r.Discard(size + 2); err != nil {
				return err
			}
			if size == 0 {
				return nil
			}
		}
	})
}

func BenchmarkPostLength(b *testing.B) {
	body := strings.Repeat("x", 16384)
	request := "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 16384\r\n\r\n" + body
	const response = "HTTP/1.1 204 No Content\r\n\r\n"
	benchRelay(b, request, len(request), response, int64(len(body)), func(r *bufio.Reader) error {
		_, err := r.Discard(len(response))
		return err
	})
}

// BenchmarkKeepAliveGETDeadlineConn relays over sing's pipe-deadline connections, as when the
// decrypted connections lack native read deadlines, with and without the head timeouts.
func BenchmarkKeepAliveGETDeadlineConn(b *testing.B) {
	const request = "GET /bench HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 16384\r\n\r\n" + strings.Repeat("x", 16384)
	read := func(r *bufio.Reader) error {
		_, err := r.Discard(len(response))
		return err
	}
	for _, tc := range []struct {
		name    string
		options Options
	}{
		{"timeouts", Options{}},
		{"no-timeouts", Options{IdleTimeout: -1, HeaderTimeout: -1}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			benchRelayOptions(b, tc.options, true, request, len(request), response, 16384, read)
		})
	}
}

// benchRelay runs keep-alive round trips through Serve: the upstream reads upstreamLength bytes
// per request and writes response; readResponse consumes one response on the client.
func benchRelay(b *testing.B, request string, upstreamLength int, response string, bytesPerOp int64, readResponse func(r *bufio.Reader) error) {
	benchRelayOptions(b, Options{}, false, request, upstreamLength, response, bytesPerOp, readResponse)
}

func benchRelayOptions(b *testing.B, options Options, pipeDeadline bool, request string, upstreamLength int, response string, bytesPerOp int64, readResponse func(r *bufio.Reader) error) {
	client, proxyClient := tcpPair(b)
	proxyUpstream, upstream := tcpPair(b)
	defer client.Close()
	defer upstream.Close()
	if pipeDeadline {
		proxyClient = deadline.NewConn(proxyClient)
		proxyUpstream = deadline.NewConn(proxyUpstream)
	}
	options.OnRequest = func() {}
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), proxyClient, proxyUpstream, options)
	}()
	go func() {
		requestBuffer := make([]byte, upstreamLength)
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
	clientR := bufio.NewReaderSize(client, 64*1024)
	roundTrip := func() {
		if _, err := client.Write(requestBytes); err != nil {
			b.Fatal(err)
		}
		if err := readResponse(clientR); err != nil {
			b.Fatal(err)
		}
	}
	roundTrip()
	b.SetBytes(bytesPerOp)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		roundTrip()
	}
	b.StopTimer()
	client.Close()
	<-done
}

// The head timer interrupts a read only after its expiry, and disarming restores reads.
func TestHeadTimer(t *testing.T) {
	for _, wrap := range []func(net.Conn) net.Conn{
		func(conn net.Conn) net.Conn { return conn },
		func(conn net.Conn) net.Conn { return deadline.NewConn(conn) },
	} {
		a, b := tcpPair(t)
		defer a.Close()
		defer b.Close()
		conn := wrap(b)
		var timer headTimer
		timer.init(conn)
		// Disarmed before expiry: nothing happens.
		timer.arm(20 * time.Millisecond)
		timer.disarm()
		time.Sleep(40 * time.Millisecond)
		go a.Write([]byte("x"))
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		// Expired: the read fails with a timeout.
		timer.arm(30 * time.Millisecond)
		start := time.Now()
		_, err := conn.Read(make([]byte, 1))
		if !isTimeout(err) || time.Since(start) < 20*time.Millisecond {
			t.Fatalf("read after %v: %v", time.Since(start), err)
		}
		// Disarmed after firing: reads work again.
		timer.disarm()
		go a.Write([]byte("y"))
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		// Re-armed further out: an earlier expiry does not fire.
		timer.arm(10 * time.Millisecond)
		timer.arm(time.Hour)
		time.Sleep(30 * time.Millisecond)
		go a.Write([]byte("z"))
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		timer.disarm()
	}
}

// Re-arming after an expiry that no read observed (the idle timer firing right after the first
// byte arrived) clears the past deadline: the next read waits for the new expiry.
func TestHeadTimerRearmAfterFire(t *testing.T) {
	a, b := tcpPair(t)
	defer a.Close()
	defer b.Close()
	var timer headTimer
	timer.init(b)
	timer.arm(5 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	timer.arm(time.Second)
	go func() {
		time.Sleep(20 * time.Millisecond)
		a.Write([]byte("x"))
	}()
	if _, err := io.ReadFull(b, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	timer.disarm()
}

// Content-Length beside Transfer-Encoding on a bodiless response is overridden and dropped
// with the Transfer-Encoding, however malformed.
func TestBodilessTransferEncodingDropsContentLength(t *testing.T) {
	h := newHarness(t)
	h.send("HEAD /c HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("HEAD /c HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5, 6\r\nX: y\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nX: y\r\n\r\n")
	h.send("GET /d HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /d HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\nContent-Length: -1\r\n\r\n")
	h.expectClient("HTTP/1.1 304 Not Modified\r\n\r\n")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}
}

// Content-Length on responses without content: dropped from 1xx (also the 101 of a switch)
// and 204, kept on HEAD and 304 answers as one canonical value (RFC 9110 section 8.6).
func TestBodilessContentLength(t *testing.T) {
	h := newHarness(t)
	h.send("GET /a HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /a HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.0 100 \r\n0:\r\nContent-Length:00A0\r\n\r\nHTTP/1.1 103 Early Hints\r\nContent-Length: 5\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.0 100 \r\n0: \r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	for _, tc := range []struct{ request, response, forwarded string }{
		{"HEAD /b", "HTTP/1.1 200 OK\r\nContent-Length: 7, 7\r\nContent-Length: 07\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"},
		{"HEAD /c", "HTTP/1.1 200 OK\r\nContent-Length: 0, 0\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{"GET /d", "HTTP/1.1 304 Not Modified\r\nContent-Length: 12,12\r\n\r\n", "HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n"},
		{"GET /e", "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n"},
		{"HEAD /f", "HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n"},
	} {
		h.send(tc.request + " HTTP/1.1\r\nHost: a\r\n\r\n")
		h.expectUpstream(tc.request + " HTTP/1.1\r\nHost: a\r\n\r\n")
		h.reply(tc.response)
		h.expectClient(tc.forwarded)
	}
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatal(err)
	}

	h = newHarness(t)
	h.send("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.expectUpstream("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	h.reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 4\r\n\r\n")
	h.expectClient("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	tunnelEcho(t, h)
}
