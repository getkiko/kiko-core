package h1

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio/deadline"
)

func waitServe(t *testing.T, done chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("Serve still running after %v", within)
		return nil
	}
}

// An upstream that closes an idle keep-alive connection ends the client connection at once,
// without a synthesized 502.
func TestIdleUpstreamCloseEndsClient(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.upstream.Close()
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// A request racing with the idle close of a reused upstream connection gets a plain close.
func TestReusedUpstreamClosedBeforeResponse(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.upstream.Close()
	got, _ := io.ReadAll(h.clientR)
	if len(got) != 0 {
		t.Fatalf("client got %q, want a plain close", got)
	}
	h.wait()
}

// The first exchange on a connection still answers 502 when the upstream closes.
func TestFirstExchangeUpstreamCloseAnswers502(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.upstream.Close()
	h.expectClient(badGateway)
	h.wait()
}

func startLongPoll(t *testing.T, body string) (client net.Conn, proxyClient net.Conn, upstream net.Conn, done chan error) {
	t.Helper()
	client, proxyClient = tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)
	t.Cleanup(func() {
		client.Close()
		upstream.Close()
	})
	done = make(chan error, 1)
	go func() { done <- Serve(context.Background(), proxyClient, proxyUpstream, Options{}) }()
	request := "GET /poll HTTP/1.1\r\nHost: a\r\n\r\n"
	if body != "" {
		request = "POST /poll HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\n" + body
	}
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, "upstream", bufio.NewReader(upstream), request[:len(request)-len(body)])
	return
}

// registerInterrupt closes the routed client connection while the upstream holds the response.
func TestClientInterruptWhileWaitingResponse(t *testing.T) {
	for _, body := range []string{"", "data"} {
		_, proxyClient, upstream, done := startLongPoll(t, body)
		time.Sleep(50 * time.Millisecond)
		proxyClient.Close()
		waitServe(t, done, 3*time.Second)
		upstream.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadAll(upstream); err != nil {
			t.Fatalf("upstream not closed: %v", err)
		}
	}
}

// The real client disconnects during a long poll.
func TestClientGoneDuringLongPoll(t *testing.T) {
	client, _, _, done := startLongPoll(t, "")
	client.Close()
	if err := waitServe(t, done, 3*time.Second); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// The client disconnects while a response is streamed.
func TestClientGoneWhileStreaming(t *testing.T) {
	client, _, upstream, done := startLongPoll(t, "")
	io.WriteString(upstream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
	reader := bufio.NewReader(client)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, "client", reader, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
	client.Close()
	waitServe(t, done, 3*time.Second)
}

// A request after an idle period still works: the idle watch hands the readers back intact.
func TestIdleWatchKeepsPipelinedBytes(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	time.Sleep(50 * time.Millisecond)
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
	h.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
	time.Sleep(50 * time.Millisecond)
	h.send("GET /3 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /3 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nc")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nc")
	if got := h.requests.Load(); got != 3 {
		t.Fatalf("requests %d", got)
	}
}

type countingConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// Each forwarded chunk is a single write.
func TestChunkedForwardWritesOncePerChunk(t *testing.T) {
	client, proxyClient := tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)
	defer client.Close()
	defer upstream.Close()
	counted := &countingConn{Conn: proxyClient}
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), counted, proxyUpstream, Options{}) }()
	io.WriteString(client, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, "upstream", bufio.NewReader(upstream), "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	io.WriteString(upstream, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	reader := bufio.NewReader(client)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, "client", reader, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	for _, chunk := range []string{"aaa", "bbbb", "ccccc"} {
		io.WriteString(upstream, string("0123456789"[len(chunk)])+"\r\n"+chunk+"\r\n")
		expect(t, "client", reader, string("0123456789"[len(chunk)])+"\r\n"+chunk+"\r\n")
	}
	io.WriteString(upstream, "0\r\n\r\n")
	expect(t, "client", reader, "0\r\n\r\n")
	// head + three chunks + last chunk
	if got := counted.writes.Load(); got != 5 {
		t.Fatalf("client writes %d, want 5", got)
	}
	client.Close()
	waitServe(t, done, 3*time.Second)
}

// noDeadlineConn models an outbound stream without read deadlines (protocol/ssh
// chanConnWrapper, transport/v2raygrpc and v2rayhttp conns).
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetReadDeadline(time.Time) error { return os.ErrInvalid }
func (noDeadlineConn) SetDeadline(time.Time) error     { return os.ErrInvalid }

func TestKeepAliveOverNoDeadlineUpstream(t *testing.T) {
	client, proxyClient := tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)
	defer client.Close()
	defer upstream.Close()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), proxyClient, noDeadlineConn{proxyUpstream}, Options{}) }()
	clientR := bufio.NewReader(client)
	upstreamR := bufio.NewReader(upstream)
	client.SetDeadline(time.Now().Add(10 * time.Second))
	upstream.SetDeadline(time.Now().Add(10 * time.Second))
	for _, path := range []string{"/1", "/2", "/3"} {
		start := time.Now()
		io.WriteString(client, "GET "+path+" HTTP/1.1\r\nHost: a\r\n\r\n")
		expect(t, "upstream", upstreamR, "GET "+path+" HTTP/1.1\r\nHost: a\r\n\r\n")
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("request %s reached upstream after %v", path, elapsed)
		}
		io.WriteString(upstream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		expect(t, "client", clientR, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}
	// An interrupt while idle still ends the session.
	proxyClient.Close()
	waitServe(t, done, 3*time.Second)
}

func TestNoDeadlineClientInterruptWhileWaitingResponse(t *testing.T) {
	client, proxyClient := tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)
	defer client.Close()
	defer upstream.Close()
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), noDeadlineConn{proxyClient}, noDeadlineConn{proxyUpstream}, Options{})
	}()
	io.WriteString(client, "GET /poll HTTP/1.1\r\nHost: a\r\n\r\n")
	upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
	expect(t, "upstream", bufio.NewReader(upstream), "GET /poll HTTP/1.1\r\nHost: a\r\n\r\n")
	time.Sleep(50 * time.Millisecond)
	proxyClient.Close()
	waitServe(t, done, 3*time.Second)
}

// A watch on a connection that refuses deadlines ends the session instead of blocking.
func TestWatcherEndWithoutDeadline(t *testing.T) {
	near, far := tcpPair(t)
	defer far.Close()
	conn := noDeadlineConn{near}
	var failed atomic.Bool
	var w watcher
	w.init(conn, bufio.NewReader(conn), false, func() {
		failed.Store(true)
		near.Close()
	})
	w.begin()
	ended := make(chan struct{})
	go func() {
		w.end()
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("end blocked")
	}
	if !failed.Load() {
		t.Fatal("expected the session to end")
	}
	w.close()
}

// A request whose Connection nominates Content-Length or Host keeps both upstream: the body is
// still forwarded, so dropping the length would let the upstream read it as the next request.
func TestConnectionNominatingContentLengthRequest(t *testing.T) {
	h := newHarness(t)
	h.send("POST /a HTTP/1.1\r\nHost: a\r\nConnection: content-length, host\r\nContent-Length: 5\r\n\r\nhello")
	h.expectUpstream("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.send("GET /b HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /b HTTP/1.1\r\nHost: a\r\n\r\n")
}

// A response whose Connection nominates Content-Length keeps its length on the client side.
func TestConnectionNominatingContentLengthResponse(t *testing.T) {
	h := newHarness(t)
	h.send("GET /a HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /a HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.send("GET /b HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /b HTTP/1.1\r\nHost: a\r\n\r\n")
}

// A fixed-length body is forwarded with exactly one Content-Length holding the framed value.
func TestContentLengthNormalized(t *testing.T) {
	h := newHarness(t)
	h.send("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\nhello")
	h.expectUpstream("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello")
	h.reply("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nX: y\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nX: y\r\n\r\nok")
}

// An HTTP/1.0 request carrying Transfer-Encoding has faulty framing: 400, then close, nothing
// forwarded.
func TestHTTP10TransferEncodingRejected(t *testing.T) {
	for _, raw := range []string{
		"POST /a HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"POST /a HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello",
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

func readHead(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read head: %q %v", b.String(), err)
		}
		b.WriteString(line)
		if line == "\r\n" {
			return b.String()
		}
	}
}

// Pipelined keep-alive requests with random body sizes and pacing over pipe-deadline
// connections (as route/mitm wraps them) arrive complete and in order on both sides.
func TestPipelinedKeepAliveOverDeadlineConns(t *testing.T) {
	iterations := 100
	if testing.Short() {
		iterations = 10
	}
	for iter := 0; iter < iterations; iter++ {
		client, proxyClient := tcpPair(t)
		proxyUpstream, upstream := tcpPair(t)
		done := make(chan error, 1)
		go func() {
			done <- Serve(context.Background(), deadline.NewConn(proxyClient), deadline.NewConn(proxyUpstream), Options{})
		}()
		client.SetDeadline(time.Now().Add(10 * time.Second))
		upstream.SetDeadline(time.Now().Add(10 * time.Second))
		clientR := bufio.NewReader(client)
		upstreamR := bufio.NewReader(upstream)
		const n = 8
		go func() {
			for i := 0; i < n; i++ {
				body := strings.Repeat("x", rand.Intn(3000))
				fmt.Fprintf(client, "POST /%d HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n%s", i, len(body), body)
				if rand.Intn(2) == 0 {
					time.Sleep(time.Duration(rand.Intn(300)) * time.Microsecond)
				}
			}
		}()
		for i := 0; i < n; i++ {
			head := readHead(t, upstreamR)
			if !strings.HasPrefix(head, fmt.Sprintf("POST /%d ", i)) {
				t.Fatalf("iter %d: request %d head %q", iter, i, head)
			}
			length := -1
			for _, line := range strings.Split(head, "\r\n") {
				fmt.Sscanf(line, "Content-Length: %d", &length)
			}
			if length < 0 {
				t.Fatalf("iter %d: request %d without Content-Length: %q", iter, i, head)
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(upstreamR, body); err != nil || strings.Trim(string(body), "x") != "" {
				t.Fatalf("iter %d: request body %d: %q %v", iter, i, body, err)
			}
			resp := strings.Repeat("y", rand.Intn(5000))
			fmt.Fprintf(upstream, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(resp), resp)
			clientHead := readHead(t, clientR)
			if !strings.HasPrefix(clientHead, "HTTP/1.1 200") {
				t.Fatalf("iter %d: response %q", iter, clientHead)
			}
			got := make([]byte, len(resp))
			if _, err := io.ReadFull(clientR, got); err != nil || string(got) != resp {
				t.Fatalf("iter %d: response body %d: %v", iter, i, err)
			}
		}
		client.Close()
		if err := waitServe(t, done, 3*time.Second); err != nil {
			t.Fatalf("iter %d: Serve: %v", iter, err)
		}
		upstream.Close()
	}
}

// tunnelEcho checks that the CONNECT tunnel forwards bytes both ways and that a client close
// ends the session normally.
func tunnelEcho(t *testing.T, h *harness) {
	t.Helper()
	for _, message := range []string{"ping", "GET /not-a-request HTTP/1.1\r\n\r\n"} {
		h.send(message)
		h.expectUpstream(message)
		h.reply(strings.ToUpper(message))
		h.expectClient(strings.ToUpper(message))
	}
	h.client.Close()
	expectEOF(t, "upstream", h.upstreamR)
	h.upstream.Close()
	if err := h.wait(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if n := h.requests.Load(); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
}

// A 2xx answer to CONNECT inside a decrypted session turns the connection into a tunnel right
// after the header block (RFC 9112 section 6.3), forwarding the bytes either side sent right
// behind the request and the response head.
func TestConnectTunnel(t *testing.T) {
	h := newHarness(t)
	h.send("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\nearly")
	h.expectUpstream("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
	h.reply("HTTP/1.1 200 Connection Established\r\n\r\nhello")
	h.expectClient("HTTP/1.1 200 Connection Established\r\n\r\nhello")
	h.expectUpstream("early")
	tunnelEcho(t, h)
}

// The framing fields of a 2xx answer to CONNECT are ignored and not forwarded: the bytes that
// follow the head belong to the tunnel.
func TestConnectTunnelIgnoresFraming(t *testing.T) {
	for _, framing := range []string{"Content-Length: 5\r\n", "Transfer-Encoding: chunked\r\n"} {
		h := newHarness(t)
		h.send("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
		h.expectUpstream("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
		h.reply("HTTP/1.1 200 OK\r\n" + framing + "X: y\r\n\r\nhello")
		h.expectClient("HTTP/1.1 200 OK\r\nX: y\r\n\r\nhello")
		tunnelEcho(t, h)
	}
}

// A refused CONNECT is an ordinary response: its body is forwarded and the session follows the
// usual keep-alive rules.
func TestConnectRefused(t *testing.T) {
	h := newHarness(t)
	h.send("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
	h.expectUpstream("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
	h.reply("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 4\r\n\r\ndeny")
	h.expectClient("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 4\r\n\r\ndeny")
	h.send("GET /next HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /next HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.client.Close()
	if err := h.wait(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if n := h.requests.Load(); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}

	// Without a length the refusal body runs until close, so the session ends after it.
	h = newHarness(t)
	h.send("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
	h.expectUpstream("CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n")
	h.reply("HTTP/1.1 502 Bad Gateway\r\n\r\nno route")
	h.upstream.Close()
	h.expectClient("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nno route")
	expectEOF(t, "client", h.clientR)
	if err := h.wait(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}
