package mitm

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/h1"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/option"
)

func benchmarkTCPPair(b *testing.B) (net.Conn, net.Conn) {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	conn := <-accepted
	if conn == nil {
		b.Fatal("accept failed")
	}
	return dialed, conn
}

// BenchmarkKeepAliveGETReadAhead relays keep-alive GETs through h1.Serve with both connections
// behind withDeadlineReader, as the engine passes connections without native read deadlines:
// the per-request cost of the read-ahead path, to compare with h1's BenchmarkKeepAliveGET (raw
// TCP) and BenchmarkKeepAliveGETDeadlineConn (sing's pipe deadline).
func BenchmarkKeepAliveGETReadAhead(b *testing.B) {
	benchmarkKeepAlive(b, h1.Options{OnRequest: func() {}})
}

// BenchmarkKeepAliveGETCaptureOff is the same relay with an Observer that is nil (capture off).
func BenchmarkKeepAliveGETCaptureOff(b *testing.B) {
	benchmarkKeepAlive(b, h1.Options{OnRequest: func() {}, Observer: capture.New(capture.Options{Enabled: false}).Observer()})
}

// BenchmarkKeepAliveGETRewriteNone has a rewrite hook returning no rules: the per-request cost
// of the feature when it is unused.
func BenchmarkKeepAliveGETRewriteNone(b *testing.B) {
	set, _ := rewrite.Compile(context.Background(), nil)
	benchmarkKeepAlive(b, h1.Options{OnRequest: func() {}, Rewrite: func() *rewrite.Set { return set }})
}

// BenchmarkKeepAliveGETRewriteMiss has rules that never match the benchmark URL.
func BenchmarkKeepAliveGETRewriteMiss(b *testing.B) {
	set, err := rewrite.Compile(context.Background(), &option.MITMHTTPRewriteOptions{
		URL:      []option.MITMURLRewriteRule{{Pattern: `^https://ads\.example\.net/`, Action: "reject"}},
		MapLocal: []option.MITMMapLocalRule{{Pattern: `^https://mock\.example\.net/`, Body: "x"}},
		Headers: []option.MITMHeaderRewriteRule{{Pattern: `^https://other\.example\.net/`, Scope: "request",
			Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-A", Value: "1"}}}},
	})
	if err != nil {
		b.Fatal(err)
	}
	benchmarkKeepAlive(b, h1.Options{OnRequest: func() {}, Rewrite: func() *rewrite.Set { return set }})
}

// BenchmarkKeepAliveGETCaptureHeaders records heads only.
func BenchmarkKeepAliveGETCaptureHeaders(b *testing.B) {
	manager := capture.New(capture.Options{Enabled: true, MaxRecords: 1000})
	benchmarkKeepAlive(b, h1.Options{OnRequest: func() {}, Observer: manager.Observer(), Connection: &flow.ConnectionInfo{ID: "bench"}})
}

// BenchmarkKeepAliveGETCaptureBodies records heads and the 16 KiB response bodies.
func BenchmarkKeepAliveGETCaptureBodies(b *testing.B) {
	manager := capture.New(capture.Options{Enabled: true, Body: true, MaxRecords: 1000})
	benchmarkKeepAlive(b, h1.Options{OnRequest: func() {}, Observer: manager.Observer(), Connection: &flow.ConnectionInfo{ID: "bench"}})
}

func benchmarkKeepAlive(b *testing.B, options h1.Options) {
	const request = "GET /bench HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 16384\r\n\r\n" + strings.Repeat("x", 16384)
	client, proxyClient := benchmarkTCPPair(b)
	proxyUpstream, upstream := benchmarkTCPPair(b)
	defer client.Close()
	defer upstream.Close()
	clientSide := withDeadlineReader(proxyClient)
	upstreamSide := withDeadlineReader(proxyUpstream)
	if _, ok := clientSide.(*readAheadConn); !ok {
		b.Fatal("client not read ahead")
	}
	if _, ok := upstreamSide.(*readAheadConn); !ok {
		b.Fatal("upstream not read ahead")
	}
	done := make(chan error, 1)
	go func() {
		done <- h1.Serve(context.Background(), clientSide, upstreamSide, options)
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
