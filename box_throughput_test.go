package box_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// benchmarkTransferBytes is moved from the sink to the client per iteration.
const benchmarkTransferBytes = 64 << 20

// captureClientHello returns the first TLS record a client sends for serverName.
func captureClientHello(tb testing.TB, serverName string) []byte {
	tb.Helper()
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	go func() {
		_ = tls.Client(clientSide, &tls.Config{ServerName: serverName}).Handshake()
		clientSide.Close()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(serverSide, header); err != nil {
		tb.Fatal(err)
	}
	record := make([]byte, 5+int(binary.BigEndian.Uint16(header[3:])))
	copy(record, header)
	if _, err := io.ReadFull(serverSide, record[5:]); err != nil {
		tb.Fatal(err)
	}
	return record
}

// startBenchmarkSink accepts connections, reads the ClientHello and sends
// benchmarkTransferBytes before closing.
func startBenchmarkSink(tb testing.TB, helloLength int) string {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { listener.Close() })
	payload := make([]byte, 256<<10)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.ReadFull(conn, make([]byte, helloLength)); err != nil {
					return
				}
				for remaining := benchmarkTransferBytes; remaining > 0; remaining -= len(payload) {
					if _, err := conn.Write(payload[:min(remaining, len(payload))]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// BenchmarkMixedSniffDirectThroughput moves bulk data through mixed inbound
// (CONNECT) → sniff rule → direct outbound. The connection sniffs as TLS with
// a server name. BOX_BENCH_CONFIG_EXTRA adds top-level configuration, e.g.
// `"mitm": {"enabled": true, "hostnames": {"include": ["other.test"]}}`.
func BenchmarkMixedSniffDirectThroughput(b *testing.B) {
	hello := captureClientHello(b, "bench.test")
	sinkAddress := startBenchmarkSink(b, len(hello))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := `{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"}`
	if extra := strings.TrimSpace(os.Getenv("BOX_BENCH_CONFIG_EXTRA")); extra != "" {
		config += ",\n  " + extra
	}
	config += "\n}"
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		b.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		b.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		b.Fatal(err)
	}
	defer instance.Close()
	proxyAddress := "127.0.0.1:" + strconv.Itoa(proxyPort)
	connect := "CONNECT " + sinkAddress + " HTTP/1.1\r\nHost: " + sinkAddress + "\r\n\r\n"
	buffer := make([]byte, 256<<10)
	transfer := func() {
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			b.Fatal(err)
		}
		defer conn.Close()
		if _, err = io.WriteString(conn, connect); err != nil {
			b.Fatal(err)
		}
		reader := bufio.NewReaderSize(conn, 64<<10)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				b.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err = conn.Write(hello); err != nil {
			b.Fatal(err)
		}
		var received int
		for {
			n, err := reader.Read(buffer)
			received += n
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
		if received != benchmarkTransferBytes {
			b.Fatalf("received %d of %d bytes", received, benchmarkTransferBytes)
		}
	}
	transfer()
	b.SetBytes(benchmarkTransferBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transfer()
	}
}
