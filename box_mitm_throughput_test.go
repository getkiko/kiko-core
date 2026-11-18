package box_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
)

// startBenchmarkHTTPS serves /download (benchmarkTransferBytes, with Content-Length unless
// ?chunked), /upload (discards the body and answers its size) and anything else small.
func startBenchmarkHTTPS(tb testing.TB) *httptest.Server {
	tb.Helper()
	payload := make([]byte, 256<<10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/download":
			if request.URL.Query().Get("chunked") == "" {
				writer.Header().Set("Content-Length", strconv.Itoa(benchmarkTransferBytes))
			}
			for remaining := benchmarkTransferBytes; remaining > 0; remaining -= len(payload) {
				if _, err := writer.Write(payload[:min(remaining, len(payload))]); err != nil {
					return
				}
			}
		case "/upload":
			buffer := make([]byte, 64<<10)
			n, _ := io.CopyBuffer(io.Discard, struct{ io.Reader }{request.Body}, buffer)
			_, _ = io.WriteString(writer, strconv.FormatInt(n, 10))
		default:
			_, _ = io.WriteString(writer, "ok")
		}
	}))
	tb.Cleanup(server.Close)
	return server
}

type benchmarkMITMClient struct {
	client    *http.Client
	transport *http.Transport
	target    string
}

// newBenchmarkMITMClient starts mixed → sniff → direct with decryption enabled, decrypting
// the server when decrypted and else passing it through, and returns an HTTP/1.1 client
// through the proxy that trusts the test CA and the server.
func newBenchmarkMITMClient(b *testing.B, server *httptest.Server, decrypted bool) *benchmarkMITMClient {
	b.Helper()
	ca := writeMITMTestCA(b)
	port := server.Listener.Addr().(*net.TCPAddr).Port
	hostname := "other.test"
	if decrypted {
		hostname = "example.com:" + strconv.Itoa(port)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	serverPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	certificateSection, _ := json.Marshal(map[string]any{"certificate": []string{serverPEM}})
	config := `{
  "log": {"disabled": true},
  "certificate": ` + string(certificateSection) + `,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"},
  "mitm": ` + mitmSection(ca, true, hostname) + `
}`
	ctx := include.Context(context.Background())
	options, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
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
	b.Cleanup(func() { instance.Close() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.certificatePEM)
	roots.AddCert(server.Certificate())
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		TLSClientConfig:     &tls.Config{RootCAs: roots, ServerName: "example.com"},
		DisableCompression:  true,
		MaxIdleConnsPerHost: 1,
		ReadBufferSize:      64 << 10,
		WriteBufferSize:     64 << 10,
	}
	b.Cleanup(transport.CloseIdleConnections)
	c := &benchmarkMITMClient{
		client:    &http.Client{Transport: transport, Timeout: time.Minute},
		transport: transport,
		target:    "https://127.0.0.1:" + strconv.Itoa(port),
	}
	// Warm up the connection and the leaf cache, and check the mode.
	response := c.do(b, http.MethodGet, "/small", nil, 2)
	issuer := response.TLS.PeerCertificates[0].Issuer.CommonName
	if decrypted != (issuer == "Kiko Box Test CA") {
		b.Fatalf("decrypted %v, certificate issued by %q", decrypted, issuer)
	}
	return c
}

// do sends a request, reads the whole response body and checks its size.
func (c *benchmarkMITMClient) do(b *testing.B, method string, path string, body io.Reader, size int64) *http.Response {
	request, err := http.NewRequest(method, c.target+path, body)
	if err != nil {
		b.Fatal(err)
	}
	if body != nil {
		request.ContentLength = benchmarkTransferBytes
	}
	response, err := c.client.Do(request)
	if err != nil {
		b.Fatal(err)
	}
	defer response.Body.Close()
	buffer := make([]byte, 64<<10)
	n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{response.Body}, buffer)
	if err != nil {
		b.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || n != size {
		b.Fatalf("status %d, %d of %d bytes", response.StatusCode, n, size)
	}
	return response
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

var benchmarkMITMModes = []struct {
	name      string
	decrypted bool
}{{"passthrough", false}, {"decrypted", true}}

// BenchmarkMITMThroughput moves benchmarkTransferBytes per request over one kept-alive
// HTTPS connection through mixed CONNECT → sniff → direct, end to end (passthrough) and
// decrypted.
func BenchmarkMITMThroughput(b *testing.B) {
	server := startBenchmarkHTTPS(b)
	uploadAnswer := int64(len(strconv.Itoa(benchmarkTransferBytes)))
	for _, mode := range benchmarkMITMModes {
		b.Run(mode.name, func(b *testing.B) {
			c := newBenchmarkMITMClient(b, server, mode.decrypted)
			for _, operation := range []struct {
				name string
				run  func()
			}{
				{"download-length", func() { c.do(b, http.MethodGet, "/download", nil, benchmarkTransferBytes) }},
				{"download-chunked", func() { c.do(b, http.MethodGet, "/download?chunked=1", nil, benchmarkTransferBytes) }},
				{"upload", func() {
					c.do(b, http.MethodPost, "/upload", io.LimitReader(zeroReader{}, benchmarkTransferBytes), uploadAnswer)
				}},
			} {
				b.Run(operation.name, func(b *testing.B) {
					operation.run()
					b.SetBytes(benchmarkTransferBytes)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						operation.run()
					}
				})
			}
		})
	}
}

// BenchmarkMITMFirstByte measures the time to response headers of a small GET, on a new
// connection (CONNECT and TLS handshakes included) and on a kept-alive one, and reports
// the median.
func BenchmarkMITMFirstByte(b *testing.B) {
	server := startBenchmarkHTTPS(b)
	for _, mode := range benchmarkMITMModes {
		b.Run(mode.name, func(b *testing.B) {
			c := newBenchmarkMITMClient(b, server, mode.decrypted)
			for _, fresh := range []bool{true, false} {
				name := "kept-alive"
				if fresh {
					name = "new-connection"
				}
				b.Run(name, func(b *testing.B) {
					durations := make([]time.Duration, 0, b.N)
					for i := 0; i < b.N; i++ {
						if fresh {
							c.transport.CloseIdleConnections()
						}
						start := time.Now()
						response, err := c.client.Get(c.target + "/small")
						if err != nil {
							b.Fatal(err)
						}
						durations = append(durations, time.Since(start))
						_, _ = io.Copy(io.Discard, response.Body)
						response.Body.Close()
					}
					slices.Sort(durations)
					b.ReportMetric(float64(durations[len(durations)/2].Microseconds()), "p50-µs")
				})
			}
		})
	}
}
