package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/script"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// fakeScriptRouter plays the router: it connects each routed connection to the backend
// registered for its destination, and records the metadata it received.
type fakeScriptRouter struct {
	mu       sync.Mutex
	backends map[string]string
	seen     []adapter.InboundContext
	calls    atomic.Int32
	// failWith closes the connection with this error before connecting, as the router's
	// after-dial guard does.
	failWith error
}

func (r *fakeScriptRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.calls.Add(1)
	r.mu.Lock()
	r.seen = append(r.seen, metadata)
	backend, found := r.backends[metadata.Destination.String()]
	r.mu.Unlock()
	if r.failWith != nil {
		conn.Close()
		onClose(r.failWith)
		return
	}
	if !found {
		conn.Close()
		onClose(io.ErrClosedPipe)
		return
	}
	remote, err := net.Dial("tcp", backend)
	if err != nil {
		conn.Close()
		onClose(err)
		return
	}
	go func() {
		_, _ = io.Copy(remote, conn)
		remote.Close()
	}()
	_, _ = io.Copy(conn, remote)
	conn.Close()
	remote.Close()
	onClose(nil)
}

type knownOutbounds struct{ adapter.Outbound }

func (knownOutbounds) Type() string { return "test" }

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func newScriptClientEngine(t *testing.T) *Engine {
	t.Helper()
	return newTestEngine(t, context.Background(), &option.MITMOptions{})
}

func allowScriptLocal(t *testing.T) {
	t.Helper()
	SetScriptHTTPAllowLocal(true)
	t.Cleanup(func() { SetScriptHTTPAllowLocal(false) })
}

func TestScriptHostRefusedTable(t *testing.T) {
	engine := newScriptClientEngine(t)
	refused := []string{
		"localhost", "LOCALHOST", "localhost.", "localhost..", "foo.localhost", "a.b.localhost.", "foo.LocalHost",
		"127.0.0.1", "127.1.2.3", "127.0.0.1.", "0.0.0.0", "0.1.2.3", "::", "::1", "[::1]",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1",
		"10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1", "fd00::1", "fc12::1",
		"169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1", "255.255.255.255",
		"2130706433", "0x7f000001", "0x7f.1", "127.1", "0177.0.0.1", "017700000001", "1", "0", "0x0", "127.0.1",
		"example.com.0x7f", "fe80::1%eth0", "", ".", "a b", "1.2.3.4.5",
	}
	for _, host := range refused {
		require.NotEmpty(t, engine.scriptHostRefused(strings.Trim(host, "[]")), "host %q", host)
	}
	allowed := []string{"example.com", "example.com.", "8.8.8.8", "2606:4700:4700::1111", "a.b.example.org", "1e100.net", "xn--bcher-kva.example"}
	for _, host := range allowed {
		require.Empty(t, engine.scriptHostRefused(host), "host %q", host)
	}
}

func TestScriptAddressRefusedOwnAddress(t *testing.T) {
	engine := newScriptClientEngine(t)
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	checked := 0
	for _, addr := range addrs {
		network, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		parsed, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			continue
		}
		require.NotEmpty(t, engine.ScriptAddressRefused(parsed), "own address %s", parsed)
		checked++
	}
	require.NotZero(t, checked)
	require.Empty(t, engine.ScriptAddressRefused(netip.MustParseAddr("8.8.8.8")))
	require.Empty(t, engine.ScriptAddressRefused(netip.MustParseAddr("::ffff:8.8.8.8")))
}

func TestScriptTargetRefusedAddress(t *testing.T) {
	engine := newScriptClientEngine(t)
	_, _, reason := engine.scriptTargetRefused("[::1]:80")
	require.NotEmpty(t, reason)
	_, _, reason = engine.scriptTargetRefused("example.com:0")
	require.Equal(t, "invalid port", reason)
	_, _, reason = engine.scriptTargetRefused("example.com")
	require.Equal(t, "invalid address", reason)
	host, port, reason := engine.scriptTargetRefused("example.com:8443")
	require.Empty(t, reason)
	require.Equal(t, "example.com", host)
	require.EqualValues(t, 8443, port)
}

func TestScriptHTTPRefusesHostileURLs(t *testing.T) {
	engine := newScriptClientEngine(t)
	router := &fakeScriptRouter{}
	client := engine.ScriptHTTPClient(router, nil)
	urls := []string{
		"http://127.0.0.1/", "http://127.0.0.1:9090/", "http://localhost/", "http://localhost./", "http://x.localhost:80/",
		"http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "http://0/", "http://2130706433/",
		"http://0x7f.1/", "http://127.1/", "http://10.1.2.3/", "http://192.168.0.1/", "http://169.254.169.254/latest/meta-data/",
		"https://[fd00::1]/", "http://224.0.0.1/",
	}
	for _, target := range urls {
		_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: target, Timeout: time.Second})
		require.Error(t, err, target)
		require.True(t, strings.HasPrefix(err.Error(), "refused:"), "%s: %v", target, err)
	}
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://user@example.com/"})
	require.ErrorContains(t, err, "refused:")
	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "ftp://example.com/"})
	require.ErrorContains(t, err, "scheme")
	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://"})
	require.Error(t, err)
	require.Zero(t, router.calls.Load(), "nothing reaches the router")
}

func TestScriptHTTPDialGuardRejectsHostOverride(t *testing.T) {
	// The Host header never changes the dial target.
	engine := newScriptClientEngine(t)
	router := &fakeScriptRouter{}
	client := engine.ScriptHTTPClient(router, nil)
	_, err := client.Do(context.Background(), &script.HTTPRequest{
		Method: "GET", URL: "http://127.0.0.1:80/", Headers: []script.Header{{Name: "Host", Value: "example.com"}},
	})
	require.ErrorContains(t, err, "refused:")
	require.Zero(t, router.calls.Load())
}

// scriptTestBackends serves the handler and maps the given fake host names to it.
func scriptTestBackends(t *testing.T, handler http.Handler, tlsServer bool, names ...string) (*fakeScriptRouter, *httptest.Server) {
	t.Helper()
	var server *httptest.Server
	if tlsServer {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	router := &fakeScriptRouter{backends: map[string]string{}}
	address := server.Listener.Addr().String()
	for _, name := range names {
		router.backends[name] = address
	}
	return router, server
}

func TestScriptHTTPBasicExchange(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	type seen struct {
		header http.Header
		host   string
		body   string
	}
	seenCh := make(chan seen, 1)
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		seenCh <- seen{header: r.Header.Clone(), host: r.Host, body: string(data)}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello"))
	}), false, "origin.test:80")
	client := engine.ScriptHTTPClient(router, nil)
	response, err := client.Do(context.Background(), &script.HTTPRequest{
		Script: "tagged", Method: "POST", URL: "http://origin.test/path?q=1",
		Headers: []script.Header{
			{Name: "X-A", Value: "1"}, {Name: "X-A", Value: "2"}, {Name: "Connection", Value: "close"},
			{Name: "Content-Length", Value: "999"}, {Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "Host", Value: "override.example"}, {Name: "Upgrade", Value: "h2c"},
		},
		Body: []byte("payload"),
	})
	require.NoError(t, err)
	require.Equal(t, 201, response.Status)
	require.Equal(t, "hello", string(response.Body))
	var cookies []string
	for _, header := range response.Headers {
		if header.Name == "Set-Cookie" {
			cookies = append(cookies, header.Value)
		}
	}
	require.Equal(t, []string{"a=1", "b=2"}, cookies)
	got := <-seenCh
	require.Equal(t, []string{"1", "2"}, got.header.Values("X-A"))
	require.Equal(t, "payload", got.body)
	require.Equal(t, "override.example", got.host)
	require.Empty(t, got.header.Get("Upgrade"))
	require.Empty(t, got.header.Get("User-Agent"), "no default agent")

	require.Len(t, router.seen, 1)
	metadata := router.seen[0]
	require.Equal(t, adapter.InboundKikoScript, metadata.Inbound)
	require.Equal(t, adapter.InboundKikoInternal, metadata.InboundType)
	require.True(t, metadata.Internal)
	require.True(t, metadata.ScriptClient)
	require.Equal(t, "tagged", metadata.User)
	require.Equal(t, "origin.test:80", metadata.Destination.String())
	require.Equal(t, adapter.MITMStatusSkipped, metadata.MITM.Status())
}

func TestScriptHTTPForcedOutbound(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), false, "origin.test:80")
	client := engine.ScriptHTTPClient(router, scriptOutbounds{"proxy-1": true})
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", Outbound: "proxy-1"})
	require.NoError(t, err)
	require.Equal(t, "proxy-1", router.seen[0].ForcedOutbound)

	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", Outbound: "nope"})
	require.EqualError(t, err, "outbound not found")
	require.EqualValues(t, 1, router.calls.Load())
}

type scriptOutbounds map[string]bool

func (o scriptOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	if o[tag] {
		return knownOutbounds{}, true
	}
	return nil, false
}

func TestScriptHTTPRedirects(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	var methodsMu sync.Mutex
	var methods []string
	var hops atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		methodsMu.Lock()
		methods = append(methods, r.Method)
		methodsMu.Unlock()
		http.Redirect(w, r, "http://second.test/end", 302)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		methodsMu.Lock()
		methods = append(methods, r.Method+" "+r.Host)
		methodsMu.Unlock()
		_, _ = w.Write([]byte("end"))
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, "/loop", 302)
	})
	router, _ := scriptTestBackends(t, mux, false, "first.test:80", "second.test:80")
	client := engine.ScriptHTTPClient(router, nil)

	response, err := client.Do(context.Background(), &script.HTTPRequest{Method: "POST", URL: "http://first.test/start", Body: []byte("x")})
	require.NoError(t, err)
	require.Equal(t, "end", string(response.Body))
	require.Equal(t, []string{"POST", "GET second.test"}, methods, "302 turns POST into GET")
	require.Len(t, router.seen, 2, "every hop is routed")
	require.Equal(t, "second.test:80", router.seen[1].Destination.String())

	response, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://first.test/start", NoRedirect: true})
	require.NoError(t, err)
	require.Equal(t, 302, response.Status)
	var location string
	for _, header := range response.Headers {
		if header.Name == "Location" {
			location = header.Value
		}
	}
	require.Equal(t, "http://second.test/end", location)

	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://first.test/loop"})
	require.ErrorContains(t, err, "redirects")
	require.LessOrEqual(t, int(hops.Load()), script.MaxHTTPRedirects+1)
}

func TestScriptHTTPRedirectToRefusedTarget(t *testing.T) {
	engine := newScriptClientEngine(t)
	targets := []string{
		"http://127.0.0.1:9090/", "http://localhost/x", "http://[::ffff:7f00:1]/", "http://169.254.169.254/", "http://0x7f.1/",
		"http://user:pw@example.org/", "ftp://example.org/", "http://10.0.0.5/",
	}
	for _, target := range targets {
		var destination string
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, destination, 302)
		})
		destination = target
		router, _ := scriptTestBackends(t, mux, false, "public.test:80")
		client := engine.ScriptHTTPClient(router, nil)
		// "public.test" is a name: the engine lets it through, then the redirect is refused.
		_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://public.test/"})
		require.Error(t, err, target)
		if !strings.HasPrefix(target, "ftp:") {
			require.True(t, strings.HasPrefix(err.Error(), "refused:"), "%s: %v", target, err)
		}
		require.EqualValues(t, 1, router.calls.Load(), "%s: only the first hop was routed", target)
	}
}

func TestScriptHTTPPostDialRefusalSurfaces(t *testing.T) {
	// A router whose after-dial guard refused the connection: the script sees the reason, not
	// the pipe's EOF.
	engine := newScriptClientEngine(t)
	router := &fakeScriptRouter{failWith: &scriptRefusal{"loopback address (127.0.0.1)"}}
	client := engine.ScriptHTTPClient(router, nil)
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://rebind.test/"})
	require.EqualError(t, err, "refused: loopback address (127.0.0.1)")
}

func TestScriptHTTPResponseCap(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chunked" {
			flusher := w.(http.Flusher)
			for i := 0; i < 10; i++ {
				_, _ = w.Write([]byte(strings.Repeat("a", 100)))
				flusher.Flush()
			}
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("a", 1000)))
	}), false, "origin.test:80")
	client := engine.ScriptHTTPClient(router, nil)
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", MaxResponse: 999})
	require.EqualError(t, err, "response body larger than 999")
	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/chunked", MaxResponse: 999})
	require.EqualError(t, err, "response body larger than 999")
	response, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", MaxResponse: 1000})
	require.NoError(t, err)
	require.Len(t, response.Body, 1000)
}

func TestScriptHTTPTimeout(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	release := make(chan struct{})
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), false, "origin.test:80")
	t.Cleanup(func() { close(release) })
	client := engine.ScriptHTTPClient(router, nil)
	start := time.Now()
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", Timeout: 300 * time.Millisecond})
	require.EqualError(t, err, "timeout")
	require.Less(t, time.Since(start), 3*time.Second)
}

func TestScriptHTTPCancel(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	release := make(chan struct{})
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), false, "origin.test:80")
	t.Cleanup(func() { close(release) })
	client := engine.ScriptHTTPClient(router, nil)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := client.Do(ctx, &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", Timeout: 10 * time.Second})
	require.EqualError(t, err, "canceled")
}

func TestScriptHTTPTLS(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure " + r.Proto))
	}), true, "secure.test:443")
	client := engine.ScriptHTTPClient(router, nil)
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "https://secure.test/"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")
	response, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "https://secure.test/", Insecure: true})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(response.Body), "secure HTTP/"), string(response.Body))
}

func TestScriptHTTPGzipDecoded(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	router, server := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			_, _ = w.Write([]byte("plain"))
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzipBytes(t, []byte("decoded text")))
	}), false, "origin.test:80")
	_ = server
	client := engine.ScriptHTTPClient(router, nil)
	response, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/"})
	require.NoError(t, err)
	require.Equal(t, "decoded text", string(response.Body))
	// A script that sets Accept-Encoding itself gets the raw bytes.
	response, err = client.Do(context.Background(), &script.HTTPRequest{
		Method: "GET", URL: "http://origin.test/", Headers: []script.Header{{Name: "Accept-Encoding", Value: "gzip"}},
	})
	require.NoError(t, err)
	require.NotEqual(t, "decoded text", string(response.Body))
}

func TestScriptHTTPCaptureRecords(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "/b", 302)
			return
		}
		_, _ = w.Write([]byte("body-b"))
	}), false, "origin.test:80")
	client := engine.ScriptHTTPClient(router, nil)

	// Capture disabled: the request works and nothing is recorded.
	engine.capture.SetOptions(capture.Options{Enabled: false})
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/b"})
	require.NoError(t, err)
	require.Empty(t, engine.capture.List(capture.Filter{Limit: 10}).Records)

	engine.capture.SetOptions(capture.Options{Enabled: true, Body: true})
	_, err = client.Do(context.Background(), &script.HTTPRequest{Script: "cronjob", Method: "GET", URL: "http://origin.test/a"})
	require.NoError(t, err)
	records := engine.capture.List(capture.Filter{Limit: 10}).Records
	require.Len(t, records, 2, "one record per hop")
	byPath := map[string]capture.Record{}
	for _, record := range records {
		byPath[record.Path] = record
	}
	require.Equal(t, 302, byPath["/a"].Status)
	require.Equal(t, 200, byPath["/b"].Status)
	require.Equal(t, adapter.InboundKikoScript, byPath["/b"].Connection.Inbound)
	require.Equal(t, "cronjob", byPath["/b"].Connection.User)
	require.Equal(t, "origin.test", byPath["/b"].Connection.Host)
}

func TestScriptHTTPNoRouter(t *testing.T) {
	engine := newScriptClientEngine(t)
	client := engine.ScriptHTTPClient(nil, nil)
	_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://example.com/"})
	require.EqualError(t, err, "not available")
}

func TestScriptHTTPRedirectDoesNotReuseConnection(t *testing.T) {
	// Each hop dials again, so a redirect cannot ride on the connection of an allowed host.
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://second.test/end", 302) })
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	router := &fakeScriptRouter{backends: map[string]string{"first.test:443": server.Listener.Addr().String(), "second.test:443": server.Listener.Addr().String()}}
	client := engine.ScriptHTTPClient(router, nil)
	response, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "https://first.test/end", Insecure: true})
	require.NoError(t, err)
	require.Equal(t, "ok", string(response.Body))
	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "https://first.test/start", Insecure: true})
	require.NoError(t, err)
	require.Len(t, router.seen, 3)
}

func TestScriptHTTPBodylessResponsesIgnoreContentLength(t *testing.T) {
	allowScriptLocal(t)
	engine := newScriptClientEngine(t)
	router, _ := scriptTestBackends(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "20000000")
		if r.Method == http.MethodHead {
			return
		}
		if r.URL.Path == "/notmod" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("short"))
	}), false, "origin.test:80")
	client := engine.ScriptHTTPClient(router, nil)
	response, err := client.Do(context.Background(), &script.HTTPRequest{Method: "HEAD", URL: "http://origin.test/"})
	require.NoError(t, err)
	require.Equal(t, 200, response.Status)
	require.Empty(t, response.Body)
	var length string
	for _, header := range response.Headers {
		if header.Name == "Content-Length" {
			length = header.Value
		}
	}
	require.Equal(t, "20000000", length)
	response, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/notmod"})
	require.NoError(t, err)
	require.Equal(t, 304, response.Status)
	require.Empty(t, response.Body)
	// A GET that announces more than the cap still fails before reading.
	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://origin.test/", MaxResponse: 1000})
	require.Error(t, err)
}
