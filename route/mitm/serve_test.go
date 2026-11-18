package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type testCertificateStore struct {
	pool *x509.CertPool
}

func (s *testCertificateStore) Name() string { return "certificate" }

func (s *testCertificateStore) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (s *testCertificateStore) Pool() *x509.CertPool { return s.pool }

func (s *testCertificateStore) ExclusiveAnchors() bool { return true }

func contextWithRoots(upstream *httptest.Server) context.Context {
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	ctx := service.ContextWithDefaultRegistry(context.Background())
	return service.ContextWith[adapter.CertificateStore](ctx, &testCertificateStore{pool: pool})
}

func newUpstream(t *testing.T) *httptest.Server {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Path", request.URL.Path)
		_, _ = io.WriteString(writer, "body of "+request.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

type session struct {
	client   net.Conn
	routed   net.Conn // the routed client connection given to Serve
	state    *adapter.MITMState
	closes   atomic.Int32
	closeErr atomic.Pointer[error]
	done     chan struct{}
}

// startSession serves one decrypted connection to upstream and returns the
// raw client side.
func startSession(t *testing.T, ctx context.Context, engine *Engine, upstreamAddress string) *session {
	t.Helper()
	// A gateway device: not a local address, so its failures feed the skip table.
	return startSessionFrom(t, ctx, engine, upstreamAddress, "203.0.113.9:50000", nil)
}

// startSessionFrom is startSession with the given client source address and
// an optional hook on the connection metadata.
func startSessionFrom(t *testing.T, ctx context.Context, engine *Engine, upstreamAddress string, source string, edit func(*adapter.InboundContext)) *session {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	serverSide, err := listener.Accept()
	require.NoError(t, err)
	upstream, err := net.Dial("tcp", upstreamAddress)
	require.NoError(t, err)
	metadata := tlsMetadata("example.com", "127.0.0.1:443")
	metadata.Source = M.ParseSocksaddr(source)
	if edit != nil {
		edit(metadata)
	}
	metadata.MITM = adapter.NewMITMState(adapter.MITMStatusPending, "")
	s := &session{client: client, routed: serverSide, state: metadata.MITM, done: make(chan struct{})}
	go func() {
		engine.Serve(ctx, serverSide, upstream, testRedial(upstreamAddress, nil), metadata, N.CloseHandlerFunc(func(err error) {
			s.closes.Add(1)
			s.closeErr.Store(&err)
		}))
		close(s.done)
	}()
	return s
}

// testRedial dials address again like the routed upstream, wrapped by wrap when not nil.
func testRedial(address string, wrap func(net.Conn) net.Conn) adapter.MITMRedialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		if wrap != nil {
			conn = wrap(conn)
		}
		return conn, nil
	}
}

func (s *session) wait(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
	require.Equal(t, int32(1), s.closes.Load())
}

func caPool(t *testing.T, ca testCA) *x509.CertPool {
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.certificatePEM))
	return pool
}

func TestServeDecryptsKeepAlive(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	ctx := contextWithRoots(upstream)
	engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())

	clientConn := tls.Client(s.client, &tls.Config{
		ServerName: "example.com",
		RootCAs:    caPool(t, ca),
		NextProtos: []string{"h2", "http/1.1"},
	})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	connectionState := clientConn.ConnectionState()
	require.Equal(t, "http/1.1", connectionState.NegotiatedProtocol)
	leaf := connectionState.PeerCertificates[0]
	require.Equal(t, "Kiko Test CA", leaf.Issuer.CommonName)
	require.Contains(t, leaf.DNSNames, "example.com")
	// The server side completes its handshake after the client's.
	require.Eventually(t, func() bool {
		return s.state.Status() == adapter.MITMStatusDecrypted
	}, 5*time.Second, 10*time.Millisecond)

	reader := bufio.NewReader(clientConn)
	for _, path := range []string{"/first", "/second"} {
		_, err := io.WriteString(clientConn, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "body of "+path, string(body))
		require.Equal(t, path, response.Header.Get("X-Path"))
	}
	require.Equal(t, int64(2), s.state.Requests())
	require.Equal(t, 1, engine.Status().LeafCacheSize)
	clientConn.Close()
	s.wait(t)
	require.Equal(t, adapter.MITMStatusDecrypted, s.state.Status())
	require.Equal(t, int64(2), s.state.Requests())
}

func TestServeUntrustedUpstream(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	// No certificate store: the upstream's self-signed certificate is not
	// trusted by the system roots.
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"example.com"}, nil))
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
	require.Error(t, clientConn.HandshakeContext(context.Background()))
	s.wait(t)
	require.Equal(t, adapter.MITMStatusFailed, s.state.Status())
	require.Contains(t, s.state.Reason(), "upstream TLS handshake")
	require.Error(t, *s.closeErr.Load())
	require.Zero(t, engine.Status().LeafCacheSize)
}

func TestServeUntrustedClient(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com"})
	require.Error(t, clientConn.HandshakeContext(context.Background()))
	s.wait(t)
	require.Equal(t, adapter.MITMStatusFailed, s.state.Status())
	require.Contains(t, s.state.Reason(), "client TLS handshake")
	require.NoError(t, *s.closeErr.Load())
}

func TestServeContextCancel(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startSession(t, ctx, engine, upstream.Listener.Addr().String())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	cancel()
	s.wait(t)
	_, err := clientConn.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestServeEngineClose(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.NoError(t, engine.Close())
	s.wait(t)
}

func TestServeCancelDuringUpstreamHandshake(t *testing.T) {
	// The upstream accepts but never answers the ClientHello.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer silent.Close()
	go func() {
		for {
			conn, acceptErr := silent.Accept()
			if acceptErr != nil {
				return
			}
			defer conn.Close()
		}
	}()
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"example.com"}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	s := startSession(t, ctx, engine, silent.Addr().String())
	go func() {
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
		_ = clientConn.HandshakeContext(context.Background())
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()
	s.wait(t)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, adapter.MITMStatusFailed, s.state.Status())
}

func TestServeNoGoroutineLeak(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	before := runtime.NumGoroutine()
	for range 5 {
		s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
		require.NoError(t, clientConn.HandshakeContext(context.Background()))
		_, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, response.Body)
		clientConn.Close()
		s.wait(t)
	}
	// Upstream handlers finish their keep-alive connections asynchronously.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= before+1
	}, 5*time.Second, 50*time.Millisecond, "goroutines: before %d, now %d", before, runtime.NumGoroutine())
}
