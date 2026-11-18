package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// rejectingSession is a client that does not trust the generated certificate.
func rejectingSession(t *testing.T, engine *Engine, upstreamAddress string) *session {
	t.Helper()
	s := startSession(t, context.Background(), engine, upstreamAddress)
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com"})
	require.Error(t, clientConn.HandshakeContext(context.Background()))
	s.wait(t)
	return s
}

// silentSession completes the handshake, optionally sends a request, and closes.
func silentSession(t *testing.T, engine *Engine, ca testCA, upstreamAddress string, request bool) *session {
	t.Helper()
	s := startSession(t, context.Background(), engine, upstreamAddress)
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	if request {
		_, err := io.WriteString(clientConn, "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	clientConn.Close()
	s.wait(t)
	return s
}

// pinningOptions decrypts example.com for local clients and the gateway device
// range the test sessions come from.
func pinningOptions(ca testCA) *option.MITMOptions {
	options := fileOptions(ca, true, []string{"example.com"}, nil)
	options.Sources = []string{"local", "203.0.113.0/24"}
	return options
}

func decideExample(engine *Engine) (adapter.MITMStatus, string) {
	metadata := tlsMetadata("example.com", "127.0.0.1:443")
	metadata.Source = M.ParseSocksaddr("203.0.113.9:50000")
	return decideStatus(engine, metadata)
}

func TestPinningFlowRejectedCertificate(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()

	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	first := rejectingSession(t, engine, address)
	require.Equal(t, adapter.MITMStatusFailed, first.state.Status())
	status, _ = decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Len(t, engine.Status().Failures, 1)

	rejectingSession(t, engine, address)
	status, reason := decideExample(engine)
	require.Equal(t, adapter.MITMStatusSkipped, status)
	require.Equal(t, ReasonPinned, reason)

	engineStatus := engine.Status()
	require.Len(t, engineStatus.Skip, 1)
	require.Equal(t, "example.com", engineStatus.Skip[0].Host)
	require.Equal(t, "auto", engineStatus.Skip[0].Source)
	require.WithinDuration(t, time.Now().Add(DefaultPinningSkipDuration), engineStatus.Skip[0].Until, time.Minute)
	require.Len(t, engineStatus.Failures, 1)
	require.Equal(t, 2, engineStatus.Failures[0].Count)
	require.Contains(t, engineStatus.Failures[0].LastError, "client rejected the certificate")
	// Another host is unaffected.
	status, _ = decideStatus(engine, tlsMetadata("other.test", "127.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusNone, status)

	require.True(t, engine.ClearSkip("example.com"))
	status, _ = decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
}

func TestPinningSuccessResetsCount(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()

	rejectingSession(t, engine, address)
	silentSession(t, engine, ca, address, true)
	rejectingSession(t, engine, address)
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Empty(t, engine.Status().Skip)
	rejectingSession(t, engine, address)
	status, _ = decideExample(engine)
	require.Equal(t, adapter.MITMStatusSkipped, status)
}

func TestPinningClosedWithoutRequest(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()

	silentSession(t, engine, ca, address, false)
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	silentSession(t, engine, ca, address, false)
	status, _ = decideExample(engine)
	require.Equal(t, adapter.MITMStatusSkipped, status)
	require.Contains(t, engine.Status().Failures[0].LastError, "without a request")
}

func TestPinningSlowCloseIsNotPinning(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	// The clock jumps past the silence window while the session is open.
	var offset atomic.Int64
	engine.timeFunc = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	address := upstream.Listener.Addr().String()

	for i := 0; i < 3; i++ {
		s := startSession(t, context.Background(), engine, address)
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
		require.NoError(t, clientConn.HandshakeContext(context.Background()))
		require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
		offset.Add(int64(2 * pinningSilenceWindow))
		clientConn.Close()
		s.wait(t)
	}
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Empty(t, engine.Status().Failures)
}

func TestShutdownIsNotPinning(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	s := startSession(t, context.Background(), engine, address)
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
	engine.Close()
	s.wait(t)
	clientConn.Close()
	require.Empty(t, engine.Status().Failures)
}

func TestUpstreamFailureIsLoggedNotSkipped(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	// The upstream certificate is not trusted.
	engine := newTestEngine(t, context.Background(), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	for i := 0; i < 3; i++ {
		s := startSession(t, context.Background(), engine, address)
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
		require.Error(t, clientConn.HandshakeContext(context.Background()))
		s.wait(t)
	}
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	failures := engine.Status().Failures
	require.Len(t, failures, 1)
	require.Equal(t, "example.com", failures[0].Host)
	require.Equal(t, 3, failures[0].Count)
	require.Contains(t, failures[0].LastError, "upstream TLS handshake")
}

func TestCancelledContextIsNotPinning(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		s := startSession(t, ctx, engine, address)
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
		require.NoError(t, clientConn.HandshakeContext(context.Background()))
		require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
		cancel()
		s.wait(t)
		clientConn.Close()
	}
	require.Empty(t, engine.Status().Failures)
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
}

// decryptedSession completes the client handshake and waits for the decrypted state.
func decryptedSession(t *testing.T, s *session, ca testCA) *tls.Conn {
	t.Helper()
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
	return clientConn
}

func TestLocalCloseIsNotPinning(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	for i := 0; i < 3; i++ {
		s := startSession(t, context.Background(), engine, address)
		clientConn := decryptedSession(t, s, ca)
		// The group connection closer closes the routed connection without cancelling the context.
		require.NoError(t, s.routed.Close())
		s.wait(t)
		clientConn.Close()
	}
	require.Empty(t, engine.Status().Failures)
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
}

func TestUpstreamClosingFirstIsNotPinning(t *testing.T) {
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {}))
	upstream.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	for i := 0; i < 3; i++ {
		s := startSession(t, context.Background(), engine, address)
		clientConn := decryptedSession(t, s, ca)
		mu.Lock()
		last := conns[len(conns)-1]
		mu.Unlock()
		require.NoError(t, last.Close())
		// The idle upstream is replaced on demand: the session lives on until the client leaves.
		time.Sleep(200 * time.Millisecond)
		clientConn.Close()
		s.wait(t)
	}
	require.Empty(t, engine.Status().Failures)
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
}

func TestSharedLocalClientDoesNotFeedSkipTable(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	for i := 0; i < 3; i++ {
		s := startSessionFrom(t, context.Background(), engine, address, "127.0.0.1:50000", nil)
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com"})
		require.Error(t, clientConn.HandshakeContext(context.Background()))
		s.wait(t)
	}
	status, _ := decideExample(engine)
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Empty(t, engine.Status().Skip)
	failures := engine.Status().Failures
	require.Len(t, failures, 1)
	require.Equal(t, 3, failures[0].Count)
	// A known process on the same local address keeps its own key.
	app := func(metadata *adapter.InboundContext) {
		metadata.ProcessInfo = &adapter.ConnectionOwner{ProcessPath: "/usr/bin/app"}
	}
	for i := 0; i < 2; i++ {
		s := startSessionFrom(t, context.Background(), engine, address, "127.0.0.1:50000", app)
		clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com"})
		require.Error(t, clientConn.HandshakeContext(context.Background()))
		s.wait(t)
	}
	require.Len(t, engine.Status().Skip, 1)
}

// TestTLS13FinishedFailureClassification covers the errors crypto/tls reports
// while waiting for the client's Finished. The "bad record MAC" form was seen
// with curl 7.76.1 (OpenSSL 3.2.2) rejecting the certificate; Go clients
// report the plain remote alert, which the flow test above covers.
func TestTLS13FinishedFailureClassification(t *testing.T) {
	engine := newTestEngine(t, context.Background(), pinningOptions(writeTestCA(t)))
	tracker := func() *pinningTracker {
		return &pinningTracker{engine: engine, host: "example.com", key: pinKey{process: "/bin/curl"}, duration: time.Hour}
	}
	macErr := &net.OpError{Op: "local error", Err: tlsAlertError("tls: bad record MAC")}
	require.False(t, tracker().handshakeFailed(macErr, false))
	require.False(t, tracker().handshakeFailed(io.EOF, false))
	require.False(t, tracker().handshakeFailed(context.Canceled, true))
	require.False(t, tracker().handshakeFailed(net.ErrClosed, true))
	require.False(t, tracker().handshakeFailed(&net.OpError{Op: "local error", Err: tlsAlertError("tls: protocol version not supported")}, true))
	require.Empty(t, engine.Status().Failures)

	require.False(t, tracker().handshakeFailed(macErr, true))
	require.True(t, tracker().handshakeFailed(macErr, true))
	require.Len(t, engine.Status().Skip, 1)
	require.Contains(t, engine.Status().Failures[0].LastError, "bad record MAC")
}

type tlsAlertError string

func (e tlsAlertError) Error() string { return string(e) }

// A Go client with an unknown CA reaches the skip table through the TLS 1.3
// path as well.
func TestTLS13RejectedCertificateReachesSkipTable(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), pinningOptions(ca))
	address := upstream.Listener.Addr().String()
	rejectingSession(t, engine, address)
	rejectingSession(t, engine, address)
	status, reason := decideExample(engine)
	require.Equal(t, adapter.MITMStatusSkipped, status)
	require.Equal(t, ReasonPinned, reason)
}
