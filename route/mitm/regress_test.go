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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// silentUpstream accepts connections and never answers.
func silentUpstream(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		var conns []net.Conn
		defer func() {
			for _, conn := range conns {
				conn.Close()
			}
		}()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conns = append(conns, conn)
		}
	}()
	return listener.Addr().String()
}

// A client close or an interrupt (closing the routed connection) cancels a stalled upstream
// handshake at once.
func TestServeClientCloseDuringUpstreamHandshake(t *testing.T) {
	for _, interrupt := range []bool{true, false} {
		ca := writeTestCA(t)
		engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"example.com"}, nil))
		s := startSession(t, context.Background(), engine, silentUpstream(t))
		go func() {
			clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
			_ = clientConn.HandshakeContext(context.Background())
		}()
		time.Sleep(300 * time.Millisecond)
		start := time.Now()
		if interrupt {
			s.routed.Close()
		} else {
			s.client.Close()
		}
		s.wait(t)
		require.Less(t, time.Since(start), 3*time.Second)
		require.Equal(t, adapter.MITMStatusFailed, s.state.Status())
		require.Contains(t, s.state.Reason(), "client closed during upstream TLS handshake")
		// A client abort is no failure of the outbound.
		require.NoError(t, *s.closeErr.Load())
	}
}

// Bytes the client sends while the upstream handshake runs reach the TLS server intact.
func TestHandshakeConnKeepsWatchedBytes(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	conn := &handshakeConn{Conn: near}
	canceled := make(chan struct{})
	stop := conn.watch(func() { close(canceled) })
	go far.Write([]byte("abc"))
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, stop())
	select {
	case <-canceled:
		t.Fatal("canceled without a close")
	default:
	}
	go far.Write([]byte("def"))
	buffer := make([]byte, 6)
	_, err := io.ReadFull(conn, buffer)
	require.NoError(t, err)
	require.Equal(t, "abcdef", string(buffer))

	stop = conn.watch(func() { close(canceled) })
	far.Close()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("close not noticed")
	}
	require.Error(t, stop())
}

// A reload that removed the authority between Decide and Serve passes the connection through.
func TestServeAuthorityRemovedPassesThrough(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	commit, err := engine.Reload(&option.MITMOptions{
		Enabled:     true,
		Certificate: &option.MITMCertificateOptions{Source: C.MITMCertificateSourceManaged},
		Hostnames:   &option.MITMHostnamesOptions{Include: []string{"example.com"}},
	})
	require.NoError(t, err)
	commit()
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	client := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: upstreamPool(upstream)})
			return conn, conn.HandshakeContext(ctx)
		},
	}}
	response, err := client.Get("https://example.com/plain")
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, "body of /plain", string(body))
	require.True(t, response.TLS.PeerCertificates[0].Equal(upstream.Certificate()))
	require.Equal(t, adapter.MITMStatusSkipped, s.state.Status())
	require.Equal(t, ReasonAuthorityPending, s.state.Reason())
	client.CloseIdleConnections()
	s.wait(t)
}

func upstreamPool(upstream *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	return pool
}

type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetReadDeadline(time.Time) error { return os.ErrInvalid }
func (noDeadlineConn) SetDeadline(time.Time) error     { return os.ErrInvalid }

// startRawSession is startSession with the routed connections wrapped.
func startRawSession(t *testing.T, engine *Engine, upstreamAddress string, wrap func(net.Conn) net.Conn) *session {
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
	metadata.MITM = adapter.NewMITMState(adapter.MITMStatusPending, "")
	s := &session{client: client, routed: serverSide, state: metadata.MITM, done: make(chan struct{})}
	go func() {
		engine.Serve(context.Background(), wrap(serverSide), wrap(upstream), testRedial(upstreamAddress, wrap), metadata, func(err error) {
			s.closes.Add(1)
			s.closeErr.Store(&err)
		})
		close(s.done)
	}()
	return s
}

// Connections without read deadlines (ssh, gRPC, HTTP transports) keep working on keep-alive
// reuse, and an interrupt still ends a stalled handshake.
func TestServeWithoutReadDeadlines(t *testing.T) {
	wrap := func(conn net.Conn) net.Conn { return noDeadlineConn{conn} }
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	s := startRawSession(t, engine, upstream.Listener.Addr().String(), wrap)
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	reader := bufio.NewReader(clientConn)
	for _, path := range []string{"/1", "/2", "/3"} {
		start := time.Now()
		_, err := io.WriteString(clientConn, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, "body of "+path, string(body))
		require.Less(t, time.Since(start), time.Second)
	}
	require.Equal(t, int64(3), s.state.Requests())
	s.routed.Close()
	s.wait(t)

	stalled := startRawSession(t, engine, silentUpstream(t), wrap)
	go func() {
		clientConn := tls.Client(stalled.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
		_ = clientConn.HandshakeContext(context.Background())
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	stalled.routed.Close()
	stalled.wait(t)
	require.Less(t, time.Since(start), 3*time.Second)
	require.Contains(t, stalled.state.Reason(), "client closed during upstream TLS handshake")
}

// A handshake watch on a connection that refuses deadlines fails instead of blocking.
func TestHandshakeConnStopWithoutDeadline(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	conn := &handshakeConn{Conn: noDeadlineConn{near}}
	stop := conn.watch(func() {})
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	select {
	case err := <-stopped:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("stop blocked")
	}
}

// Pipelined keep-alive requests over the full TLS path answer in order, with and without native
// read deadlines, and every session reports exactly one close.
func TestPipelinedKeepAliveOverTLS(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	iterations := 20
	if testing.Short() {
		iterations = 3
	}
	for _, wrap := range []func(net.Conn) net.Conn{
		func(conn net.Conn) net.Conn { return conn },
		func(conn net.Conn) net.Conn { return noDeadlineConn{conn} },
	} {
		for iter := 0; iter < iterations; iter++ {
			s := startRawSession(t, engine, upstream.Listener.Addr().String(), wrap)
			clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca)})
			require.NoError(t, clientConn.HandshakeContext(context.Background()))
			clientConn.SetDeadline(time.Now().Add(10 * time.Second))
			const n = 30
			var requests strings.Builder
			for i := 0; i < n; i++ {
				requests.WriteString("GET /" + string(rune('a'+i%26)) + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
			}
			go io.WriteString(clientConn, requests.String())
			reader := bufio.NewReader(clientConn)
			for i := 0; i < n; i++ {
				response, err := http.ReadResponse(reader, nil)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, "body of /"+string(rune('a'+i%26)), string(body))
			}
			require.Equal(t, int64(n), s.state.Requests())
			clientConn.Close()
			s.wait(t)
			require.Equal(t, int32(1), s.closes.Load())
		}
	}
}
