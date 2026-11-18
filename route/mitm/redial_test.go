package mitm

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// upstreamScript is what one upstream connection does.
type upstreamScript int

const (
	// scriptServe answers every request and keeps the connection open.
	scriptServe upstreamScript = iota
	// scriptCloseIdle answers the first request, then closes the idle connection.
	scriptCloseIdle
	// scriptResetSecond answers the first request, reads the second request head, then resets.
	scriptResetSecond
	// scriptResetFirst reads the first request head, then resets.
	scriptResetFirst
)

// scriptedUpstream is a TLS HTTP/1.1 server; script gives the behaviour of each accepted
// connection by its index. Answers name the connection, method and path.
type scriptedUpstream struct {
	address string
	script  func(index int) upstreamScript
	config  *tls.Config
	accepts atomic.Int32
	access  sync.Mutex
	seen    []string
	idle    chan int // connection indexes closed by scriptCloseIdle
}

// newScriptedUpstream returns the upstream and a context whose roots trust it.
func newScriptedUpstream(t *testing.T, script func(index int) upstreamScript) (*scriptedUpstream, context.Context) {
	// The httptest server only provides the certificate and its roots.
	certificateSource := newUpstream(t)
	return startScriptedUpstream(t, script, certificateSource.TLS.Clone()), contextWithRoots(certificateSource)
}

func startScriptedUpstream(t *testing.T, script func(index int) upstreamScript, config *tls.Config) *scriptedUpstream {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	u := &scriptedUpstream{
		address: listener.Addr().String(),
		script:  script,
		config:  config,
		idle:    make(chan int, 8),
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			index := int(u.accepts.Add(1)) - 1
			go u.handle(index, conn.(*net.TCPConn))
		}
	}()
	return u
}

// selfSignedConfig serves a certificate for example.com that no test root trusts.
func selfSignedConfig(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func (u *scriptedUpstream) record(entry string) {
	u.access.Lock()
	u.seen = append(u.seen, entry)
	u.access.Unlock()
}

func (u *scriptedUpstream) entries() []string {
	u.access.Lock()
	defer u.access.Unlock()
	return slices.Clone(u.seen)
}

func (u *scriptedUpstream) handle(index int, raw *net.TCPConn) {
	conn := tls.Server(raw, u.config)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	script := u.script(index)
	prefix := "conn " + strconv.Itoa(index) + " "
	for n := 0; ; n++ {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if script == scriptResetFirst && n == 0 || script == scriptResetSecond && n == 1 {
			u.record(prefix + request.Method + " " + request.URL.Path + " reset")
			_ = raw.SetLinger(0)
			_ = raw.Close()
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return
		}
		u.record(prefix + request.Method + " " + request.URL.Path + " " + string(body))
		answer := prefix + request.Method + " " + request.URL.Path
		_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(answer))+"\r\n\r\n"+answer)
		if err != nil {
			return
		}
		if script == scriptCloseIdle {
			conn.Close()
			u.idle <- index
			return
		}
	}
}

// countingRedial counts its calls and dials address, or fails with err.
type countingRedial struct {
	address string
	err     error
	calls   atomic.Int32
}

func (r *countingRedial) redial(ctx context.Context) (net.Conn, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", r.address)
}

// startRedialSession serves one decrypted connection to upstream with redial and returns the
// client's TLS connection.
func startRedialSession(t *testing.T, engine *Engine, ca testCA, address string, redial adapter.MITMRedialFunc) (*session, *tls.Conn) {
	return startRedialSessionALPN(t, engine, ca, address, redial, nil)
}

// startRedialSessionALPN is startRedialSession with a client that offers the protocols.
func startRedialSessionALPN(t *testing.T, engine *Engine, ca testCA, address string, redial adapter.MITMRedialFunc, protocols []string) (*session, *tls.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	serverSide, err := listener.Accept()
	require.NoError(t, err)
	upstream, err := net.Dial("tcp", address)
	require.NoError(t, err)
	metadata := tlsMetadata("example.com", "127.0.0.1:443")
	metadata.MITM = adapter.NewMITMState(adapter.MITMStatusPending, "")
	s := &session{client: client, routed: serverSide, state: metadata.MITM, done: make(chan struct{})}
	go func() {
		engine.Serve(context.Background(), serverSide, upstream, redial, metadata, func(err error) {
			s.closes.Add(1)
			s.closeErr.Store(&err)
		})
		close(s.done)
	}()
	clientConn := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: protocols})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(10*time.Second)))
	return s, clientConn
}

type redialClient struct {
	conn   *tls.Conn
	reader *bufio.Reader
}

// do sends one request and returns the status and body of its response.
func (c *redialClient) do(method string, path string, body string) (int, string, error) {
	head := method + " " + path + " HTTP/1.1\r\nHost: example.com\r\n"
	if body != "" {
		head += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	if _, err := io.WriteString(c.conn, head+"\r\n"+body); err != nil {
		return 0, "", err
	}
	response, err := http.ReadResponse(c.reader, nil)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	return response.StatusCode, string(content), err
}

func newRedialClient(conn *tls.Conn) *redialClient {
	return &redialClient{conn: conn, reader: bufio.NewReader(conn)}
}

func firstConnection(script upstreamScript) func(int) upstreamScript {
	return func(index int) upstreamScript {
		if index == 0 {
			return script
		}
		return scriptServe
	}
}

func waitIdleClose(t *testing.T, u *scriptedUpstream) {
	t.Helper()
	select {
	case <-u.idle:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not close")
	}
	// Let the session notice the close while idle.
	time.Sleep(100 * time.Millisecond)
}

// An upstream that closes an idle keep-alive connection is redialed for the next request, on
// the same client connection; a request with a body is sent whole to the new connection.
func TestRedialAfterIdleClose(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			u, ctx := newScriptedUpstream(t, firstConnection(scriptCloseIdle))
			ca := writeTestCA(t)
			engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
			redial := &countingRedial{address: u.address}
			s, clientConn := startRedialSession(t, engine, ca, u.address, redial.redial)
			client := newRedialClient(clientConn)

			status, body, err := client.do(http.MethodGet, "/1", "")
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, "conn 0 GET /1", body)
			waitIdleClose(t, u)

			var requestBody string
			if method == http.MethodPost {
				requestBody = "hello"
			}
			status, body, err = client.do(method, "/2", requestBody)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, "conn 1 "+method+" /2", body)
			status, body, err = client.do(http.MethodGet, "/3", "")
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, "conn 1 GET /3", body)

			require.Equal(t, int32(1), redial.calls.Load())
			require.Equal(t, int32(2), u.accepts.Load())
			require.Equal(t, []string{"conn 0 GET /1 ", "conn 1 " + method + " /2 " + requestBody, "conn 1 GET /3 "}, u.entries())
			require.Equal(t, int64(3), s.state.Requests())
			clientConn.Close()
			s.wait(t)
			require.NoError(t, *s.closeErr.Load())
		})
	}
}

// A reused upstream connection reset right after reading a GET head is redialed and the GET
// answered from the new connection.
func TestRedialAfterResetOfReusedConnection(t *testing.T) {
	u, ctx := newScriptedUpstream(t, firstConnection(scriptResetSecond))
	ca := writeTestCA(t)
	engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
	redial := &countingRedial{address: u.address}
	s, clientConn := startRedialSession(t, engine, ca, u.address, redial.redial)
	client := newRedialClient(clientConn)

	for i, want := range []string{"conn 0 GET /1", "conn 1 GET /2", "conn 1 GET /3"} {
		status, body, err := client.do(http.MethodGet, "/"+strconv.Itoa(i+1), "")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, want, body)
	}
	require.Equal(t, int32(1), redial.calls.Load())
	require.Equal(t, []string{"conn 0 GET /1 ", "conn 0 GET /2 reset", "conn 1 GET /2 ", "conn 1 GET /3 "}, u.entries())
	require.Equal(t, int64(3), s.state.Requests())
	clientConn.Close()
	s.wait(t)
}

// A POST with a body that reached a reused connection before it was reset is not repeated:
// the client connection closes and no second POST reaches the upstream.
func TestNoRedialOfSentPost(t *testing.T) {
	u, ctx := newScriptedUpstream(t, firstConnection(scriptResetSecond))
	ca := writeTestCA(t)
	engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
	redial := &countingRedial{address: u.address}
	s, clientConn := startRedialSession(t, engine, ca, u.address, redial.redial)
	client := newRedialClient(clientConn)

	status, _, err := client.do(http.MethodGet, "/1", "")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	_, _, err = client.do(http.MethodPost, "/p", strings.Repeat("x", 1024))
	require.Error(t, err)
	var netErr net.Error
	require.False(t, errors.As(err, &netErr) && netErr.Timeout(), "client connection not closed: %v", err)
	s.wait(t)
	// The session is over; give a stray redial time to show.
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(0), redial.calls.Load())
	require.Equal(t, int32(1), u.accepts.Load())
	require.Equal(t, []string{"conn 0 GET /1 ", "conn 0 POST /p reset"}, u.entries())
}

// A failed redial ends the session without waiting: on a reused session with a close (see
// requireFailedRedial), on the first exchange with 502.
func TestRedialFailure(t *testing.T) {
	failure := errors.New("refused")
	t.Run("reused", func(t *testing.T) {
		u, ctx := newScriptedUpstream(t, firstConnection(scriptCloseIdle))
		ca := writeTestCA(t)
		engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
		redial := &countingRedial{address: u.address, err: failure}
		s, clientConn := startRedialSession(t, engine, ca, u.address, redial.redial)
		client := newRedialClient(clientConn)
		status, _, err := client.do(http.MethodGet, "/1", "")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		waitIdleClose(t, u)
		requireFailedRedial(t, client)
		s.wait(t)
		require.Equal(t, int32(1), redial.calls.Load())
		require.Equal(t, int32(1), u.accepts.Load())
	})
	t.Run("first", func(t *testing.T) {
		u, ctx := newScriptedUpstream(t, firstConnection(scriptResetFirst))
		ca := writeTestCA(t)
		engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
		redial := &countingRedial{address: u.address, err: failure}
		s, clientConn := startRedialSession(t, engine, ca, u.address, redial.redial)
		client := newRedialClient(clientConn)
		status, _, err := client.do(http.MethodGet, "/1", "")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadGateway, status)
		clientConn.Close()
		s.wait(t)
		require.LessOrEqual(t, redial.calls.Load(), int32(1))
	})
}

// A redialed upstream is verified like the first one: an upstream whose certificate the core
// does not trust fails the redial, and the session ends.
func TestRedialVerifiesUpstream(t *testing.T) {
	u, ctx := newScriptedUpstream(t, firstConnection(scriptCloseIdle))
	untrusted := startScriptedUpstream(t, firstConnection(scriptServe), selfSignedConfig(t))
	ca := writeTestCA(t)
	engine := newTestEngine(t, ctx, fileOptions(ca, true, []string{"example.com"}, nil))
	redial := &countingRedial{address: untrusted.address}
	s, clientConn := startRedialSession(t, engine, ca, u.address, redial.redial)
	client := newRedialClient(clientConn)
	status, _, err := client.do(http.MethodGet, "/1", "")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	waitIdleClose(t, u)
	requireFailedRedial(t, client)
	s.wait(t)
	require.Equal(t, int32(1), redial.calls.Load())
	require.Empty(t, untrusted.entries())
}

// requireFailedRedial sends a request on a reused session whose redial fails: h1 closes the
// client connection without an answer, so that the client retries on a new one; it never waits.
func requireFailedRedial(t *testing.T, client *redialClient) {
	t.Helper()
	status, _, err := client.do(http.MethodGet, "/2", "")
	require.Error(t, err, "got status %d, want a close", status)
	var netErr net.Error
	require.False(t, errors.As(err, &netErr) && netErr.Timeout(), "client connection not closed: %v", err)
}
