package mitm

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func writeServerRoot(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.pem")
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// upstreamHandshake dials the server and handshakes through the engine.
func upstreamHandshake(t *testing.T, engine *Engine, address string, serverName string) error {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upstream, _, _, err := engine.handshakeUpstream(ctx, engine.config.Load(), conn, serverName, 443, []string{"http/1.1"})
	if err != nil {
		conn.Close()
		return err
	}
	upstream.Close()
	return nil
}

func upstreamOptions(t *testing.T, upstream *option.MITMUpstreamOptions) *option.MITMOptions {
	t.Helper()
	options := fileOptions(writeTestCA(t), true, []string{"example.com"}, nil)
	options.Upstream = upstream
	return options
}

func TestUpstreamVerification(t *testing.T) {
	server := newUpstream(t)
	address := server.Listener.Addr().String()

	// The self-signed upstream is untrusted by default.
	engine := newTestEngine(t, context.Background(), upstreamOptions(t, nil))
	require.Error(t, upstreamHandshake(t, engine, address, "example.com"))

	// custom_roots adds it to the roots of every host.
	engine = newTestEngine(t, context.Background(), upstreamOptions(t, &option.MITMUpstreamOptions{CustomRoots: []string{writeServerRoot(t, server)}}))
	require.NoError(t, upstreamHandshake(t, engine, address, "example.com"))
	// The name is still verified.
	require.Error(t, upstreamHandshake(t, engine, address, "other.test"))

	// skip_verify skips verification for the listed hosts only.
	engine = newTestEngine(t, context.Background(), upstreamOptions(t, &option.MITMUpstreamOptions{SkipVerify: []string{"*.other.test", "example.com"}}))
	require.NoError(t, upstreamHandshake(t, engine, address, "example.com"))
	require.NoError(t, upstreamHandshake(t, engine, address, "x.other.test"))
	require.Error(t, upstreamHandshake(t, engine, address, "other.test"))
	engine = newTestEngine(t, context.Background(), upstreamOptions(t, &option.MITMUpstreamOptions{SkipVerify: []string{"*.example.org"}}))
	require.Error(t, upstreamHandshake(t, engine, address, "example.com"))

	// The core's roots still work, and custom_roots extend them.
	engine = newTestEngine(t, contextWithRoots(server), upstreamOptions(t, nil))
	require.NoError(t, upstreamHandshake(t, engine, address, "example.com"))
	engine = newTestEngine(t, contextWithRoots(server), upstreamOptions(t, &option.MITMUpstreamOptions{CustomRoots: []string{writeServerRoot(t, server)}}))
	require.NoError(t, upstreamHandshake(t, engine, address, "example.com"))
}

func TestUpstreamOptionsReload(t *testing.T) {
	server := newUpstream(t)
	address := server.Listener.Addr().String()
	engine := newTestEngine(t, context.Background(), upstreamOptions(t, nil))
	require.Error(t, upstreamHandshake(t, engine, address, "example.com"))
	commit, err := engine.Reload(upstreamOptions(t, &option.MITMUpstreamOptions{SkipVerify: []string{"example.com"}}))
	require.NoError(t, err)
	require.Error(t, upstreamHandshake(t, engine, address, "example.com"))
	commit()
	require.NoError(t, upstreamHandshake(t, engine, address, "example.com"))
}

func TestServeSkipVerifyMarksState(t *testing.T) {
	server := newUpstream(t)
	ca := writeTestCA(t)
	options := fileOptions(ca, true, []string{"example.com"}, nil)
	options.Upstream = &option.MITMUpstreamOptions{SkipVerify: []string{"example.com"}}
	engine := newTestEngine(t, context.Background(), options)
	s := startSession(t, context.Background(), engine, server.Listener.Addr().String())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
	require.True(t, s.state.Unverified())
	clientConn.Close()
	s.wait(t)

	// Verified connections are not marked.
	engine = newTestEngine(t, contextWithRoots(server), fileOptions(ca, true, []string{"example.com"}, nil))
	s = startSession(t, context.Background(), engine, server.Listener.Addr().String())
	clientConn = tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
	require.False(t, s.state.Unverified())
	clientConn.Close()
	s.wait(t)
}

// capturedHello is what an upstream server sees of the core's ClientHello.
type capturedHello struct {
	cipherSuites []uint16
	curves       []tls.CurveID
	schemes      []tls.SignatureScheme
}

func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && value>>8 == value&0xff
}

func (h capturedHello) hasGREASE() bool {
	for _, suite := range h.cipherSuites {
		if isGREASE(suite) {
			return true
		}
	}
	return false
}

func (h capturedHello) signature() string {
	var out []byte
	for _, suite := range h.cipherSuites {
		if !isGREASE(suite) {
			out = append(out, byte(suite>>8), byte(suite))
		}
	}
	out = append(out, 0xff, 0xff)
	for _, curve := range h.curves {
		if !isGREASE(uint16(curve)) {
			out = append(out, byte(curve>>8), byte(curve))
		}
	}
	out = append(out, 0xff, 0xff)
	for _, scheme := range h.schemes {
		out = append(out, byte(scheme>>8), byte(scheme))
	}
	return string(out)
}

// captureHello handshakes through the engine with the fingerprint and returns
// the ClientHello the server received.
func captureHello(t *testing.T, fingerprint string) capturedHello {
	t.Helper()
	server := newUpstream(t)
	hellos := make(chan capturedHello, 1)
	config := server.TLS.Clone()
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		hellos <- capturedHello{
			cipherSuites: append([]uint16(nil), hello.CipherSuites...),
			curves:       append([]tls.CurveID(nil), hello.SupportedCurves...),
			schemes:      append([]tls.SignatureScheme(nil), hello.SignatureSchemes...),
		}
		return nil, nil
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	engine := newTestEngine(t, contextWithRoots(server), upstreamOptions(t, &option.MITMUpstreamOptions{Fingerprint: fingerprint}))
	require.NoError(t, upstreamHandshake(t, engine, listener.Addr().String(), "example.com"))
	select {
	case hello := <-hellos:
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello")
		return capturedHello{}
	}
}

func TestUpstreamFingerprintNone(t *testing.T) {
	hello := captureHello(t, "none")
	require.False(t, hello.hasGREASE())
}

func TestServeFailedUpstreamHandshakeIsNotUnverified(t *testing.T) {
	broken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { broken.Close() })
	go func() {
		for {
			conn, acceptErr := broken.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()
	ca := writeTestCA(t)
	options := fileOptions(ca, true, []string{"example.com"}, nil)
	options.Upstream = &option.MITMUpstreamOptions{SkipVerify: []string{"example.com"}}
	engine := newTestEngine(t, context.Background(), options)
	s := startSession(t, context.Background(), engine, broken.Addr().String())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.Error(t, clientConn.HandshakeContext(context.Background()))
	s.wait(t)
	require.Equal(t, adapter.MITMStatusFailed, s.state.Status())
	require.False(t, s.state.Unverified())
}

func TestVerifySkippedPortAware(t *testing.T) {
	engine := newTestEngine(t, context.Background(), upstreamOptions(t, &option.MITMUpstreamOptions{SkipVerify: []string{"dev.example.com:8443", "plain.example.com", "*.wild.test:9443"}}))
	upstream := engine.config.Load().upstream
	require.True(t, upstream.verifySkipped("dev.example.com", 8443))
	require.False(t, upstream.verifySkipped("dev.example.com", 443))
	require.False(t, upstream.verifySkipped("dev.example.com", 0))
	require.True(t, upstream.verifySkipped("plain.example.com", 443))
	require.True(t, upstream.verifySkipped("plain.example.com", 0))
	require.False(t, upstream.verifySkipped("plain.example.com", 8443))
	require.True(t, upstream.verifySkipped("a.wild.test", 9443))
	require.False(t, upstream.verifySkipped("a.wild.test", 443))
}
