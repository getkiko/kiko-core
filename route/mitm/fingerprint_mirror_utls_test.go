//go:build with_utls

package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// helloShape is the part of a ClientHello a mirror must preserve: cipher
// suites and extension types in order, GREASE normalized, padding and
// pre-shared keys (which depend on the connection) left out.
func helloShape(t *testing.T, record []byte) (suites []uint16, extensions []uint16) {
	t.Helper()
	ids, ok := helloExtensionIDs(record)
	require.True(t, ok)
	for _, id := range ids {
		switch {
		case id == 21 || id == extensionPreSharedKey:
		case isGREASE(id):
			extensions = append(extensions, 0x0a0a)
		default:
			extensions = append(extensions, id)
		}
	}
	// Cipher suites: record header (5), handshake header (4), version, random, session id.
	pos := 5 + 4 + 2 + 32
	pos += 1 + int(record[pos])
	count := int(record[pos])<<8 | int(record[pos+1])
	for i := 0; i < count; i += 2 {
		suite := uint16(record[pos+2+i])<<8 | uint16(record[pos+3+i])
		if isGREASE(suite) {
			suite = 0x0a0a
		}
		suites = append(suites, suite)
	}
	return suites, extensions
}

// mirrorUpstream returns the ClientHello records an upstream received, per connection.
func mirrorUpstream(t *testing.T) (string, <-chan []byte, context.Context) {
	t.Helper()
	server := newUpstream(t)
	hellos := make(chan []byte, 4)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	config := server.TLS.Clone()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				capture := &helloCapture{Conn: conn}
				tlsConn := tls.Server(capture, config)
				if tlsConn.Handshake() != nil {
					return
				}
				hellos <- capture.snapshot()
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return listener.Addr().String(), hellos, contextWithRoots(server)
}

// browserHello is the ClientHello record a browser parrot sends.
func browserHello(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	uconn := utls.UClient(client, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, id)
	require.NoError(t, uconn.BuildHandshakeState())
	raw := uconn.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}, raw...)
}

// TestMirrorClientHello checks that the upstream hello copies the client's
// cipher suites and extension order instead of the fixed Chrome fingerprint.
func TestMirrorClientHello(t *testing.T) {
	for name, id := range map[string]utls.ClientHelloID{
		"firefox": utls.HelloFirefox_120,
		"safari":  utls.HelloSafari_16_0,
		"chrome":  utls.HelloChrome_133,
		"ios":     utls.HelloIOS_14,
	} {
		t.Run(name, func(t *testing.T) {
			address, hellos, ctx := mirrorUpstream(t)
			record := browserHello(t, id)
			engine := newTestEngine(t, ctx, upstreamOptions(t, &option.MITMUpstreamOptions{MirrorClientHello: true}))
			conn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			defer conn.Close()
			handshake, cancel := context.WithTimeout(clientHelloContext(context.Background(), record), 5*time.Second)
			defer cancel()
			upstream, _, _, err := engine.handshakeUpstream(handshake, engine.config.Load(), conn, "example.com", 443, []string{"http/1.1"})
			require.NoError(t, err)
			defer upstream.Close()
			var received []byte
			select {
			case received = <-hellos:
			case <-time.After(5 * time.Second):
				t.Fatal("no upstream ClientHello")
			}
			wantSuites, wantExtensions := helloShape(t, record)
			gotSuites, gotExtensions := helloShape(t, received)
			require.Equal(t, wantSuites, gotSuites)
			require.Equal(t, wantExtensions, gotExtensions)
		})
	}
}

// Without the option, or when no ClientHello is known, the fixed fingerprint applies.
func TestMirrorClientHelloFallback(t *testing.T) {
	fixed := func(options *option.MITMUpstreamOptions, ctx context.Context) []uint16 {
		address, hellos, rootCtx := mirrorUpstream(t)
		engine := newTestEngine(t, rootCtx, upstreamOptions(t, options))
		conn, err := net.Dial("tcp", address)
		require.NoError(t, err)
		defer conn.Close()
		handshake, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		upstream, _, _, err := engine.handshakeUpstream(handshake, engine.config.Load(), conn, "example.com", 443, []string{"http/1.1"})
		require.NoError(t, err)
		defer upstream.Close()
		_, extensions := helloShape(t, <-hellos)
		return extensions
	}
	firefox := browserHello(t, utls.HelloFirefox_120)
	chrome := fixed(nil, context.Background())
	_, firefoxExtensions := helloShape(t, firefox)
	require.NotEqual(t, firefoxExtensions, chrome)
	// The option off: the client's hello is ignored even when present.
	require.Equal(t, len(chrome), len(fixed(nil, clientHelloContext(context.Background(), firefox))))
	// The option on without a hello, or with garbage: the fixed fingerprint.
	require.Equal(t, len(chrome), len(fixed(&option.MITMUpstreamOptions{MirrorClientHello: true}, context.Background())))
	require.Equal(t, len(chrome), len(fixed(&option.MITMUpstreamOptions{MirrorClientHello: true}, clientHelloContext(context.Background(), []byte{0x16, 3, 1, 0, 2, 9, 9}))))
}
