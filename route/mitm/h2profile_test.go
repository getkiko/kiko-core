package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2Wire is what an HTTP/2 origin sees of the core before the first request.
type h2Wire struct {
	settings     []http2.Setting
	windowUpdate uint32
	pseudo       []string
	fields       []string
	headersEnd   bool
	priority     http2.PriorityParam
}

// captureH2Wire serves one decrypted h2 connection of a browser-like client
// and returns the wire image the upstream (a raw h2 server) received.
func captureH2Wire(t *testing.T, options *option.MITMUpstreamOptions) h2Wire {
	t.Helper()
	if !h2Supported {
		t.Skip("h2 relay needs Go 1.26")
	}
	server := newUpstream(t)
	config := server.TLS.Clone()
	config.NextProtos = []string{"h2"}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	wires := make(chan h2Wire, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := readFull(conn, preface); err != nil {
			return
		}
		framer := http2.NewFramer(conn, conn)
		framer.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
		framer.WriteSettings()
		var wire h2Wire
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() && wire.settings == nil {
					f.ForeachSetting(func(s http2.Setting) error {
						wire.settings = append(wire.settings, s)
						return nil
					})
					framer.WriteSettingsAck()
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 && wire.windowUpdate == 0 {
					wire.windowUpdate = f.Increment
				}
			case *http2.MetaHeadersFrame:
				wire.headersEnd = f.StreamEnded()
				wire.priority = f.Priority
				for _, field := range f.Fields {
					if field.IsPseudo() {
						wire.pseudo = append(wire.pseudo, field.Name)
					} else {
						wire.fields = append(wire.fields, field.Name)
					}
				}
				wires <- wire
				var block bytes.Buffer
				hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				framer.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true})
				framer.WriteData(f.StreamID, true, []byte("ok"))
			}
		}
	}()

	ca := writeTestCA(t)
	enabled := true
	mitmOptions := h2Options(ca, &enabled)
	mitmOptions.Upstream = options
	engine := newTestEngine(t, contextWithRoots(server), mitmOptions)
	s, clientConn := startRedialSessionALPN(t, engine, ca, listener.Addr().String(), nil, []string{"h2", "http/1.1"})
	client := h2Client(t, clientConn)
	request, err := http.NewRequest("GET", "https://example.com/a", nil)
	require.NoError(t, err)
	request.Header.Set("Accept-Language", "en")
	request.Header.Set("User-Agent", "ua")
	request.Header.Set("Accept", "*/*")
	response, err := client.Do(request)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 2, response.ProtoMajor)
	_ = s
	select {
	case wire := <-wires:
		return wire
	case <-time.After(10 * time.Second):
		t.Fatal("upstream saw no request")
		return h2Wire{}
	}
}

func TestUpstreamH2ChromeWire(t *testing.T) {
	wire := captureH2Wire(t, &option.MITMUpstreamOptions{H2Profile: "chrome"})
	require.Equal(t, []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}, wire.settings)
	require.Equal(t, uint32(15663105), wire.windowUpdate)
	require.Equal(t, []string{":method", ":authority", ":scheme", ":path"}, wire.pseudo)
	require.Equal(t, []string{"user-agent", "accept", "accept-encoding", "accept-language"}, wire.fields)
	// A request without a body ends on its HEADERS frame, which carries Chrome's priority.
	require.True(t, wire.headersEnd)
	require.Equal(t, http2.PriorityParam{Exclusive: true, Weight: 255}, wire.priority)
}

func TestUpstreamH2UnknownProfile(t *testing.T) {
	_, err := NewEngine(context.Background(), log.NewNOPFactory().NewLogger("mitm"), upstreamOptions(t, &option.MITMUpstreamOptions{H2Profile: "firefox"}))
	require.ErrorContains(t, err, "unknown upstream h2 profile")
}

// Without h2_profile the upstream HTTP/2 client is net/http's, whatever the TLS fingerprint.
func TestUpstreamH2DefaultProfile(t *testing.T) {
	wire := captureH2Wire(t, nil)
	require.Equal(t, []string{":authority", ":method", ":path", ":scheme"}, wire.pseudo)
	require.NotEqual(t, uint32(15663105), wire.windowUpdate)
}

func readFull(conn net.Conn, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := conn.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
