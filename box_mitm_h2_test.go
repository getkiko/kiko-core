package box_test

import (
	"bytes"
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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	h2relay "github.com/sagernet/sing-box/common/mitm/h2"
	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// mitmStateTracker records the decryption state of every routed connection.
type mitmStateTracker struct {
	access sync.Mutex
	states []*adapter.MITMState
}

func (t *mitmStateTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if metadata.MITM != nil {
		t.access.Lock()
		t.states = append(t.states, metadata.MITM)
		t.access.Unlock()
	}
	return conn
}

func (t *mitmStateTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	return conn
}

func (t *mitmStateTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

func (t *mitmStateTracker) snapshot() []*adapter.MITMState {
	t.access.Lock()
	defer t.access.Unlock()
	return append([]*adapter.MITMState(nil), t.states...)
}

// mitmSectionH2 is mitmSection with the h2 option set.
func mitmSectionH2(ca mitmTestCA, h2 bool, include ...string) string {
	var section map[string]any
	_ = json.Unmarshal([]byte(mitmSection(ca, true, include...)), &section)
	section["h2"] = h2
	content, _ := json.Marshal(section)
	return string(content)
}

// HTTP/2 through mixed CONNECT → sniff → direct → decryption in front of an origin that speaks
// h2 and http/1.1: the client gets h2 with the MITM certificate, h2 off gives HTTP/1.1 to new
// connections only, a session open across the reload keeps working, and a WebSocket
// (http/1.1 ALPN on its own connection) still works against the same origin.
func TestMITMHTTP2(t *testing.T) {
	if !h2relay.Supported {
		t.Skip("h2 relay needs Go 1.26")
	}
	var (
		originAccess sync.Mutex
		originProtos []string
	)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ws":
			conn, err := websocket.Accept(writer, request, nil)
			if err != nil {
				return
			}
			originAccess.Lock()
			originProtos = append(originProtos, request.Proto)
			originAccess.Unlock()
			conn.SetReadLimit(webSocketReadLimit)
			for {
				messageType, message, readErr := conn.Read(request.Context())
				if readErr != nil {
					return
				}
				if conn.Write(request.Context(), messageType, message) != nil {
					return
				}
			}
		case "/echo":
			_, _ = io.Copy(writer, request.Body)
		default:
			_, _ = io.WriteString(writer, request.Proto+" "+request.URL.Path+" "+request.Host)
		}
	}))
	origin.EnableHTTP2 = true
	origin.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	origin.StartTLS()
	defer origin.Close()
	originPort := origin.Listener.Addr().(*net.TCPAddr).Port
	originPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}))
	ca := writeMITMTestCA(t)
	proxyPort := freePort(t)
	certificateSection, _ := json.Marshal(map[string]any{"certificate": []string{originPEM}})
	build := func(h2 bool) string {
		return `{
  "log": {"disabled": true},
  "certificate": ` + string(certificateSection) + `,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"},
  "mitm": ` + mitmSectionH2(ca, h2, "example.com:"+strconv.Itoa(originPort)) + `
}`
	}
	ctx, instance := startLiveBox(t, build(true))
	tracker := &mitmStateTracker{}
	instance.Router().AppendTracker(tracker)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certificatePEM))
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	require.NoError(t, err)
	newClient := func() *http.Client {
		transport := &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: "example.com"},
		}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Timeout: 20 * time.Second, Transport: transport}
	}
	target := "https://127.0.0.1:" + strconv.Itoa(originPort)
	// The request names example.com, the SNI of the connection, as an HTTP/2 client would.
	do := func(client *http.Client, method string, path string, body []byte) (*http.Response, []byte) {
		request, requestErr := http.NewRequest(method, target+path, bytes.NewReader(body))
		require.NoError(t, requestErr)
		request.Host = "example.com"
		response, doErr := client.Do(request)
		require.NoError(t, doErr)
		defer response.Body.Close()
		content, readErr := io.ReadAll(response.Body)
		require.NoError(t, readErr)
		return response, content
	}

	// h2 on: the client sees h2 and the MITM certificate; both requests share one session.
	clientA := newClient()
	response, body := do(clientA, http.MethodGet, "/one", nil)
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, "Kiko Box Test CA", response.TLS.PeerCertificates[0].Issuer.CommonName)
	require.Equal(t, "h2", response.TLS.NegotiatedProtocol)
	require.Equal(t, "HTTP/2.0 /one example.com", string(body))
	large := bytes.Repeat([]byte("0123456789abcdef"), 16<<10)
	response, body = do(clientA, http.MethodPost, "/echo", large)
	require.Equal(t, 2, response.ProtoMajor)
	require.True(t, bytes.Equal(large, body))
	states := tracker.snapshot()
	require.Len(t, states, 1)
	require.Equal(t, adapter.MITMStatusDecrypted, states[0].Status())
	require.Equal(t, int64(2), states[0].Requests())

	// h2 off: new connections are HTTP/1.1; the open h2 session is not disturbed.
	result, err := applyLive(t, ctx, build(false))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	response, body = do(clientA, http.MethodGet, "/still-h2", nil)
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, "HTTP/2.0 /still-h2 example.com", string(body))
	require.Len(t, tracker.snapshot(), 1)
	clientB := newClient()
	response, body = do(clientB, http.MethodGet, "/two", nil)
	require.Equal(t, 1, response.ProtoMajor)
	require.Equal(t, "http/1.1", response.TLS.NegotiatedProtocol)
	require.Equal(t, "Kiko Box Test CA", response.TLS.PeerCertificates[0].Issuer.CommonName)
	require.Equal(t, "HTTP/1.1 /two example.com", string(body))

	// Back on: new connections negotiate h2 again.
	result, err = applyLive(t, ctx, build(true))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	response, body = do(newClient(), http.MethodGet, "/three", nil)
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, "HTTP/2.0 /three example.com", string(body))

	// A WebSocket client offers http/1.1 on its own connection, whatever the origin supports.
	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, upgrade, err := websocket.Dial(dialCtx, "wss://127.0.0.1:"+strconv.Itoa(originPort)+"/ws", &websocket.DialOptions{HTTPClient: newClient(), Host: "example.com"})
	require.NoError(t, err)
	defer conn.CloseNow()
	require.Equal(t, http.StatusSwitchingProtocols, upgrade.StatusCode)
	require.NotEqual(t, "h2", upgrade.TLS.NegotiatedProtocol)
	require.NoError(t, conn.Write(dialCtx, websocket.MessageText, []byte("ping")))
	messageType, message, err := conn.Read(dialCtx)
	require.NoError(t, err)
	require.Equal(t, websocket.MessageText, messageType)
	require.Equal(t, "ping", string(message))
	require.NoError(t, conn.Close(websocket.StatusNormalClosure, "bye"))
	originAccess.Lock()
	require.Equal(t, []string{"HTTP/1.1"}, originProtos)
	originAccess.Unlock()

	// The session opened before the reloads is still the only h2 one and still serves.
	response, body = do(clientA, http.MethodGet, "/last", nil)
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, "HTTP/2.0 /last example.com", string(body))
	require.Equal(t, int64(4), tracker.snapshot()[0].Requests())
}
