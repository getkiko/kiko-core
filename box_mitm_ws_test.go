package box_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

const webSocketReadLimit = 4 << 20

// A WebSocket session through mixed CONNECT → sniff → direct → decryption: the server sends
// first right after the 101, text and binary messages (one over 1 MiB) echo, a ping is
// answered, and the close handshake completes on both sides.
func TestMITMWebSocketEcho(t *testing.T) {
	serverDone := make(chan error, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			serverDone <- err
			return
		}
		conn.SetReadLimit(webSocketReadLimit)
		ctx := request.Context()
		if err = conn.Write(ctx, websocket.MessageText, []byte("hello from server")); err != nil {
			serverDone <- err
			return
		}
		for {
			messageType, message, readErr := conn.Read(ctx)
			if readErr != nil {
				if websocket.CloseStatus(readErr) == websocket.StatusNormalClosure {
					readErr = nil
				}
				serverDone <- readErr
				return
			}
			if err = conn.Write(ctx, messageType, message); err != nil {
				serverDone <- err
				return
			}
		}
	}))
	defer upstream.Close()
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
	upstreamPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))
	ca := writeMITMTestCA(t)
	proxyPort := freePort(t)
	certificateSection, _ := json.Marshal(map[string]any{"certificate": []string{upstreamPEM}})
	ctx, _ := startLiveBox(t, `{
  "log": {"disabled": true},
  "certificate": `+string(certificateSection)+`,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(proxyPort)+`}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"},
  "mitm": `+mitmSection(ca, true, "example.com:"+strconv.Itoa(upstreamPort))+`
}`)

	// The client trusts only the test CA: the session works only when decrypted.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certificatePEM))
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
	}}
	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(dialCtx, "wss://127.0.0.1:"+strconv.Itoa(upstreamPort)+"/ws", &websocket.DialOptions{HTTPClient: client})
	require.NoError(t, err)
	defer conn.CloseNow()
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	conn.SetReadLimit(webSocketReadLimit)

	messageType, message, err := conn.Read(dialCtx)
	require.NoError(t, err)
	require.Equal(t, websocket.MessageText, messageType)
	require.Equal(t, "hello from server", string(message))

	large := make([]byte, 1<<20+12345)
	_, _ = rand.Read(large)
	for _, sent := range []struct {
		messageType websocket.MessageType
		content     []byte
	}{
		{websocket.MessageText, []byte("text message")},
		{websocket.MessageBinary, []byte{0, 1, 2, 0xff}},
		{websocket.MessageBinary, large},
		{websocket.MessageText, bytes.Repeat([]byte("a"), 70000)},
	} {
		require.NoError(t, conn.Write(dialCtx, sent.messageType, sent.content))
		messageType, message, err = conn.Read(dialCtx)
		require.NoError(t, err)
		require.Equal(t, sent.messageType, messageType)
		require.True(t, bytes.Equal(sent.content, message), "echo of %d bytes differs", len(sent.content))
	}

	// A ping completes once a read processes the pong: keep echoing until it does.
	pinged := make(chan error, 1)
	go func() { pinged <- conn.Ping(dialCtx) }()
	for done := false; !done; {
		require.NoError(t, conn.Write(dialCtx, websocket.MessageText, []byte("during ping")))
		_, message, err = conn.Read(dialCtx)
		require.NoError(t, err)
		require.Equal(t, "during ping", string(message))
		select {
		case err = <-pinged:
			require.NoError(t, err)
			done = true
		case <-time.After(10 * time.Millisecond):
		}
	}

	require.NoError(t, conn.Close(websocket.StatusNormalClosure, "bye"))
	select {
	case err = <-serverDone:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not see the close")
	}
	engine := service.FromContext[adapter.MITMEngine](ctx)
	require.Equal(t, 1, engine.Status().LeafCacheSize)
}
