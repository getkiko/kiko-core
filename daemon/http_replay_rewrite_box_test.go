package daemon_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/authority"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// Replay is an internal connection: rewrite rules that answer the same URL through the proxy do
// not touch it.
func TestReplayNotRewritten(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream "+r.URL.Path)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port

	certificatePEM, keyPEM, err := authority.Generate("Kiko Replay Test CA", 24*time.Hour)
	require.NoError(t, err)
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ca.pem"), certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ca.key"), keyPEM, 0o600))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	mitm, _ := json.Marshal(map[string]any{
		"enabled":     true,
		"certificate": map[string]any{"source": "file", "certificate_path": filepath.Join(directory, "ca.pem"), "key_path": filepath.Join(directory, "ca.key")},
		"hostnames":   map[string]any{"include": []string{"127.0.0.1:" + strconv.Itoa(port)}},
		"capture":     map[string]any{"enabled": true, "body": true},
		"http_rewrite": map[string]any{"url": []map[string]any{
			{"id": "dict", "pattern": `^https://127\.0\.0\.1:\d+/replay`, "action": "reject-dict"},
		}},
	})
	trusted, _ := json.Marshal(map[string]any{"certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))}})
	config := `{
  "log": {"disabled": true},
  "certificate": ` + string(trusted) + `,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"},
  "mitm": ` + string(mitm) + `
}`
	ctx := include.Context(context.Background())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	traffic := trafficcontrol.NewManager()
	instance.Router().AppendTracker(traffic)
	require.NoError(t, instance.Start())
	defer instance.Close()

	engine := service.FromContext[adapter.MITMEngine](ctx)
	manager := engine.(adapter.MITMCaptureProvider).Capture()
	require.NotNil(t, manager)
	provider := &boxReplayProvider{manager: manager, target: &daemon.HTTPReplayTarget{
		Router:    instance.Router(),
		Outbounds: instance.Outbound(),
		Connection: func(id string) *trafficcontrol.TrackerMetadata {
			parsed, parseErr := uuid.FromString(id)
			if parseErr != nil {
				return nil
			}
			for _, closed := range traffic.ClosedConnections() {
				if closed.ID == parsed {
					return closed
				}
			}
			return nil
		},
	}}
	bufListener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	daemon.RegisterHTTPCapture(grpcServer, provider)
	go grpcServer.Serve(bufListener)
	defer grpcServer.Stop()
	conn, err := grpc.NewClient("passthrough:///box", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return bufListener.Dial() }))
	require.NoError(t, err)
	defer conn.Close()
	client := mitmapi.NewHTTPCaptureClient(conn)
	target := "https://127.0.0.1:" + strconv.Itoa(port)

	// Through the proxy the rule answers.
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	proxied := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := proxied.Get(target + "/replay")
	require.NoError(t, err)
	content, _ := io.ReadAll(response.Body)
	response.Body.Close()
	require.Equal(t, "{}", string(content))
	require.Eventually(t, func() bool { return manager.Stats().Records == 1 && manager.Stats().InProgress == 0 }, 5*time.Second, 10*time.Millisecond)
	require.True(t, manager.List(capture.Filter{Limit: 10}).Records[0].Rewritten)

	// The replay of the same URL reaches the origin and records no rewrite.
	result, err := client.Replay(context.Background(), &mitmapi.ReplayRequest{Method: "GET", Url: target + "/replay"})
	require.NoError(t, err)
	require.Empty(t, result.Error)
	require.Equal(t, int32(200), result.Record.Status)
	require.Empty(t, result.Record.Rewrites)
	body, err := client.GetBody(context.Background(), &mitmapi.GetBodyRequest{Id: result.Record.Id, Side: mitmapi.BodySide_BODY_SIDE_RESPONSE})
	require.NoError(t, err)
	chunk, err := body.Recv()
	require.NoError(t, err)
	require.Equal(t, "upstream /replay", string(chunk.Data))
}
