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

// Replay through a real box: the router forces the outbound, the connection is
// tracked under the internal inbound, and the MITM engine leaves it alone
// although the host is on its include list.
func TestReplayThroughBox(t *testing.T) {
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
	})
	trusted, _ := json.Marshal(map[string]any{"certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))}})
	config := `{
  "log": {"disabled": true},
  "certificate": ` + string(trusted) + `,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "alt"}],
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
			if tracker := traffic.Connection(parsed); tracker != nil {
				return tracker.Metadata()
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

	// Control: through the proxy the same host is decrypted and recorded.
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	proxied := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := proxied.Get(target + "/control")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.Equal(t, "Kiko Replay Test CA", response.TLS.PeerCertificates[0].Issuer.CommonName)
	require.Eventually(t, func() bool { return manager.Stats().Records == 1 && manager.Stats().InProgress == 0 }, 5*time.Second, 10*time.Millisecond)

	// A decrypted connection reports its setup on the first exchange.
	controlRecords := manager.List(capture.Filter{Limit: 10}).Records
	require.Len(t, controlRecords, 1)
	require.Greater(t, int64(controlRecords[0].Timing.TLS), int64(0))
	require.Greater(t, int64(controlRecords[0].Timing.Connect), int64(0))

	for _, forced := range []string{"alt", ""} {
		before := manager.Stats().Records
		result, err := client.Replay(context.Background(), &mitmapi.ReplayRequest{Method: "GET", Url: target + "/replay", Outbound: forced})
		require.NoError(t, err)
		require.Empty(t, result.Error)
		record := result.Record
		require.Equal(t, int32(200), record.Status)
		require.Equal(t, "h2", record.Proto)
		require.Equal(t, "kiko-internal", record.Connection.Inbound)
		require.NotEmpty(t, record.ConnectionId)
		wantOutbound := forced
		if wantOutbound == "" {
			wantOutbound = "direct"
		}
		require.Equal(t, wantOutbound, record.Connection.Outbound)
		require.True(t, record.Unverified)
		require.Greater(t, record.Timing.Connect, int64(0))
		require.Greater(t, record.Timing.Tls, int64(0))
		// The sniff rule accepts the first write before the dial; the dial is
		// still charged to connect and the TLS phase excludes it.
		require.Greater(t, record.Timing.Connect, int64(0))
		require.Less(t, record.Timing.Tls, int64(5*time.Second))
		body, err := client.GetBody(context.Background(), &mitmapi.GetBodyRequest{Id: record.Id, Side: mitmapi.BodySide_BODY_SIDE_RESPONSE})
		require.NoError(t, err)
		chunk, err := body.Recv()
		require.NoError(t, err)
		require.Equal(t, "upstream /replay", string(chunk.Data))

		// One record: the engine did not decrypt and capture the replay again.
		time.Sleep(100 * time.Millisecond)
		require.Equal(t, before+1, manager.Stats().Records)

		parsed, err := uuid.FromString(record.ConnectionId)
		require.NoError(t, err)
		var tracked *trafficcontrol.TrackerMetadata
		require.Eventually(t, func() bool {
			for _, closed := range traffic.ClosedConnections() {
				if closed.ID == parsed {
					tracked = closed
					return true
				}
			}
			return false
		}, 5*time.Second, 10*time.Millisecond)
		require.Equal(t, adapter.InboundKikoInternal, tracked.Metadata.Inbound)
		require.Equal(t, wantOutbound, tracked.Outbound)
		require.Equal(t, adapter.MITMStatusSkipped, tracked.Metadata.MITM.Status())
		require.Equal(t, "replay", tracked.Metadata.MITM.Reason())
	}

	missing, err := client.Replay(context.Background(), &mitmapi.ReplayRequest{Method: "GET", Url: target, Outbound: "nope"})
	require.Error(t, err)
	require.Nil(t, missing)
}

type boxReplayProvider struct {
	manager *capture.Manager
	target  *daemon.HTTPReplayTarget
}

func (p *boxReplayProvider) HTTPCapture() *capture.Manager        { return p.manager }
func (p *boxReplayProvider) HTTPReplay() *daemon.HTTPReplayTarget { return p.target }
