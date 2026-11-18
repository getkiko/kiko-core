package box_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/mitm"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	box "github.com/sagernet/sing-box"

	"github.com/stretchr/testify/require"
)

// scriptHTTPConfig has a hosts DNS server that points rebind.test at loopback, a direct
// outbound and a second one ("alt") to force, and the capture manager on.
const scriptHTTPConfig = `{
  "log": {"disabled": true},
  "dns": {"servers": [{"type": "hosts", "tag": "hosts", "predefined": {"rebind.test": "127.0.0.1"}}], "final": "hosts"},
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "alt"}],
  "route": {"final": "direct", "default_domain_resolver": "hosts"},
  "mitm": {"enabled": false, "capture": {"enabled": true, "body": true}}
  SCRIPTS
}`

func scriptHTTPConfigWith(scripts string) string {
	if scripts == "" {
		return strings.Replace(scriptHTTPConfig, "SCRIPTS", "", 1)
	}
	return strings.Replace(scriptHTTPConfig, "SCRIPTS", `, "scripts": `+scripts, 1)
}

type scriptHTTPBox struct {
	ctx     context.Context
	box     *box.Box
	traffic *trafficcontrol.Manager
	engine  adapter.MITMEngine
	manager *script.Manager
	origin  *httptest.Server
	hits    atomic.Int32
	port    int
}

func startScriptHTTPBox(t *testing.T, scripts string, prepare ...func(port int)) *scriptHTTPBox {
	t.Helper()
	f := &scriptHTTPBox{}
	f.origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("X-Origin", "yes")
		_, _ = w.Write([]byte("origin says " + r.Method + " " + r.URL.Path))
	}))
	t.Cleanup(f.origin.Close)
	f.port = f.origin.Listener.Addr().(*net.TCPAddr).Port
	for _, fn := range prepare {
		fn(f.port)
	}
	f.ctx = include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](f.ctx, []byte(scriptHTTPConfigWith(scripts)))
	require.NoError(t, err)
	f.box, err = box.New(box.Options{Context: f.ctx, Options: options})
	require.NoError(t, err)
	f.traffic = trafficcontrol.NewManager()
	f.box.Router().AppendTracker(f.traffic)
	require.NoError(t, f.box.Start())
	t.Cleanup(func() { f.box.Close() })
	f.engine = service.FromContext[adapter.MITMEngine](f.ctx)
	f.manager = f.engine.(adapter.MITMScriptProvider).Scripts()
	return f
}

// client builds the same client box.go attaches to the script manager.
func (f *scriptHTTPBox) client() script.HTTPClient {
	engine := f.engine.(*mitm.Engine)
	return engine.ScriptHTTPClient(f.box.Router(), service.FromContext[adapter.OutboundManager](f.ctx))
}

func (f *scriptHTTPBox) scriptConnections() []*trafficcontrol.TrackerMetadata {
	var out []*trafficcontrol.TrackerMetadata
	for _, list := range [][]*trafficcontrol.TrackerMetadata{f.traffic.Connections(), f.traffic.ClosedConnections()} {
		for _, tracked := range list {
			if tracked.Metadata.Inbound == adapter.InboundKikoScript {
				out = append(out, tracked)
			}
		}
	}
	return out
}

func TestScriptHTTPClientThroughRouter(t *testing.T) {
	f := startScriptHTTPBox(t, "")
	client := f.client()
	mitm.SetScriptHTTPAllowLocal(true)
	t.Cleanup(func() { mitm.SetScriptHTTPAllowLocal(false) })

	response, err := client.Do(context.Background(), &script.HTTPRequest{
		Script: "tagged", Method: "GET", URL: "http://rebind.test:" + strconv.Itoa(f.port) + "/hello",
		Outbound: "alt", Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, 200, response.Status)
	require.Equal(t, "origin says GET /hello", string(response.Body))

	// The request is a tracked connection of the script inbound, on the forced outbound.
	var tracked *trafficcontrol.TrackerMetadata
	require.Eventually(t, func() bool {
		connections := f.scriptConnections()
		if len(connections) == 0 {
			return false
		}
		tracked = connections[0]
		return true
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, adapter.InboundKikoScript, tracked.Metadata.Inbound)
	require.Equal(t, "tagged", tracked.Metadata.User)
	require.True(t, tracked.Metadata.Internal)
	require.Equal(t, "alt", tracked.Outbound)
	require.Equal(t, "rebind.test:"+strconv.Itoa(f.port), tracked.Metadata.Destination.String())

	// And an exchange record of the HTTP tab.
	capturer := f.engine.(adapter.MITMCaptureProvider).Capture()
	var record capture.Record
	require.Eventually(t, func() bool {
		for _, r := range capturer.List(capture.Filter{Limit: 10}).Records {
			if r.Path == "/hello" && r.State != capture.StateInProgress {
				record = r
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, 200, record.Status)
	require.Equal(t, adapter.InboundKikoScript, record.Connection.Inbound)
	require.Equal(t, "tagged", record.Connection.User)
	require.Equal(t, "alt", record.Connection.Outbound)
	require.NotEmpty(t, record.Connection.ID, "the record links the tracked connection")

	_, err = client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: "http://rebind.test:" + strconv.Itoa(f.port) + "/", Outbound: "missing"})
	require.EqualError(t, err, "outbound not found")
}

func TestScriptHTTPClientRefusesLocalTargets(t *testing.T) {
	f := startScriptHTTPBox(t, "")
	client := f.client()
	port := strconv.Itoa(f.port)
	for _, target := range []string{
		"http://127.0.0.1:" + port + "/", "http://localhost:" + port + "/", "http://[::ffff:127.0.0.1]:" + port + "/",
		"http://0.0.0.0:" + port + "/", "http://2130706433:" + port + "/", "http://0x7f.1:" + port + "/", "http://localhost.:" + port + "/",
		"http://example.com@127.0.0.1:" + port + "/",
	} {
		_, err := client.Do(context.Background(), &script.HTTPRequest{Method: "GET", URL: target, Timeout: 3 * time.Second})
		require.Error(t, err, target)
		require.True(t, strings.HasPrefix(err.Error(), "refused:"), "%s: %v", target, err)
	}
	require.Zero(t, f.hits.Load())
	require.Empty(t, f.scriptConnections(), "refused before routing")

	// A name that resolves to loopback passes the name rules, the router refuses the connected
	// address before any byte is sent.
	_, err := client.Do(context.Background(), &script.HTTPRequest{Script: "rebind", Method: "GET", URL: "http://rebind.test:" + port + "/", Timeout: 3 * time.Second})
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "refused:"), err.Error())
	require.Zero(t, f.hits.Load(), "the origin saw nothing")
	require.Eventually(t, func() bool { return len(f.scriptConnections()) == 1 }, 3*time.Second, 10*time.Millisecond)

}

const genericHTTPScript = `
$httpClient.get({url: 'http://127.0.0.1:%PORT%/direct'}, function (err, resp, data) {
  var first = err;
  $httpClient.get({url: 'http://rebind.test:%PORT%/name'}, function (err2) {
    $done({first: first, second: err2});
  });
});`

// The script runtime reaches the same client: a generic script that calls $httpClient at a
// local target gets "refused:", also for a name that resolves to a listening loopback server.
func TestScriptHTTPClientFromGenericScript(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scripts"), 0o755))
	f := startScriptHTTPBox(t, `[{"tag": "g", "type": "generic", "source_path": "scripts/g.js"}]`, func(port int) {
		source := strings.ReplaceAll(genericHTTPScript, "%PORT%", strconv.Itoa(port))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts", "g.js"), []byte(source), 0o644))
	})
	result, err := f.manager.RunGeneric(context.Background(), "g", "")
	require.NoError(t, err)
	require.Equal(t, script.ActionNone, result.Action, result.Error)
	require.Contains(t, result.Output, `"first":"refused:`)
	require.Contains(t, result.Output, `"second":"refused:`)
	require.Zero(t, f.hits.Load(), "the origin on loopback saw no request")
}

// ApplyLiveConfig of the daemon service (the gRPC handler) applies a configuration with a
// script to the running core, and the new script runs.
func TestApplyLiveConfigWithScripts(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts", "live.js"), []byte(`$persistentStore.write('1', 'ran'); $done({ok: true, arg: $argument});`), 0o644))
	f := startScriptHTTPBox(t, "")
	require.Nil(t, f.manager.Current().Lookup("live"))

	svc := daemon.NewStartedService(daemon.ServiceOptions{Context: f.ctx})
	result, err := svc.ApplyLiveConfig(context.Background(), &daemon.LiveConfigRequest{
		ConfigJson: scriptHTTPConfigWith(`[{"tag": "live", "type": "generic", "source_path": "scripts/live.js", "argument": "from-live"}]`),
		Revision:   1,
	})
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.False(t, result.RestartRequired, result.Reason)
	require.NotNil(t, f.manager.Current().Lookup("live"))

	run, err := f.manager.RunGeneric(context.Background(), "live", "")
	require.NoError(t, err)
	require.Equal(t, script.ActionNone, run.Action, run.Error)
	require.JSONEq(t, `{"ok":true,"arg":"from-live"}`, run.Output)

	// Removing the script applies live too.
	result, err = svc.ApplyLiveConfig(context.Background(), &daemon.LiveConfigRequest{ConfigJson: scriptHTTPConfigWith(""), Revision: 2})
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Nil(t, f.manager.Current().Lookup("live"))
}
