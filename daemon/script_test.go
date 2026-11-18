package daemon

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type scriptFixture struct {
	manager *script.Manager
	hub     *script.Hub
	store   *script.MemoryStore
	client  mitmapi.ScriptClient
	impl    *scriptServer
	stopped atomic.Bool
}

// newScriptFixture serves the Script service on a loopback listener, as the injected API
// service does.
func newScriptFixture(t *testing.T) *scriptFixture {
	t.Helper()
	f := &scriptFixture{hub: script.NewHub(nil), store: script.NewMemoryStore()}
	f.manager = script.NewManager(script.ManagerOptions{Store: f.store, Logger: f.hub, Notifier: f.hub})
	t.Cleanup(f.manager.Close)
	server := grpc.NewServer(grpc.MaxRecvMsgSize(HTTPReplayMaxMessage))
	f.impl = newScriptServer(ScriptProviderFunc(func() (*script.Manager, *script.Hub) {
		if f.stopped.Load() {
			return nil, nil
		}
		return f.manager, f.hub
	}))
	mitmapi.RegisterScriptServer(server, f.impl)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
		server.Stop()
	})
	f.client = mitmapi.NewScriptClient(conn)
	return f
}

func (f *scriptFixture) apply(t *testing.T, configs ...script.Config) {
	t.Helper()
	require.NoError(t, f.manager.Apply(configs))
}

func headers(pairs ...string) []*mitmapi.ScriptHeader {
	var out []*mitmapi.ScriptHeader
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, &mitmapi.ScriptHeader{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func codeOf(err error) codes.Code { return status.Code(err) }

func TestScriptEvaluateRequestModify(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{
		Type:         "http-request",
		RequiresBody: true,
		Source: `
var h = $request.headers;
h['X-New'] = 'v';
delete h['X-Old'];
h['Accept'] = 'text/html';
console.log('url', $request.url);
console.warn('careful');
$done({url: $request.url + '&x=1', headers: h, body: $request.body.toUpperCase()});`,
		Request: &mitmapi.ScriptRequestMessage{
			Url: "https://example.com/a?b=1", Method: "POST", Body: []byte("hello"), HasBody: true,
			Headers: headers("X-Old", "1", "Accept", "*/*"),
		},
	})
	require.NoError(t, err)
	require.Equal(t, "modify", response.Action, response.Error)
	require.Equal(t, "https://example.com/a?b=1&x=1", response.Url)
	require.True(t, response.HeadersChanged)
	require.True(t, response.BodyChanged)
	require.Equal(t, "HELLO", string(response.Body))
	require.Len(t, response.Logs, 2)
	require.Equal(t, "log", response.Logs[0].Level)
	require.Equal(t, "url https://example.com/a?b=1", response.Logs[0].Message)
	require.Equal(t, "warn", response.Logs[1].Level)
	require.Greater(t, response.DurationUs, int64(0))

	byKey := map[string]*mitmapi.ScriptChange{}
	for _, c := range response.Changes {
		byKey[c.Kind+"/"+c.Name] = c
	}
	require.Equal(t, "set", byKey["url/url"].Op)
	require.Equal(t, "https://example.com/a?b=1", byKey["url/url"].Before)
	require.Equal(t, "remove", byKey["header/X-Old"].Op)
	require.Equal(t, "1", byKey["header/X-Old"].Before)
	require.Equal(t, "add", byKey["header/X-New"].Op)
	require.Equal(t, "set", byKey["header/Accept"].Op)
	require.Equal(t, "*/*", byKey["header/Accept"].Before)
	require.Equal(t, "text/html", byKey["header/Accept"].After)
	require.Equal(t, "5", byKey["body/body"].Before)
	require.Equal(t, "5", byKey["body/body"].After)
}

func TestScriptEvaluateBodyHiddenWithoutRequiresBody(t *testing.T) {
	f := newScriptFixture(t)
	response, err := f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{
		Type:    "http-request",
		Source:  `$done({headers: Object.assign($request.headers, {'X-Body': typeof $request.body})});`,
		Request: &mitmapi.ScriptRequestMessage{Url: "https://e.com/", Method: "POST", Body: []byte("x"), HasBody: true},
	})
	require.NoError(t, err)
	require.Equal(t, "modify", response.Action)
	require.Equal(t, "undefined", response.Headers[len(response.Headers)-1].Value)
}

func TestScriptEvaluateRespondAndAbort(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{
		Type:    "http-request",
		Source:  `$done({response: {status: 418, headers: {'X-Mock': '1'}, body: 'tea'}});`,
		Request: &mitmapi.ScriptRequestMessage{Url: "https://e.com/", Method: "GET"},
	})
	require.NoError(t, err)
	require.Equal(t, "respond", response.Action)
	require.EqualValues(t, 418, response.Response.Status)
	require.Equal(t, "tea", string(response.Response.Body))
	require.Equal(t, "X-Mock", response.Response.Headers[0].Name)
	require.Empty(t, response.Changes)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{
		Type: "http-request", Source: `$done({abort: true});`,
		Request: &mitmapi.ScriptRequestMessage{Url: "https://e.com/", Method: "GET"},
	})
	require.NoError(t, err)
	require.Equal(t, "abort", response.Action)
}

func TestScriptEvaluateResponseStatusAndBody(t *testing.T) {
	f := newScriptFixture(t)
	response, err := f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{
		Type:         "http-response",
		RequiresBody: true,
		Source:       `var b = JSON.parse($response.body); delete b.ads; $done({status: 203, body: JSON.stringify(b)});`,
		Request:      &mitmapi.ScriptRequestMessage{Url: "https://e.com/x", Method: "GET"},
		Response: &mitmapi.ScriptResponseMessage{
			Status: 200, Headers: headers("Content-Type", "application/json"),
			Body: []byte(`{"ads":1,"keep":2}`), HasBody: true,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "modify", response.Action, response.Error)
	require.EqualValues(t, 203, response.Status)
	require.JSONEq(t, `{"keep":2}`, string(response.Body))
	var kinds []string
	for _, c := range response.Changes {
		kinds = append(kinds, c.Kind)
	}
	require.ElementsMatch(t, []string{"status", "body"}, kinds)
}

func TestScriptEvaluateBinaryBody(t *testing.T) {
	f := newScriptFixture(t)
	response, err := f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{
		Type: "http-response", RequiresBody: true, BinaryBody: true,
		Source:   `var u = new Uint8Array($response.body); u[0] = 0xff; $done({body: u});`,
		Request:  &mitmapi.ScriptRequestMessage{Url: "https://e.com/x"},
		Response: &mitmapi.ScriptResponseMessage{Status: 200, Body: []byte{1, 2, 3}, HasBody: true},
	})
	require.NoError(t, err)
	require.Equal(t, "modify", response.Action, response.Error)
	require.Equal(t, []byte{0xff, 2, 3}, response.Body)
}

func TestScriptEvaluateBodyOverMaxSizeIsSkipped(t *testing.T) {
	f := newScriptFixture(t)
	response, err := f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{
		Type: "http-response", RequiresBody: true, MaxSize: 4, Source: `$done({});`,
		Request:  &mitmapi.ScriptRequestMessage{Url: "https://e.com/x"},
		Response: &mitmapi.ScriptResponseMessage{Status: 200, Body: []byte("12345"), HasBody: true},
	})
	require.NoError(t, err)
	require.Equal(t, "skipped", response.Action)
	require.Equal(t, "size", response.Reason)
}

func TestScriptEvaluateGeneric(t *testing.T) {
	f := newScriptFixture(t)
	response, err := f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{
		Type: "generic", Argument: "a=1", Tag: "my-task",
		Source: `$persistentStore.write('x', 'k'); $persistentStore.write('s', '@shared/g');
$notification.post('title', 'sub', 'body', {url: 'https://e.com'});
$done({arg: $argument, name: $script.name, type: $script.type, seen: $persistentStore.read('pre')});`,
		Store: []*mitmapi.ScriptStoreEntry{{Key: "pre", Value: "seeded"}, {Key: "@shared/pre2", Value: "s2"}},
	})
	require.NoError(t, err)
	require.Equal(t, "none", response.Action, response.Error)
	require.JSONEq(t, `{"arg":"a=1","name":"my-task","type":"generic","seen":"seeded"}`, response.Output)
	require.Len(t, response.Notifications, 1)
	require.Equal(t, "title", response.Notifications[0].Title)
	require.Equal(t, "https://e.com", response.Notifications[0].Url)
	require.Equal(t, "my-task", response.Notifications[0].Script)
	var stores []string
	for _, c := range response.Changes {
		require.Equal(t, "store", c.Kind)
		stores = append(stores, c.Op+":"+c.Name)
	}
	require.Equal(t, []string{"set:@shared/g", "set:k"}, stores)
}

func TestScriptEvaluateIsADryRun(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	f.apply(t, script.Config{Tag: "live", Type: script.PhaseGeneric, Source: `$done({});`})
	require.NoError(t, f.store.Set("live", "k", "real"))
	usage := f.store.Usage()

	for range 3 {
		response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{
			Type: "generic", Tag: "live",
			Source: `$persistentStore.write('changed', 'k'); $persistentStore.write('n', 'other'); $notification.post('t'); console.log('hi'); throw new Error('boom');`,
		})
		require.NoError(t, err)
		require.Equal(t, "error", response.Action)
		require.Contains(t, response.Error, "boom")
		require.NotEmpty(t, response.Logs)
	}
	value, _, _ := f.store.Get("live", "k")
	require.Equal(t, "real", value, "the live store is untouched")
	require.Equal(t, usage, f.store.Usage())
	require.Empty(t, f.hub.LogsAfter(0, 0), "dry run logs stay out of the live hub")
	require.Empty(t, f.hub.NotificationsAfter(0, 0))
	status, err := f.client.GetStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, status.Scripts, 1)
	require.Zero(t, status.Scripts[0].Runs, "dry runs are not counted")
	require.Zero(t, status.Scripts[0].Errors)
}

func TestScriptEvaluateErrors(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()

	response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `function (`})
	require.NoError(t, err)
	require.Equal(t, "error", response.Action)
	require.Equal(t, "compile", response.ErrorKind)
	require.NotEmpty(t, response.Error)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "http-request", Pattern: "(", Source: `$done({})`})
	require.NoError(t, err)
	require.Equal(t, "compile", response.ErrorKind)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `$httpClient.get('x')`})
	require.NoError(t, err)
	require.Equal(t, "error", response.Action)
	require.Contains(t, response.Error, "$httpClient is not available")
	require.Empty(t, response.ErrorKind)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `$done(1)`, TimeoutMs: 120000})
	require.NoError(t, err)
	require.Equal(t, "compile", response.ErrorKind, "timeout over the maximum is a settings error")

	for name, request := range map[string]*mitmapi.ScriptEvaluateRequest{
		"huge source":   {Type: "generic", Source: strings.Repeat("a", script.MaxSourceSize+1)},
		"bad type":      {Type: "bogus", Source: "1"},
		"empty type":    {Source: "1"},
		"negative":      {Type: "generic", Source: "1", TimeoutMs: -1},
		"binary":        {Type: "generic", Source: "1", BinaryBody: true},
		"bad tag":       {Type: "generic", Source: "1", Tag: "a b"},
		"huge messages": {Type: "http-request", Source: "1", Request: &mitmapi.ScriptRequestMessage{Body: make([]byte, 8<<20+1)}},
	} {
		_, err := f.client.Evaluate(ctx, request)
		require.Equal(t, codes.InvalidArgument, codeOf(err), name)
	}
	_, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: "1",
		Store: []*mitmapi.ScriptStoreEntry{{Key: "", Value: "x"}}})
	require.Equal(t, codes.InvalidArgument, codeOf(err))
}

func TestScriptEvaluateHostile(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	started := time.Now()
	response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `while (true) {}`, TimeoutMs: 200})
	require.NoError(t, err)
	require.Equal(t, "timeout", response.Action)
	require.Less(t, time.Since(started), 5*time.Second)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `var s = 'a'; while (true) { s = s + s; }`, TimeoutMs: 5000})
	require.NoError(t, err)
	require.Equal(t, "limit", response.Action, response.Error)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `function f() { return f() + 1; } f();`})
	require.NoError(t, err)
	require.Contains(t, []string{"error", "limit"}, response.Action)

	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `setTimeout(function () {}, 100000);`, TimeoutMs: 300})
	require.NoError(t, err)
	require.Equal(t, "timeout", response.Action)

	// The runtime still serves normal runs.
	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `$done({ok: true})`})
	require.NoError(t, err)
	require.JSONEq(t, `{"ok":true}`, response.Output)
}

func TestScriptEvaluateConcurrency(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[string]int{}
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `while (true) {}`, TimeoutMs: 300})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				counts[codeOf(err).String()]++
			default:
				counts[response.Action]++
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 24, counts["timeout"]+counts["skipped"]+counts["ResourceExhausted"], "%v", counts)
	require.Positive(t, counts["timeout"], "%v", counts)
	response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `$done(1)`})
	require.NoError(t, err)
	require.Equal(t, "none", response.Action)
}

func TestScriptEvaluateStateDoesNotLeak(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	first, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `leaked = 1; $done({a: 1})`})
	require.NoError(t, err)
	require.Equal(t, "none", first.Action)
	second, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: `$done({seen: typeof leaked})`})
	require.NoError(t, err)
	require.JSONEq(t, `{"seen":"undefined"}`, second.Output)
}

func TestScriptRun(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	f.apply(t,
		script.Config{Tag: "daily", Type: script.PhaseGeneric, Argument: "cfg", Source: `
var n = parseInt($persistentStore.read('n') || '0', 10) + 1;
$persistentStore.write(String(n), 'n');
console.log('run ' + n + ' ' + $argument);
$notification.post('done', '', 'n=' + n);
$done({n: n});`},
		script.Config{Tag: "req", Type: script.PhaseRequest, Pattern: ".*", Source: `$done({})`},
		script.Config{Tag: "fail", Type: script.PhaseGeneric, Source: `throw new Error('nope')`},
	)

	response, err := f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "daily"})
	require.NoError(t, err)
	require.Equal(t, "none", response.Action, response.Error)
	require.JSONEq(t, `{"n":1}`, response.Output)
	require.Equal(t, "run 1 cfg", response.Logs[0].Message)
	response, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "daily", Argument: "override"})
	require.NoError(t, err)
	require.JSONEq(t, `{"n":2}`, response.Output)
	require.Equal(t, "run 2 override", response.Logs[0].Message)
	value, _, _ := f.store.Get("daily", "n")
	require.Equal(t, "2", value, "Run is a live run")
	require.Len(t, f.hub.NotificationsAfter(0, 0), 2)

	response, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "fail"})
	require.NoError(t, err)
	require.Equal(t, "error", response.Action)
	require.Contains(t, response.Error, "nope")

	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "missing"})
	require.Equal(t, codes.NotFound, codeOf(err))
	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "req"})
	require.Equal(t, codes.FailedPrecondition, codeOf(err))
	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "daily", Argument: strings.Repeat("a", script.MaxArgumentSize+1)})
	require.Equal(t, codes.InvalidArgument, codeOf(err))
}

func TestScriptGetStatus(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	f.apply(t,
		script.Config{Tag: "ok", Type: script.PhaseGeneric, Source: `$done({})`},
		script.Config{Tag: "bad", Type: script.PhaseGeneric, Source: `throw new Error('x')`},
	)
	_, err := f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "ok"})
	require.NoError(t, err)
	for range 3 {
		_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "bad"})
		require.NoError(t, err)
	}
	require.NoError(t, f.store.Set("ok", "k", "12345"))

	list, err := f.client.GetStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, list.Scripts, 2)
	byTag := map[string]*mitmapi.ScriptState{}
	for _, s := range list.Scripts {
		byTag[s.Tag] = s
	}
	require.EqualValues(t, 1, byTag["ok"].Runs)
	require.EqualValues(t, 3, byTag["bad"].Runs)
	require.EqualValues(t, 3, byTag["bad"].Errors)
	require.Contains(t, byTag["bad"].LastError, "x")
	require.False(t, byTag["bad"].Paused)
	require.Equal(t, "generic", byTag["ok"].Type)
	require.Positive(t, byTag["ok"].LastRunMs)
	require.False(t, list.StorePersistent)
	require.EqualValues(t, 1+5+script.StoreEntryOverhead, list.StoreBytes)
	require.EqualValues(t, script.MaxStoreTotal, list.StoreLimit)
}

func TestScriptGetStatusPaused(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	f.apply(t, script.Config{Tag: "bad", Type: script.PhaseGeneric, Source: `throw new Error('x')`})
	for range script.PauseFailures + 2 {
		_, err := f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "bad"})
		require.NoError(t, err)
	}
	list, err := f.client.GetStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.True(t, list.Scripts[0].Paused)
	require.Greater(t, list.Scripts[0].PausedUntil, time.Now().Unix())
}

func recvLog(t *testing.T, stream grpc.ServerStreamingClient[mitmapi.ScriptLogEntry]) *mitmapi.ScriptLogEntry {
	t.Helper()
	ch := make(chan *mitmapi.ScriptLogEntry, 1)
	go func() {
		entry, err := stream.Recv()
		if err != nil {
			ch <- nil
			return
		}
		ch <- entry
	}()
	select {
	case entry := <-ch:
		require.NotNil(t, entry)
		return entry
	case <-time.After(5 * time.Second):
		t.Fatal("no log entry")
		return nil
	}
}

func TestScriptSubscribeLogs(t *testing.T) {
	f := newScriptFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.apply(t,
		script.Config{Tag: "a", Type: script.PhaseGeneric, Source: `console.log('from a'); console.error('bad a'); $done({})`},
		script.Config{Tag: "b", Type: script.PhaseGeneric, Source: `console.info('from b'); $done({})`},
	)
	for _, tag := range []string{"a", "b"} {
		_, err := f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: tag})
		require.NoError(t, err)
	}

	// The recent lines come first, then live ones.
	stream, err := f.client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	first := recvLog(t, stream)
	require.Equal(t, "a", first.Script)
	require.Equal(t, "from a", first.Message)
	require.Equal(t, "log", first.Level)
	require.Equal(t, "generic", first.Phase)
	require.Positive(t, first.TimeMs)
	require.Equal(t, "bad a", recvLog(t, stream).Message)
	third := recvLog(t, stream)
	require.Equal(t, "from b", third.Message)
	require.Equal(t, "info", third.Level)
	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "a"})
	require.NoError(t, err)
	live := recvLog(t, stream)
	require.Equal(t, "from a", live.Message)
	require.Greater(t, live.Seq, third.Seq)

	// Resume after a cursor and filter by tag.
	filtered, err := f.client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{After: first.Seq, Tag: "b"})
	require.NoError(t, err)
	require.Equal(t, "from b", recvLog(t, filtered).Message)
	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "a"})
	require.NoError(t, err)
	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "b"})
	require.NoError(t, err)
	next := recvLog(t, filtered)
	require.Equal(t, "b", next.Script)
	require.Greater(t, next.Seq, live.Seq)
}

func TestScriptSubscribeNotifications(t *testing.T) {
	f := newScriptFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.apply(t, script.Config{Tag: "n", Type: script.PhaseGeneric, Source: `$notification.post('T', 'S', 'B ' + $argument, {url: 'https://x'}); $done({})`})
	_, err := f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "n", Argument: "1"})
	require.NoError(t, err)
	stream, err := f.client.SubscribeNotifications(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	note, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, "n", note.Script)
	require.Equal(t, "T", note.Title)
	require.Equal(t, "S", note.Subtitle)
	require.Equal(t, "B 1", note.Body)
	require.Equal(t, "https://x", note.Url)
	require.Positive(t, note.TimeMs)
	_, err = f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "n", Argument: "2"})
	require.NoError(t, err)
	next, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, "B 2", next.Body)
	require.Greater(t, next.Seq, note.Seq)
}

func TestScriptSubscriberLimit(t *testing.T) {
	f := newScriptFixture(t)
	impl := f.impl
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var streams []grpc.ServerStreamingClient[mitmapi.ScriptLogEntry]
	for range scriptStreamSlots {
		stream, err := f.client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{})
		require.NoError(t, err)
		streams = append(streams, stream)
	}
	require.Eventually(t, func() bool { return len(impl.streams) == scriptStreamSlots }, 5*time.Second, 10*time.Millisecond, "streams registered: %d", len(impl.streams))
	require.Eventually(t, func() bool {
		// The first streams may not have reached the server yet; an accepted extra stream
		// waits for data, so each attempt is bounded.
		attempt, stop := context.WithTimeout(ctx, 300*time.Millisecond)
		defer stop()
		stream, err := f.client.SubscribeLogs(attempt, &mitmapi.ScriptSubscribeRequest{})
		if err != nil {
			return false
		}
		_, err = stream.Recv()
		return codeOf(err) == codes.ResourceExhausted
	}, 10*time.Second, 50*time.Millisecond)
	_ = streams
}

func TestScriptStoreRPCs(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()

	info, err := f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "feed", Key: "k1", Value: "v1"})
	require.NoError(t, err)
	require.EqualValues(t, 4+script.StoreEntryOverhead, info.Bytes)
	require.EqualValues(t, script.MaxStoreTotal, info.Limit)
	require.False(t, info.Persistent)
	_, err = f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "feed", Key: "k2", Value: strings.Repeat("é", 4000)})
	require.NoError(t, err)
	_, err = f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "@shared", Key: "tok", Value: "t"})
	require.NoError(t, err)

	// The UI and a script see the same values.
	f.apply(t, script.Config{Tag: "feed", Type: script.PhaseGeneric, Source: `$done({k1: $persistentStore.read('k1'), tok: $persistentStore.read('@shared/tok')})`})
	run, err := f.client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "feed"})
	require.NoError(t, err)
	require.JSONEq(t, `{"k1":"v1","tok":"t"}`, run.Output)

	got, err := f.client.StoreGet(ctx, &mitmapi.ScriptStoreKey{Namespace: "feed", Key: "k1"})
	require.NoError(t, err)
	require.True(t, got.Found)
	require.Equal(t, "v1", got.Value)
	got, err = f.client.StoreGet(ctx, &mitmapi.ScriptStoreKey{Namespace: "feed", Key: "none"})
	require.NoError(t, err)
	require.False(t, got.Found)

	namespaces, err := f.client.StoreList(ctx, &mitmapi.ScriptStoreListRequest{})
	require.NoError(t, err)
	require.Empty(t, namespaces.Entries)
	require.Len(t, namespaces.Namespaces, 2)
	require.Equal(t, "@shared", namespaces.Namespaces[0].Name)
	require.Equal(t, "feed", namespaces.Namespaces[1].Name)
	require.EqualValues(t, 2, namespaces.Namespaces[1].Entries)

	list, err := f.client.StoreList(ctx, &mitmapi.ScriptStoreListRequest{Namespace: "feed"})
	require.NoError(t, err)
	require.Len(t, list.Entries, 2)
	require.Equal(t, "k1", list.Entries[0].Key)
	require.False(t, list.Entries[0].Truncated)
	require.Equal(t, "k2", list.Entries[1].Key)
	require.True(t, list.Entries[1].Truncated)
	require.EqualValues(t, 8000, list.Entries[1].Size)
	require.LessOrEqual(t, len(list.Entries[1].Value), scriptListValueBytes)
	require.True(t, strings.HasPrefix(strings.Repeat("é", 4000), list.Entries[1].Value), "a character is never split")
	full, err := f.client.StoreGet(ctx, &mitmapi.ScriptStoreKey{Namespace: "feed", Key: "k2"})
	require.NoError(t, err)
	require.Len(t, full.Value, 8000)

	info, err = f.client.StoreDelete(ctx, &mitmapi.ScriptStoreKey{Namespace: "feed", Key: "k2"})
	require.NoError(t, err)
	require.EqualValues(t, 2+2+len("tok")+1+2*script.StoreEntryOverhead, info.Bytes)
	_, err = f.client.StoreDelete(ctx, &mitmapi.ScriptStoreKey{Namespace: "feed", Key: "k2"})
	require.NoError(t, err, "deleting a missing key succeeds")
}

func TestScriptStoreRPCLimits(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	set := func(namespace, key, value string) error {
		_, err := f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: namespace, Key: key, Value: value})
		return err
	}
	require.Equal(t, codes.InvalidArgument, codeOf(set("feed", "", "v")))
	require.Equal(t, codes.InvalidArgument, codeOf(set("feed", strings.Repeat("k", 257), "v")))
	require.NoError(t, set("feed", strings.Repeat("k", 256), "v"))
	require.Equal(t, codes.InvalidArgument, codeOf(set("feed", "big", strings.Repeat("x", script.MaxStoreValue+1))))
	require.NoError(t, set("feed", "max", strings.Repeat("x", script.MaxStoreValue)))
	require.Equal(t, codes.InvalidArgument, codeOf(set("bad namespace", "k", "v")))
	require.Equal(t, codes.InvalidArgument, codeOf(set("", "k", "v")))
	require.Equal(t, codes.InvalidArgument, codeOf(set("feed", "@shared/x", "v")), "script keys with the shared prefix are unreachable")
	require.NoError(t, set("@shared", "@shared/x", "v"))
	_, err := f.client.StoreGet(ctx, &mitmapi.ScriptStoreKey{Namespace: "../x", Key: "k"})
	require.Equal(t, codes.InvalidArgument, codeOf(err))
	_, err = f.client.StoreList(ctx, &mitmapi.ScriptStoreListRequest{Namespace: "a/b"})
	require.Equal(t, codes.InvalidArgument, codeOf(err))

	var full error
	for i := 0; i < 20 && full == nil; i++ {
		full = set("fill", "k"+strings.Repeat("a", i), strings.Repeat("y", script.MaxStoreValue))
	}
	require.Equal(t, codes.ResourceExhausted, codeOf(full))
	list, err := f.client.GetStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.LessOrEqual(t, list.StoreBytes, uint64(script.MaxStoreTotal))
}

func TestScriptServiceRefusesStoppedCoreAndRemotePeers(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	f.stopped.Store(true)
	_, err := f.client.GetStatus(ctx, &emptypb.Empty{})
	require.Equal(t, codes.FailedPrecondition, codeOf(err))
	_, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: "1"})
	require.Equal(t, codes.FailedPrecondition, codeOf(err))
	_, err = f.client.StoreList(ctx, &mitmapi.ScriptStoreListRequest{})
	require.Equal(t, codes.FailedPrecondition, codeOf(err))
	stream, err := f.client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Equal(t, codes.FailedPrecondition, codeOf(err))

	// A peer that is neither loopback, unix socket nor TLS (bufconn reports "bufconn") is
	// refused on every method.
	manager := script.NewManager(script.ManagerOptions{})
	hub := script.NewHub(nil)
	server := grpc.NewServer()
	RegisterScript(server, ScriptProviderFunc(func() (*script.Manager, *script.Hub) { return manager, hub }))
	listener := bufconn.Listen(1 << 20)
	go server.Serve(listener)
	conn, err := grpc.NewClient("passthrough:///remote", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	defer func() {
		conn.Close()
		server.Stop()
	}()
	client := mitmapi.NewScriptClient(conn)
	_, err = client.GetStatus(ctx, &emptypb.Empty{})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	_, err = client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "generic", Source: "1"})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	_, err = client.Run(ctx, &mitmapi.ScriptRunRequest{Tag: "x"})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	_, err = client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "a", Key: "k", Value: "v"})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	_, err = client.StoreGet(ctx, &mitmapi.ScriptStoreKey{Namespace: "a", Key: "k"})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	_, err = client.StoreDelete(ctx, &mitmapi.ScriptStoreKey{Namespace: "a", Key: "k"})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	_, err = client.StoreList(ctx, &mitmapi.ScriptStoreListRequest{})
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	logs, err := client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	_, err = logs.Recv()
	require.Equal(t, codes.PermissionDenied, codeOf(err))
	notes, err := client.SubscribeNotifications(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	_, err = notes.Recv()
	require.Equal(t, codes.PermissionDenied, codeOf(err))
}

func TestRewriteHitsToProtoScriptRun(t *testing.T) {
	hits := rewriteHitsToProto([]flow.RewriteHit{
		{Kind: "url", Rule: "r1", Action: "rewrite"},
		{
			Kind: "script", Rule: "fix", Action: "error", Side: "response", Target: "fix",
			Run: &flow.ScriptRun{
				Phase: "http-response", Duration: 1500 * time.Microsecond, Error: "boom", Reason: "",
				Logs: []flow.ScriptLog{{Level: "warn", Message: "w"}, {Level: "log", Message: "l"}},
			},
		},
		{Kind: "script", Rule: "big", Action: "skipped", Target: "big", Run: &flow.ScriptRun{Phase: "http-request", Reason: "size"}},
	})
	require.Len(t, hits, 3)
	require.Nil(t, hits[0].Run)
	run := hits[1].Run
	require.Equal(t, "fix", run.Tag)
	require.Equal(t, "http-response", run.Phase)
	require.EqualValues(t, 1500, run.DurationUs)
	require.Equal(t, "boom", run.Error)
	require.Len(t, run.Logs, 2)
	require.Equal(t, "warn", run.Logs[0].Level)
	require.Equal(t, "l", run.Logs[1].Message)
	require.Equal(t, "size", hits[2].Run.Reason)
}

// TestScriptServiceOnEngine serves the service from a StartedService whose instance holds a
// real MITM engine: the manager, hub and store are the engine's.
func TestScriptServiceOnEngine(t *testing.T) {
	var output bytes.Buffer
	_, engine := newTestMITMServer(t, &output)
	ctx := service.ContextWith[adapter.MITMEngine](context.Background(), engine)
	started := &StartedService{instance: &Instance{ctx: ctx}}
	manager, hub := started.ScriptRuntime()
	require.NotNil(t, manager)
	require.NotNil(t, hub)
	require.Same(t, engine.(adapter.MITMScriptProvider).Scripts(), manager)
	require.NoError(t, manager.Apply([]script.Config{{Tag: "g", Type: script.PhaseGeneric, Source: `console.info('hello'); $notification.post('t'); $persistentStore.write('1', 'k'); $done({})`}}))

	server := grpc.NewServer()
	RegisterScript(server, started)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() {
		conn.Close()
		server.Stop()
	}()
	client := mitmapi.NewScriptClient(conn)
	rctx := context.Background()
	_, err = client.Run(rctx, &mitmapi.ScriptRunRequest{Tag: "g"})
	require.NoError(t, err)
	require.Len(t, hub.LogsAfter(0, 0), 1)
	require.Len(t, hub.NotificationsAfter(0, 0), 1)
	value, err := client.StoreGet(rctx, &mitmapi.ScriptStoreKey{Namespace: "g", Key: "k"})
	require.NoError(t, err)
	require.Equal(t, "1", value.Value)
	// The engine logger also received the console line.
	require.Contains(t, output.String(), "script g: hello")

	// A stopped service has no runtime.
	stopped := &StartedService{}
	m, h := stopped.ScriptRuntime()
	require.Nil(t, m)
	require.Nil(t, h)
}

// TestScriptStreamsFollowTheHub: after a core reload the runtime has a new hub. Streams on
// the old one end with Unavailable and free their slot; a cursor from the old hub starts over.
func TestScriptStreamsFollowTheHub(t *testing.T) {
	manager := script.NewManager(script.ManagerOptions{})
	hub1, hub2 := script.NewHub(nil), script.NewHub(nil)
	var current atomic.Pointer[script.Hub]
	current.Store(hub1)
	impl := newScriptServer(ScriptProviderFunc(func() (*script.Manager, *script.Hub) { return manager, current.Load() }))
	server := grpc.NewServer()
	mitmapi.RegisterScriptServer(server, impl)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() {
		conn.Close()
		server.Stop()
	}()
	client := mitmapi.NewScriptClient(conn)
	ctx := context.Background()

	logs, err := client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	notes, err := client.SubscribeNotifications(ctx, &mitmapi.ScriptSubscribeRequest{})
	require.NoError(t, err)
	hub1.Log(script.LogEntry{Script: "a", LogLine: script.LogLine{Level: "log", Message: "old"}})
	first, err := logs.Recv()
	require.NoError(t, err)
	require.Equal(t, "old", first.Message)

	current.Store(hub2)
	for _, recv := range []func() error{
		func() error { _, err := logs.Recv(); return err },
		func() error { _, err := notes.Recv(); return err },
	} {
		done := make(chan error, 1)
		go func() { done <- recv() }()
		select {
		case err := <-done:
			require.Equal(t, codes.Unavailable, codeOf(err))
		case <-time.After(2*scriptStaleCheck + 3*time.Second):
			t.Fatal("stream on the old hub never ended")
		}
	}
	require.Eventually(t, func() bool { return len(impl.streams) == 0 }, 3*time.Second, 20*time.Millisecond)

	hub2.Log(script.LogEntry{Script: "b", LogLine: script.LogLine{Level: "log", Message: "new"}})
	fresh, err := client.SubscribeLogs(ctx, &mitmapi.ScriptSubscribeRequest{After: first.Seq + 500})
	require.NoError(t, err)
	got, err := fresh.Recv()
	require.NoError(t, err)
	require.Equal(t, "new", got.Message)
}

func TestScriptStoreSetTooManyEntries(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	for i := range script.MaxStoreNamespaceEntries {
		_, err := f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "many", Key: "k" + strconv.Itoa(i), Value: ""})
		require.NoError(t, err)
	}
	_, err := f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "many", Key: "extra", Value: ""})
	require.Equal(t, codes.ResourceExhausted, codeOf(err))
	_, err = f.client.StoreSet(ctx, &mitmapi.ScriptStoreSetRequest{Namespace: "many", Key: "k1", Value: "overwrite"})
	require.NoError(t, err)
}

func TestScriptStateMessageNextRun(t *testing.T) {
	next := time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC)
	item := scriptStateMessage(script.Status{Tag: "nightly", Type: script.PhaseCron, Cron: "0 3 * * *", NextRun: next, Runs: 2})
	require.Equal(t, "cron", item.Type)
	require.Equal(t, next.UnixMilli(), item.NextRunMs)
	require.EqualValues(t, 2, item.Runs)
	require.Zero(t, scriptStateMessage(script.Status{Tag: "plain", Type: script.PhaseGeneric}).NextRunMs)
}

func TestScriptEvaluateCron(t *testing.T) {
	f := newScriptFixture(t)
	response, err := f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{
		Type: "cron", Tag: "nightly", Source: `$done({type: $script.type, request: typeof $request});`,
	})
	require.NoError(t, err)
	require.Equal(t, "none", response.Action, response.Error)
	require.JSONEq(t, `{"type":"cron","request":"undefined"}`, response.Output)
	_, err = f.client.Evaluate(context.Background(), &mitmapi.ScriptEvaluateRequest{Type: "schedule", Source: `$done({})`})
	require.Equal(t, codes.InvalidArgument, codeOf(err))
	require.Contains(t, status.Convert(err).Message(), "cron")
}

func TestScriptRunCron(t *testing.T) {
	f := newScriptFixture(t)
	f.manager.StartSchedule()
	f.apply(t, script.Config{Tag: "nightly", Type: script.PhaseCron, Cron: "0 3 * * *", Source: `$done({type: $script.type})`})
	response, err := f.client.Run(context.Background(), &mitmapi.ScriptRunRequest{Tag: "nightly"})
	require.NoError(t, err)
	require.Equal(t, "none", response.Action, response.Error)
	require.JSONEq(t, `{"type":"cron"}`, response.Output)
	list, err := f.client.GetStatus(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, list.Scripts, 1)
	require.Equal(t, "cron", list.Scripts[0].Type)
	require.NotZero(t, list.Scripts[0].NextRunMs, "a scheduled script reports its next run")
}

func TestScriptEvaluateRuleAndDNS(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	response, err := f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{
		Type: "rule", Source: "$done($request.domain === 'a.test' && $request.port === 443)",
		Rule: &mitmapi.ScriptRuleInput{Domain: "a.test", Port: 443},
	})
	require.NoError(t, err)
	require.Equal(t, "none", response.Action)
	require.Equal(t, "true", response.Decision)
	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{
		Type: "dns", Source: "$done({addresses: ['1.2.3.4']})", Rule: &mitmapi.ScriptRuleInput{Domain: "a.test", QueryType: "A"},
	})
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", response.Decision)
	response, err = f.client.Evaluate(ctx, &mitmapi.ScriptEvaluateRequest{Type: "rule", Source: "$done('x')"})
	require.NoError(t, err)
	require.NotEmpty(t, response.Error)
}
