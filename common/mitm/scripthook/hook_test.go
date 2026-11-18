package scripthook

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/script"

	"github.com/stretchr/testify/require"
)

func newManager(t testing.TB, configs ...script.Config) *script.Manager {
	m := script.NewManager(script.ManagerOptions{})
	t.Cleanup(m.Close)
	require.NoError(t, m.Apply(configs))
	return m
}

func cfg(tag string, phase script.Phase, pattern, source string) script.Config {
	return script.Config{Tag: tag, Type: phase, Pattern: pattern, Source: source}
}

func TestBeginMatching(t *testing.T) {
	m := newManager(t,
		cfg("a", script.PhaseRequest, `^https://a\.test/`, `$done({})`),
		cfg("b", script.PhaseResponse, `^https://b\.test/`, `$done({})`),
	)
	require.Nil(t, Begin(context.Background(), m, nil, "https", "c.test", "/", "GET"))
	require.Nil(t, Begin(context.Background(), nil, nil, "https", "a.test", "/", "GET"))
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	require.True(t, x.HasRequest())
	require.False(t, x.HasResponse())
	x = Begin(context.Background(), m, nil, "https", "b.test", "/x", "GET")
	require.False(t, x.HasRequest())
	require.True(t, x.HasResponse())
	var none *Exchange
	require.False(t, none.HasRequest())
	require.False(t, none.WantsBody(script.PhaseRequest, true))
	require.Zero(t, none.MaxBody(script.PhaseResponse))
}

func TestRequestHeadersAndReserved(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseRequest, `.*`, `
var h = $request.headers;
h['X-New'] = '1';
h['Content-Length'] = '999';
h['Host'] = 'evil.test';
delete h['X-Gone'];
$done({headers: h});`))
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	out := x.RunRequest(&Message{Headers: []flow.Header{
		{Name: "Host", Value: "a.test"}, {Name: "X-Gone", Value: "g"}, {Name: "Content-Length", Value: "3"}, {Name: "Accept", Value: "*/*"},
	}}, "/x")
	require.True(t, out.HeadersChanged)
	require.Equal(t, []flow.Header{
		{Name: "Host", Value: "a.test"}, {Name: "Content-Length", Value: "3"}, {Name: "Accept", Value: "*/*"}, {Name: "X-New", Value: "1"},
	}, out.Headers)
	require.Len(t, out.Hits, 1)
	hit := out.Hits[0]
	require.Equal(t, "script", hit.Kind)
	require.Equal(t, "a", hit.Rule)
	require.Equal(t, "a", hit.Target)
	require.Equal(t, "modify", hit.Action)
	require.Equal(t, "request", hit.Side)
	require.NotNil(t, hit.Run)
}

func TestInvalidHeaderIsError(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseRequest, `.*`, `var h = $request.headers; h['X-Bad'] = 'a\r\nInjected: 1'; $done({headers: h});`))
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	out := x.RunRequest(&Message{Headers: []flow.Header{{Name: "Accept", Value: "*/*"}}}, "/x")
	require.False(t, out.HeadersChanged)
	require.Equal(t, "error", out.Hits[0].Action)
}

func TestBodyScriptSkips(t *testing.T) {
	c := cfg("a", script.PhaseResponse, `.*`, `$done({body: 'x'})`)
	c.RequiresBody = true
	c.MaxSize = 10
	m := newManager(t, c)
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	for _, tc := range []struct {
		name   string
		held   *rewrite.Held
		reason string
	}{
		{"stream", &rewrite.Held{Reason: rewrite.SkipStream}, "stream"},
		{"timeout", &rewrite.Held{Reason: rewrite.SkipTimeout}, "timeout"},
		{"busy", &rewrite.Held{Reason: rewrite.SkipBusy, Complete: true, Data: []byte("abc")}, "busy"},
		{"size", &rewrite.Held{Complete: true, Data: make([]byte, 11)}, "size"},
		{"encoding", &rewrite.Held{Complete: true, Data: []byte("abc")}, "encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Message{Status: 200, Held: tc.held, HasBody: true, Limit: 100}
			if tc.name == "encoding" {
				m.Encoding = "unknown-coding"
			}
			out := x.RunResponse(m)
			require.Len(t, out.Hits, 1)
			require.Equal(t, "skipped", out.Hits[0].Action)
			require.Equal(t, tc.reason, out.Hits[0].Run.Reason)
			require.False(t, out.BodyChanged)
		})
	}
	// Without a body there is nothing to hand over: a body script is skipped, not run.
	out := x.RunResponse(&Message{Status: 200, HasBody: false})
	require.Equal(t, "skipped", out.Hits[0].Action)
	require.Equal(t, "stream", out.Hits[0].Run.Reason)
}

func TestStatusRules(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseResponse, `.*`, `$done({status: 204})`))
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	out := x.RunResponse(&Message{Status: 200, HasBody: true, Held: &rewrite.Held{Complete: true}})
	require.Zero(t, out.Status, "a status without a body would desync the message")
	out = x.RunResponse(&Message{Status: 304})
	require.Equal(t, 204, out.Status, "both statuses carry no body")
	m3 := newManager(t, cfg("a", script.PhaseResponse, `.*`, `$done({status: 404})`))
	out = Begin(context.Background(), m3, nil, "https", "a.test", "/x", "GET").RunResponse(&Message{Status: 304})
	require.Zero(t, out.Status)
	m2 := newManager(t, cfg("a", script.PhaseResponse, `.*`, `$done({status: 404})`))
	x = Begin(context.Background(), m2, nil, "https", "a.test", "/x", "GET")
	out = x.RunResponse(&Message{Status: 200})
	require.Equal(t, 404, out.Status)
}

func TestRespondValidation(t *testing.T) {
	for source, ok := range map[string]bool{
		`$done({response: {status: 200, body: 'x'}})`:                        true,
		`$done({response: {status: 99}})`:                                    false,
		`$done({response: {status: 200, headers: {'X': 'a\nb'}}})`:           false,
		`$done({response: {status: 204, body: 'dropped'}})`:                  true,
		`$done({response: {status: 200, headers: {'Content-Length': '7'}}})`: true,
	} {
		m := newManager(t, cfg("a", script.PhaseRequest, `.*`, source))
		x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
		out := x.RunRequest(&Message{}, "/x")
		if ok {
			require.NotNil(t, out.Local, source)
			require.False(t, out.Local.Abort)
		} else {
			require.Nil(t, out.Local, source)
			require.Equal(t, "error", out.Hits[0].Action, source)
		}
	}
}

func TestURLChangeUsesGuard(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseRequest, `.*`, `$done({url: 'https://elsewhere.test/p'})`))
	rw, err := rewrite.Compile(context.Background(), nil)
	require.NoError(t, err)
	x := Begin(context.Background(), m, rw, "https", "a.test", "/x", "GET")
	out := x.RunRequest(&Message{}, "/x")
	require.NotNil(t, out.Internal)
	require.Equal(t, "elsewhere.test", out.Internal.Host)
	require.Equal(t, "modify", out.Hits[0].Action)
	rw.SetInternalGuard(func(host string, port int) bool { return true })
	x = Begin(context.Background(), m, rw, "https", "a.test", "/x", "GET")
	out = x.RunRequest(&Message{}, "/x")
	require.Nil(t, out.Internal)
	require.Equal(t, "error", out.Hits[0].Action)

	m = newManager(t, cfg("a", script.PhaseRequest, `.*`, `$done({url: 'ftp://x/'})`))
	x = Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	require.Equal(t, "error", x.RunRequest(&Message{}, "/x").Hits[0].Action)
}

func TestChainOrderAndPrecedence(t *testing.T) {
	m := newManager(t,
		cfg("one", script.PhaseRequest, `.*`, `var h = $request.headers; h['X-Order'] = 'one'; $done({headers: h});`),
		cfg("two", script.PhaseRequest, `.*`, `var h = $request.headers; h['X-Order'] = $request.headers['X-Order'] + ',two'; $done({headers: h});`),
		cfg("three", script.PhaseRequest, `.*`, `$done({response: {status: 200, body: $request.headers['X-Order']}})`),
		cfg("four", script.PhaseRequest, `.*`, `throw new Error('never runs')`),
	)
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	out := x.RunRequest(&Message{Headers: []flow.Header{{Name: "Accept", Value: "*/*"}}}, "/x")
	require.NotNil(t, out.Local)
	require.Equal(t, "one,two", string(out.Local.Body))
	require.Len(t, out.Hits, 2, "the answering script's record is Local.Hit")
	require.Equal(t, "respond", out.Local.Hit.Action)
	require.Equal(t, "three", out.Local.Hit.Rule)
}

// TestHookLatency measures a scripted exchange without a body, hook included: matching, the
// run, header conversion and the outcome.
func TestHookLatency(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseRequest, `^https://a\.test/`, `var h = $request.headers; h['X-Bench'] = '1'; $done({headers: h});`))
	headers := []flow.Header{{Name: "Accept", Value: "*/*"}, {Name: "User-Agent", Value: "bench"}, {Name: "Cookie", Value: "a=b"}}
	run := func() {
		x := Begin(context.Background(), m, nil, "https", "a.test", "/x?q=1", "GET")
		if out := x.RunRequest(&Message{Headers: headers}, "/x?q=1"); !out.HeadersChanged {
			t.Fatal("not modified")
		}
	}
	for i := 0; i < 50; i++ {
		run()
	}
	const n = 2000
	samples := make([]time.Duration, n)
	for i := range samples {
		start := time.Now()
		run()
		samples[i] = time.Since(start)
	}
	slices.Sort(samples)
	t.Logf("hook, no body: p50=%s p90=%s p99=%s max=%s", samples[n/2], samples[n*9/10], samples[n*99/100], samples[n-1])
	require.Less(t, samples[n/2], 2*time.Millisecond)
}

func BenchmarkHookNoBody(b *testing.B) {
	m := newManager(b, cfg("a", script.PhaseRequest, `^https://a\.test/`, `var h = $request.headers; h['X-Bench'] = '1'; $done({headers: h});`))
	headers := []flow.Header{{Name: "Accept", Value: "*/*"}, {Name: "User-Agent", Value: "bench"}, {Name: "Cookie", Value: "a=b"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := Begin(context.Background(), m, nil, "https", "a.test", "/x?q=1", "GET")
		x.RunRequest(&Message{Headers: headers}, "/x?q=1")
	}
}

// BenchmarkHookNoMatch is the cost of a request that no script matches (the common case).
func BenchmarkHookNoMatch(b *testing.B) {
	m := newManager(b, cfg("a", script.PhaseRequest, `^https://a\.test/`, `$done({})`))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Begin(context.Background(), m, nil, "https", "other.test", "/x?q=1", "GET")
	}
}

func TestBodylessMessagesDoNotFailBodyScripts(t *testing.T) {
	c := cfg("a", script.PhaseResponse, `.*`, `JSON.parse($response.body); $done({})`)
	c.RequiresBody = true
	m := newManager(t, c)
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	for i := 0; i < 3*script.PauseFailures; i++ {
		out := x.RunResponse(&Message{Status: 304, HasBody: false})
		require.Equal(t, "skipped", out.Hits[0].Action)
	}
	require.False(t, m.Current().Status()[0].Paused)
}

func TestResponseScriptsSeeRequestHeaders(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseResponse, `.*`, `var h = $response.headers; h['X-Saw'] = $request.headers['Authorization'] + '|' + $request.method; $done({headers: h});`))
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "POST")
	x.SetRequestHeaders([]flow.Header{{Name: "Authorization", Value: "t0k"}})
	out := x.RunResponse(&Message{Status: 200, Headers: []flow.Header{{Name: "A", Value: "b"}}})
	require.True(t, out.HeadersChanged)
	require.Equal(t, flow.Header{Name: "X-Saw", Value: "t0k|POST"}, out.Headers[len(out.Headers)-1])
}

func TestContentEncodingIsNotScriptEditable(t *testing.T) {
	m := newManager(t, cfg("a", script.PhaseResponse, `.*`, `var h = $response.headers; h['Content-Encoding'] = 'gzip'; h['X-Ok'] = '1'; $done({headers: h});`))
	x := Begin(context.Background(), m, nil, "https", "a.test", "/x", "GET")
	out := x.RunResponse(&Message{Status: 200, Headers: []flow.Header{{Name: "Content-Type", Value: "text/plain"}}})
	for _, h := range out.Headers {
		require.NotEqual(t, "Content-Encoding", h.Name)
	}
	require.Contains(t, out.Headers, flow.Header{Name: "X-Ok", Value: "1"})
}
