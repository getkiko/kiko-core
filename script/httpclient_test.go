package script

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHTTP is a scripted HTTPClient.
type fakeHTTP struct {
	mu          sync.Mutex
	reqs        []*HTTPRequest
	inflight    int
	maxInflight int
	canceled    atomic.Int32
	handler     func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error)
}

func (f *fakeHTTP) Do(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.inflight++
	f.maxInflight = max(f.maxInflight, f.inflight)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()
	if f.handler == nil {
		return &HTTPResponse{Status: 200, Body: []byte("ok")}, nil
	}
	resp, err := f.handler(ctx, req)
	if ctx.Err() != nil {
		f.canceled.Add(1)
	}
	return resp, err
}

func (f *fakeHTTP) requests() []*HTTPRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*HTTPRequest(nil), f.reqs...)
}

// block waits for the context, like a real request that never gets an answer.
func block(ctx context.Context, _ *HTTPRequest) (*HTTPResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func httpManager(t testing.TB, f *fakeHTTP) *Manager {
	t.Helper()
	m := newTestManager(t)
	if f != nil {
		m.SetHTTPClient(f)
	}
	return m
}

func genericCfg(tag, src string, timeout time.Duration) Config {
	return Config{Tag: tag, Type: PhaseGeneric, Source: src, Timeout: timeout}
}

func runGen(t testing.TB, m *Manager, src string, timeout time.Duration) *Result {
	t.Helper()
	var res *Result
	done := make(chan struct{})
	go func() { defer close(done); res = runOne(t, m, genericCfg("g", src, timeout), nil) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("script did not finish")
	}
	return res
}

func outMap(t testing.TB, res *Result) map[string]any {
	t.Helper()
	if res.Action != ActionNone {
		t.Fatalf("action %s: %s (%+v)", res.Action, res.Error, res)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("output %q: %v", res.Output, err)
	}
	return out
}

func waitGoroutines(t testing.TB, base int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= base+1 {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines: %d, started with %d\n%s", n, base, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHTTPClientUnavailable(t *testing.T) {
	m := newTestManager(t)
	res := runGen(t, m, `$httpClient.get('https://x.example/', function (err, resp, data) { $done({err: err, resp: typeof resp, data: typeof data}) })`, 0)
	out := outMap(t, res)
	if out["err"] != "$httpClient is not available" || out["resp"] != "undefined" || out["data"] != "undefined" {
		t.Fatalf("%v", out)
	}
	// Without a callback there is nothing to answer through.
	res = runGen(t, m, `$httpClient.get('https://x.example/')`, 0)
	if res.Action != ActionError || !strings.Contains(res.Error, "$httpClient is not available") {
		t.Fatalf("%+v", res)
	}
	// The same through an http script: the callback runs, nothing throws.
	res = runOne(t, m, httpConfig("a", PhaseRequest, `$httpClient.get('https://x.example/', function (err) { $done({url: 'https://e/' + (err ? 'err' : 'ok')}) })`), reqInput("https://e/"))
	if res.Action != ActionModify || res.URL != "https://e/err" {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPClientSuccess(t *testing.T) {
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 201, Headers: []Header{{"Content-Type", "text/plain"}, {"Set-Cookie", "a=1"}, {"set-cookie", "b=2"}}, Body: []byte("héllo")}, nil
	}}
	m := httpManager(t, f)
	res := runGen(t, m, `
$httpClient.post({url: 'https://a.example/p?q=1', headers: {'X-A': 'b', 'X-N': 5, 'X-L': ['1', '2']}, body: 'payload'}, function (err, resp, data) {
  $done({err: err, status: resp.status, code: resp.statusCode, ct: resp.headers['Content-Type'], cookie: resp.headers['Set-Cookie'], data: data, type: typeof data});
});`, 0)
	out := outMap(t, res)
	if out["err"] != nil || out["status"] != 201.0 || out["code"] != 201.0 || out["ct"] != "text/plain" || out["cookie"] != "a=1, b=2" || out["data"] != "héllo" || out["type"] != "string" {
		t.Fatalf("%v", out)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	r := reqs[0]
	if r.Method != "POST" || r.URL != "https://a.example/p?q=1" || string(r.Body) != "payload" || r.Script != "g" || r.Phase != PhaseGeneric {
		t.Fatalf("%+v", r)
	}
	if r.Timeout != DefaultHTTPTimeout || r.MaxResponse != MaxHTTPResponse || r.Insecure || r.NoRedirect || r.Outbound != "" {
		t.Fatalf("%+v", r)
	}
	if got := headerValue(r.Headers, "X-L"); got != "1|2" {
		t.Fatalf("headers %+v", r.Headers)
	}
	if got := headerValue(r.Headers, "X-N"); got != "5" {
		t.Fatalf("headers %+v", r.Headers)
	}
}

func TestHTTPClientMethods(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `
var n = 0;
['get', 'post', 'put', 'delete', 'head', 'options', 'patch'].forEach(function (name) {
  $httpClient[name]('https://a.example/' + name, function (err) { if (++n === 7) $done({n: n}); });
});`, 0)
	outMap(t, res)
	got := map[string]string{}
	for _, r := range f.requests() {
		got[r.URL] = r.Method
	}
	for name, method := range map[string]string{"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "head": "HEAD", "options": "OPTIONS", "patch": "PATCH"} {
		if got["https://a.example/"+name] != method {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestHTTPClientError(t *testing.T) {
	f := &fakeHTTP{handler: func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return nil, errors.New("refused: loopback address")
	}}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get('http://127.0.0.1/', function (err, resp, data) { $done({err: err, resp: typeof resp}) })`, 0)
	out := outMap(t, res)
	if out["err"] != "refused: loopback address" || out["resp"] != "undefined" {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientBinaryMode(t *testing.T) {
	f := &fakeHTTP{handler: func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: []byte{0, 1, 2, 255, 128}}, nil
	}}
	m := httpManager(t, f)
	res := runGen(t, m, `
$httpClient.get({url: 'https://a.example/', 'binary-mode': true}, function (err, resp, data) {
  $done({bin: data instanceof Uint8Array, len: data.length, last: data[3], sum: Array.prototype.reduce.call(data, function (a, b) { return a + b; }, 0)});
});`, 0)
	out := outMap(t, res)
	if out["bin"] != true || out["len"] != 5.0 || out["last"] != 255.0 || out["sum"] != 386.0 {
		t.Fatalf("%v", out)
	}
	// An empty body in binary mode is an empty Uint8Array.
	f.handler = func(context.Context, *HTTPRequest) (*HTTPResponse, error) { return &HTTPResponse{Status: 204}, nil }
	res = runGen(t, m, `$httpClient.head({url: 'https://a.example/', 'binary-mode': true}, function (err, resp, data) { $done({bin: data instanceof Uint8Array, len: data.length}) })`, 0)
	if out := outMap(t, res); out["bin"] != true || out["len"] != 0.0 {
		t.Fatalf("%v", out)
	}
	res = runGen(t, m, `$httpClient.head('https://a.example/', function (err, resp, data) { $done({t: typeof data, len: data.length}) })`, 0)
	if out := outMap(t, res); out["t"] != "string" || out["len"] != 0.0 {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientRequestOptions(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `
var left = 4;
function done() { if (--left === 0) $done({}); }
$httpClient.get({url: 'https://a.example/1', node: 'proxy-a', insecure: true, 'auto-redirect': false, timeout: 3.5}, done);
$httpClient.get({url: 'https://a.example/2', policy: 'proxy-b', timeout: 1000}, done);
$httpClient.post({url: 'https://a.example/3', 'body-base64': 'aGVsbG8='}, done);
$httpClient.post({url: 'https://a.example/4', body: new Uint8Array([1, 2, 3])}, done);
`, 0)
	outMap(t, res)
	by := map[string]*HTTPRequest{}
	for _, r := range f.requests() {
		by[r.URL] = r
	}
	if r := by["https://a.example/1"]; r == nil || r.Outbound != "proxy-a" || !r.Insecure || !r.NoRedirect || r.Timeout != 3500*time.Millisecond {
		t.Fatalf("%+v", r)
	}
	if r := by["https://a.example/2"]; r == nil || r.Outbound != "proxy-b" || r.Timeout < 59*time.Second || r.Timeout > MaxHTTPTimeout || r.Insecure || r.NoRedirect {
		t.Fatalf("%+v", r)
	}
	if r := by["https://a.example/3"]; r == nil || string(r.Body) != "hello" {
		t.Fatalf("%+v", r)
	}
	if r := by["https://a.example/4"]; r == nil || !bytes.Equal(r.Body, []byte{1, 2, 3}) {
		t.Fatalf("%+v", r)
	}
}

func TestHTTPClientTimeoutClampedToScript(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get({url: 'https://a.example/', timeout: 50}, function () { $done({}) })`, 2*time.Second)
	outMap(t, res)
	if r := f.requests()[0]; r.Timeout > 2*time.Second || r.Timeout < time.Second {
		t.Fatalf("timeout %s", r.Timeout)
	}
}

func TestHTTPClientValidation(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	cases := map[string]string{
		"no url":      `{}`,
		"number":      `5`,
		"ftp":         `'ftp://a.example/'`,
		"file":        `'file:///etc/passwd'`,
		"relative":    `'/x'`,
		"no host":     `'http:///x'`,
		"credentials": `'https://user:pw@a.example/'`,
		"user only":   `'https://user@a.example/'`,
		"long url":    `'https://a.example/' + 'x'.repeat(9000)`,
		"space":       `'https://a.example/a b\u0000'`,
		"header name": `{url: 'https://a.example/', headers: {'Bad Name': '1'}}`,
		"header crlf": `{url: 'https://a.example/', headers: {'X': 'a\r\nB: c'}}`,
		"headers arr": `{url: 'https://a.example/', headers: ['a']}`,
		"big body":    `{url: 'https://a.example/', body: 'x'.repeat(8 * 1024 * 1024 + 1)}`,
		"both bodies": `{url: 'https://a.example/', body: 'a', 'body-base64': 'YQ=='}`,
		"bad base64":  `{url: 'https://a.example/', 'body-base64': '***'}`,
		"obj body":    `{url: 'https://a.example/', body: {a: 1}}`,
		"bad node":    `{url: 'https://a.example/', node: {}}`,
	}
	for name, opts := range cases {
		res := runGen(t, m, `$httpClient.post(`+opts+`, function (err) { $done({err: err}) })`, 0)
		out := outMap(t, res)
		if s, _ := out["err"].(string); s == "" {
			t.Errorf("%s: accepted (%v)", name, out)
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d invalid requests reached the host", n)
	}
	// A callback is required.
	res := runGen(t, m, `$httpClient.get('https://a.example/')`, 0)
	if res.Action != ActionError || !strings.Contains(res.Error, "callback") {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPClientHeaderFiltering(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get({url: 'https://a.example/', headers: {'Connection': 'close', 'Keep-Alive': '1', 'Proxy-Authorization': 'x', 'Proxy-Foo': 'y', 'TE': 'x', 'Trailer': 'x', 'Transfer-Encoding': 'chunked', 'Upgrade': 'x', 'Content-Length': '99', 'host': 'h.example', 'User-Agent': 'ua'}}, function () { $done({}) })`, 0)
	outMap(t, res)
	got := f.requests()[0].Headers
	if len(got) != 2 || headerValue(got, "host") != "h.example" || headerValue(got, "User-Agent") != "ua" {
		t.Fatalf("%+v", got)
	}
}

func TestHTTPClientRequestLimit(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `
var errs = [], n = 0;
for (var i = 0; i < 17; i++) {
  $httpClient.get('https://a.example/' + i, function (err) { errs.push(err); if (++n === 17) $done({errs: errs}); });
}`, 0)
	out := outMap(t, res)
	errs := out["errs"].([]any)
	nils, tooMany := 0, 0
	for _, e := range errs {
		switch e {
		case nil:
			nils++
		case "too many requests":
			tooMany++
		}
	}
	if nils != MaxHTTPRequests || tooMany != 1 || len(f.requests()) != MaxHTTPRequests {
		t.Fatalf("%v (%d requests)", errs, len(f.requests()))
	}
	// The error is delivered through the loop, after the script body returned.
	res = runGen(t, m, `var order = []; for (var i = 0; i < 17; i++) $httpClient.get('https://a.example/', function (err) { if (err) { order.push('err'); } }); order.push('end'); setTimeout(function () { $done({order: order}) }, 200)`, 0)
	if order := outMap(t, res)["order"].([]any); order[0] != "end" {
		t.Fatalf("%v", order)
	}
}

func TestHTTPClientHostileCallCount(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `for (var i = 0; i < 100000; i++) $httpClient.get('https://a.example/', function () {})`, 0)
	if res.Action != ActionError || !strings.Contains(res.Error, "too many requests") {
		t.Fatalf("%+v", res)
	}
	if n := len(f.requests()); n > MaxHTTPRequests {
		t.Fatalf("%d requests", n)
	}
	// Refused calls (bad URL) count against the same bound.
	res = runGen(t, m, `for (var i = 0; i < 100000; i++) $httpClient.get('nope', function () {})`, 0)
	if res.Action != ActionError || !strings.Contains(res.Error, "too many requests") {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPClientInflightCap(t *testing.T) {
	var started atomic.Int32
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		started.Add(1)
		time.Sleep(40 * time.Millisecond)
		return &HTTPResponse{Status: 200, Body: []byte(req.URL)}, nil
	}}
	m := httpManager(t, f)
	res := runGen(t, m, `
var n = 0, bodies = [];
for (var i = 0; i < 12; i++) {
  $httpClient.get('https://a.example/' + i, function (err, resp, data) { bodies.push(data); if (++n === 12) $done({bodies: bodies}); });
}`, 0)
	out := outMap(t, res)
	if len(out["bodies"].([]any)) != 12 {
		t.Fatalf("%v", out)
	}
	if f.maxInflight != MaxHTTPInflight {
		t.Fatalf("max in flight %d, want %d", f.maxInflight, MaxHTTPInflight)
	}
}

func TestHTTPClientChainAndNestedRequests(t *testing.T) {
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: []byte(req.URL)}, nil
	}}
	m := httpManager(t, f)
	res := runGen(t, m, `
var seen = [];
function next(i) {
  if (i === 5) return $done({seen: seen});
  $httpClient.get('https://a.example/' + i, function (err, resp, data) { seen.push(data); next(i + 1); });
}
next(0);`, 0)
	out := outMap(t, res)
	if len(out["seen"].([]any)) != 5 {
		t.Fatalf("%v", out)
	}
	// A callback that keeps starting requests runs into the per-call limit and is told so.
	res = runGen(t, m, `
var started = 0;
function again(err) { if (err) return $done({err: err, started: started}); started++; $httpClient.get('https://a.example/', again); }
again(null);`, 0)
	out = outMap(t, res)
	if out["err"] != "too many requests" || out["started"] != float64(MaxHTTPRequests+1) {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientDoneInCallbackCancelsRest(t *testing.T) {
	base := runtime.NumGoroutine()
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		if strings.HasSuffix(req.URL, "/slow") {
			return block(ctx, req)
		}
		return &HTTPResponse{Status: 200}, nil
	}}
	m := httpManager(t, f)
	start := time.Now()
	res := runGen(t, m, `
$httpClient.get('https://a.example/slow', function () { console.log('late'); });
$httpClient.get('https://a.example/slow', function () { console.log('late'); });
$httpClient.get('https://a.example/fast', function () { $done({ok: true}); });`, 0)
	if out := outMap(t, res); out["ok"] != true {
		t.Fatalf("%v", out)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not stop at $done")
	}
	for _, l := range res.Logs {
		if strings.Contains(l.Message, "late") {
			t.Fatalf("callback ran after $done: %+v", res.Logs)
		}
	}
	waitFor(t, func() bool { return f.canceled.Load() == 2 })
	waitGoroutines(t, base)
}

func waitFor(t testing.TB, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHTTPClientLateCompletionAfterDone(t *testing.T) {
	base := runtime.NumGoroutine()
	release := make(chan struct{})
	finished := make(chan struct{})
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		// A host that ignores the context and answers after the call ended.
		<-release
		close(finished)
		return &HTTPResponse{Status: 200, Body: []byte("late")}, nil
	}}
	logger := &testLogger{}
	m := httpManager(t, f)
	m.SetLogger(logger)
	res := runGen(t, m, `
$httpClient.get('https://a.example/', function (err, resp, data) { console.log('callback ' + data); $done({late: true}); });
setTimeout(function () { $done({early: true}) }, 20);`, 0)
	if out := outMap(t, res); out["early"] != true {
		t.Fatalf("%v", out)
	}
	close(release)
	<-finished
	waitGoroutines(t, base)
	logger.mu.Lock()
	defer logger.mu.Unlock()
	for _, e := range logger.entries {
		if strings.Contains(e.Message, "callback") {
			t.Fatalf("callback delivered after the call: %+v", e)
		}
	}
	// The pooled VM carries nothing over: the next call sees a clean state.
	res = runGen(t, m, `$done({clean: typeof $httpClient.get === 'function'})`, 0)
	if outMap(t, res)["clean"] != true {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPClientAfterDone(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `$done({a: 1}); $httpClient.get('https://a.example/', function () {});`, 0)
	outMap(t, res)
	time.Sleep(50 * time.Millisecond)
	if n := len(f.requests()); n != 0 {
		t.Fatalf("%d requests after $done", n)
	}
	// Also from a callback after $done: the second request is not made.
	res = runGen(t, m, `$httpClient.get('https://a.example/1', function () { $done({}); $httpClient.get('https://a.example/2', function () {}); })`, 0)
	outMap(t, res)
	time.Sleep(50 * time.Millisecond)
	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

func TestHTTPClientScriptTimeoutWhileWaiting(t *testing.T) {
	base := runtime.NumGoroutine()
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		// Slow to notice the cancellation, so the script's own deadline is what ends the call.
		resp, err := block(ctx, req)
		time.Sleep(150 * time.Millisecond)
		return resp, err
	}}
	m := httpManager(t, f)
	start := time.Now()
	res := runGen(t, m, `$httpClient.get({url: 'https://a.example/', timeout: 30}, function () { $done({}) })`, 300*time.Millisecond)
	if res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %s", d)
	}
	waitFor(t, func() bool { return f.canceled.Load() == 1 })
	waitGoroutines(t, base)
}

func TestHTTPClientRequestTimeout(t *testing.T) {
	f := &fakeHTTP{handler: block}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get({url: 'https://a.example/', timeout: 0.1}, function (err) { $done({err: err}) })`, 0)
	if out := outMap(t, res); out["err"] != "timeout" {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientCancelOfCall(t *testing.T) {
	base := runtime.NumGoroutine()
	f := &fakeHTTP{handler: block}
	m := httpManager(t, f)
	if err := m.Apply([]Config{genericCfg("g", `$httpClient.get('https://a.example/', function () { $done({}) })`, 0)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, err := m.RunGeneric(ctx, "g", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionSkipped || res.Reason != ReasonCanceled {
		t.Fatalf("%+v", res)
	}
	waitFor(t, func() bool { return f.canceled.Load() == 1 })
	waitGoroutines(t, base)
}

func TestHTTPClientCallbackThrows(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get('https://a.example/', function () { throw new Error('boom') })`, 0)
	if res.Action != ActionError || !strings.Contains(res.Error, "boom") {
		t.Fatalf("%+v", res)
	}
	// A throwing timer behaves the same.
	res = runGen(t, m, `setTimeout(function () { throw new Error('boom2') }, 1)`, 0)
	if res.Action != ActionError || !strings.Contains(res.Error, "boom2") {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPClientReleasesSlotWhileWaiting(t *testing.T) {
	release := make(chan struct{})
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		if strings.HasSuffix(req.URL, "/hold") {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return &HTTPResponse{Status: 200}, nil
	}}
	m := NewManager(ManagerOptions{Slots: 1})
	t.Cleanup(m.Close)
	m.SetHTTPClient(f)
	if err := m.Apply([]Config{
		genericCfg("wait", `$httpClient.get('https://a.example/hold', function () { $done({}) })`, 0),
		genericCfg("quick", `$done({q: 1})`, 0),
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Result, 1)
	go func() {
		res, _ := m.RunGeneric(context.Background(), "wait", "")
		done <- res
	}()
	waitFor(t, func() bool { return len(f.requests()) == 1 })
	start := time.Now()
	res, err := m.RunGeneric(context.Background(), "quick", "")
	if err != nil || res.Action != ActionNone || time.Since(start) > time.Second {
		t.Fatalf("%+v %v after %s", res, err, time.Since(start))
	}
	close(release)
	if res := <-done; res.Action != ActionNone {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPClientManagerCap(t *testing.T) {
	old := httpSlotWait
	httpSlotWait = 150 * time.Millisecond
	t.Cleanup(func() { httpSlotWait = old })
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		select {
		case <-time.After(600 * time.Millisecond):
		case <-ctx.Done():
		}
		return &HTTPResponse{Status: 200}, nil
	}}
	m := httpManager(t, f)
	m.httpSlots = make(chan struct{}, 2)
	res := runGen(t, m, `
var errs = [], n = 0;
for (var i = 0; i < 4; i++) $httpClient.get('https://a.example/' + i, function (err) { errs.push(err); if (++n === 4) $done({errs: errs}); });`, 0)
	out := outMap(t, res)
	failed := 0
	for _, e := range out["errs"].([]any) {
		if e == "too many concurrent requests" {
			failed++
		}
	}
	if failed != 2 || f.maxInflight > 2 {
		t.Fatalf("%v (max in flight %d)", out, f.maxInflight)
	}
	// The places are given back.
	if len(m.httpSlots) != 0 {
		t.Fatalf("%d places still taken", len(m.httpSlots))
	}
}

func TestHTTPClientResponseBudget(t *testing.T) {
	body := make([]byte, MaxHTTPResponse)
	f := &fakeHTTP{handler: func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: body}, nil
	}}
	m := httpManager(t, f)
	// Sequential requests: each answer is charged, and the one that no longer fits is refused
	// before it reaches the host.
	res := runGen(t, m, `
var lens = [];
function next() {
  $httpClient.get({url: 'https://a.example/', 'binary-mode': true}, function (err, resp, data) {
    if (err) return $done({err: err, lens: lens.length});
    lens.push(data.length);
    next();
  });
}
next();`, 0)
	out := outMap(t, res)
	if out["err"] != "allocation limit reached" && out["err"] != "too many requests" {
		t.Fatalf("%v", out)
	}
	if n := out["lens"].(float64); n < 7 || n > 8 {
		t.Fatalf("%v answers fit the budget", n)
	}
	// An answer larger than the host was allowed to send is an error.
	f.handler = func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: make([]byte, MaxHTTPResponse+1)}, nil
	}
	res = runGen(t, m, `$httpClient.get('https://a.example/', function (err) { $done({err: err}) })`, 0)
	if out := outMap(t, res); out["err"] != "response too large" {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientHostPanic(t *testing.T) {
	f := &fakeHTTP{handler: func(context.Context, *HTTPRequest) (*HTTPResponse, error) { panic("host bug") }}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get('https://a.example/', function (err) { $done({err: err}) })`, 0)
	if out := outMap(t, res); out["err"] != "internal error" {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientEvaluateDryRun(t *testing.T) {
	f := &fakeHTTP{handler: func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: []byte("dry")}, nil
	}}
	m := httpManager(t, f)
	res, err := m.Evaluate(context.Background(), Config{Type: PhaseGeneric, Source: `$httpClient.get('https://a.example/', function (e, r, d) { $done({d: d}) })`}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out := outMap(t, res); out["d"] != "dry" {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientObjectFrozen(t *testing.T) {
	f := &fakeHTTP{}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get = function (o, cb) { cb('tampered'); }; $utils.ungzip = null; $done({})`, 0)
	outMap(t, res)
	res = runGen(t, m, `$httpClient.get('https://a.example/', function (err) { $done({err: err, u: typeof $utils.ungzip}) })`, 0)
	if out := outMap(t, res); out["err"] != nil || out["u"] != "function" {
		t.Fatalf("%v", out)
	}
}

func TestHTTPClientNoLeaks(t *testing.T) {
	base := runtime.NumGoroutine()
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		switch {
		case strings.HasSuffix(req.URL, "/slow"):
			return block(ctx, req)
		case strings.HasSuffix(req.URL, "/err"):
			return nil, errors.New("nope")
		}
		return &HTTPResponse{Status: 200, Body: []byte("x")}, nil
	}}
	m := httpManager(t, f)
	for i := 0; i < 20; i++ {
		runGen(t, m, `
$httpClient.get('https://a.example/slow', function () {});
$httpClient.get('https://a.example/err', function () {});
$httpClient.get('https://a.example/ok', function () { setTimeout(function () { $done({}) }, 5) });`, 0)
		runGen(t, m, `$httpClient.get('https://a.example/slow', function () {}); throw new Error('x')`, 0)
		runGen(t, m, `$httpClient.get('https://a.example/slow', function () {}); setTimeout(function () {}, 10)`, 200*time.Millisecond)
	}
	waitGoroutines(t, base)
}

func TestHTTPClientInHTTPScript(t *testing.T) {
	f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: []byte("tok")}, nil
	}}
	m := httpManager(t, f)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `$httpClient.get('https://auth.example/t', function (err, resp, data) { $done({headers: {'X-Token': data}}) })`), reqInput("https://e/"))
	if res.Action != ActionModify || !res.HeadersChanged || headerValue(res.Headers, "X-Token") != "tok" {
		t.Fatalf("%+v", res)
	}
	if r := f.requests()[0]; r.Phase != PhaseRequest || r.Script != "a" {
		t.Fatalf("%+v", r)
	}
}

func gzipBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUtilsUngzip(t *testing.T) {
	m := httpManager(t, nil)
	cfg := genericCfg("g", `
var out = $utils.ungzip($argument === '' ? new Uint8Array(0) : new Uint8Array(JSON.parse($argument)));
$done({text: new TextDecoder().decode(out), len: out.length, type: out instanceof Uint8Array});`, 0)
	payload := gzipBytes(t, []byte("hello, gzip"))
	nums := make([]int, len(payload))
	for i, b := range payload {
		nums[i] = int(b)
	}
	arg, _ := json.Marshal(nums)
	cfg.Argument = string(arg)
	res := runOne(t, m, cfg, nil)
	out := outMap(t, res)
	if out["text"] != "hello, gzip" || out["len"] != 11.0 || out["type"] != true {
		t.Fatalf("%v", out)
	}
	// ArrayBuffer input works too, multi-member data concatenates.
	multi := append(gzipBytes(t, []byte("ab")), gzipBytes(t, []byte("cd"))...)
	nums = make([]int, len(multi))
	for i, b := range multi {
		nums[i] = int(b)
	}
	arg, _ = json.Marshal(nums)
	cfg.Argument = string(arg)
	cfg.Source = `var u = new Uint8Array(JSON.parse($argument)); $done({text: new TextDecoder().decode($utils.ungzip(u.buffer))})`
	res = runOne(t, m, cfg, nil)
	if out := outMap(t, res); out["text"] != "abcd" {
		t.Fatalf("%v", out)
	}
}

func TestUtilsUngzipErrors(t *testing.T) {
	m := httpManager(t, nil)
	for name, src := range map[string]string{
		"not gzip":  `$utils.ungzip(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]))`,
		"empty":     `$utils.ungzip(new Uint8Array(0))`,
		"string":    `$utils.ungzip('abc')`,
		"undefined": `$utils.ungzip()`,
		"object":    `$utils.ungzip({})`,
	} {
		res := runGen(t, m, `try { `+src+`; $done({threw: false}) } catch (e) { $done({threw: true, msg: String(e.message)}) }`, 0)
		if out := outMap(t, res); out["threw"] != true {
			t.Errorf("%s: %v", name, out)
		}
	}
	// Truncated data fails instead of returning a prefix.
	payload := gzipBytes(t, bytes.Repeat([]byte("0123456789"), 1000))
	payload = payload[:len(payload)-12]
	nums := make([]int, len(payload))
	for i, b := range payload {
		nums[i] = int(b)
	}
	arg, _ := json.Marshal(nums)
	cfg := genericCfg("g", `try { $utils.ungzip(new Uint8Array(JSON.parse($argument))); $done({threw: false}) } catch (e) { $done({threw: true}) }`, 0)
	cfg.Argument = string(arg)
	if out := outMap(t, runOne(t, m, cfg, nil)); out["threw"] != true {
		t.Fatalf("truncated: %v", out)
	}
}

func TestUtilsUngzipBomb(t *testing.T) {
	// 200 MiB of zeros compress to about 200 KB.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 200; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f := &fakeHTTP{handler: func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: buf.Bytes()}, nil
	}}
	m := httpManager(t, f)
	res := runGen(t, m, `$httpClient.get({url: 'https://a.example/', 'binary-mode': true}, function (err, resp, data) { var out = $utils.ungzip(data); $done({len: out.length}) })`, 0)
	if res.Action != ActionLimit {
		t.Fatalf("%+v", res)
	}
	// Under the allowance the same data works.
	var small bytes.Buffer
	zw = gzip.NewWriter(&small)
	for i := 0; i < 20; i++ {
		_, _ = zw.Write(chunk)
	}
	_ = zw.Close()
	f.handler = func(context.Context, *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{Status: 200, Body: small.Bytes()}, nil
	}
	res = runGen(t, m, `$httpClient.get({url: 'https://a.example/', 'binary-mode': true}, function (err, resp, data) { var out = $utils.ungzip(data); $done({len: out.length}) })`, 0)
	if out := outMap(t, res); out["len"] != float64(20<<20) {
		t.Fatalf("%v", out)
	}
}

func TestUtilsLookups(t *testing.T) {
	m := httpManager(t, nil)
	res := runGen(t, m, `$done({a: $utils.geoip('8.8.8.8'), b: $utils.ipasn('8.8.8.8'), c: $utils.ipaso('8.8.8.8'), d: $utils.geoip()})`, 0)
	out := outMap(t, res)
	for _, k := range []string{"a", "b", "c", "d"} {
		if v, ok := out[k]; !ok || v != nil {
			t.Errorf("%s: %v", k, out)
		}
	}
}

// The call is interrupted while the answer of a request is being delivered: the outcome is
// the interrupt's, whatever the callback was doing ($done included).
func TestHTTPClientInterruptDuringDelivery(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			m := httpManager(t, f)
			cfg := genericCfg("g", `$httpClient.get({url: 'https://a.example/', timeout: 30}, function () { $done({}) })`, 0)
			ctx := context.Background()
			if mode == "timeout" {
				cfg.Timeout = 50 * time.Millisecond
			}
			if err := m.Apply([]Config{cfg}); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 100; i++ {
				c := ctx
				cancel := func() {}
				if mode == "cancel" {
					c, cancel = context.WithTimeout(ctx, time.Duration(5+i%7)*time.Millisecond)
				}
				res, err := m.RunGeneric(c, "g", "")
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				ok := res.Action == ActionSkipped && res.Reason == ReasonCanceled
				if mode == "timeout" {
					// The request ends with its own timeout error at about the same time.
					ok = res.Action == ActionTimeout || res.Action == ActionNone
				}
				if !ok {
					t.Fatalf("run %d: %+v", i, res)
				}
				if mode == "timeout" && i >= 20 {
					break
				}
			}
		})
	}
}
