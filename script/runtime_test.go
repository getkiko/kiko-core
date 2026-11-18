package script

import (
	"strings"
	"testing"
)

func TestRequestModify(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `
var h = $request.headers;
h['X-Test'] = 'yes';
delete h['Cookie'];
$done({url: $request.url + '?z=1', headers: h});
`), reqInput("https://example.com/p", "Cookie", "a=b", "Accept", "*/*"))
	if res.Action != ActionModify || res.Error != "" {
		t.Fatalf("%+v", res)
	}
	if res.URL != "https://example.com/p?z=1" {
		t.Fatal(res.URL)
	}
	if headerValue(res.Headers, "X-Test") != "yes" || headerValue(res.Headers, "Cookie") != "" || headerValue(res.Headers, "Accept") != "*/*" {
		t.Fatalf("%+v", res.Headers)
	}
}

func TestNoDoneIsNoChange(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `var x = 1;`), reqInput("https://e/"))
	if res.Action != ActionNone {
		t.Fatalf("%+v", res)
	}
}

func TestMockResponse(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `$done({response: {status: 201, headers: {'Content-Type': 'text/plain', 'Set-Cookie': ['a=1', 'b=2']}, body: 'hi'}})`), reqInput("https://e/"))
	if res.Action != ActionRespond || res.Response == nil || res.Response.Status != 201 || string(res.Response.Body) != "hi" {
		t.Fatalf("%+v", res)
	}
	if headerValue(res.Response.Headers, "Set-Cookie") != "a=1|b=2" {
		t.Fatalf("%+v", res.Response.Headers)
	}
}

func TestAbort(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `$done({abort: true})`), reqInput("https://e/"))
	if res.Action != ActionAbort {
		t.Fatalf("%+v", res)
	}
}

func TestResponseBody(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseResponse, `let b = JSON.parse($response.body); delete b.ads; b.n = 2; $done({status: 203, body: JSON.stringify(b)})`)
	cfg.RequiresBody = true
	res := runOne(t, m, cfg, respInput(200, `{"ads":[1],"n":1}`))
	if res.Action != ActionModify || res.Status != 203 || string(res.Body) != `{"n":2}` || !res.BodyChanged {
		t.Fatalf("%+v", res)
	}
}

func TestBodyIgnoredWithoutRequiresBody(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseResponse, `$done({body: 'x'})`), respInput(200, "orig"))
	if res.Action != ActionNone || res.BodyChanged {
		t.Fatalf("%+v", res)
	}
}

func TestDoneOnce(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `$done({url:'https://one/'}); $done({url:'https://two/'});`), reqInput("https://e/"))
	if res.URL != "https://one/" {
		t.Fatal(res.URL)
	}
}

func TestThrowIsError(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `throw new Error('boom')`), reqInput("https://e/"))
	if res.Action != ActionError || !strings.Contains(res.Error, "boom") {
		t.Fatalf("%+v", res)
	}
}

func TestAsyncPromiseAndTimeout(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseRequest, `
Promise.resolve(1).then(function (v) { return new Promise(function (r) { setTimeout(function () { r(v + 1); }, 20); }); })
  .then(function (v) { $done({url: 'https://e/' + v}); });
`), reqInput("https://e/"))
	if res.Action != ActionModify || res.URL != "https://e/2" {
		t.Fatalf("%+v", res)
	}
}

func TestNoStateLeak(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseRequest, `
if (typeof leaked !== 'undefined') { $done({url: 'https://leak/'}); } else { leaked = 1; globalThis.second = 2; var local = 3; $done({}); }
`)
	cfg.Argument = "k=v"
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	for i := 0; i < 5; i++ {
		res := m.Run(t.Context(), sc, reqInput("https://e/"))
		if res.Action != ActionNone {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
}

func TestLetConstRedeclare(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseRequest, `const x = 1; let y = 2; $done({});`)
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	for i := 0; i < 3; i++ {
		if res := m.Run(t.Context(), sc, reqInput("https://e/")); res.Action != ActionNone {
			t.Fatalf("%+v", res)
		}
	}
}

func TestPersistentStore(t *testing.T) {
	store := NewMemoryStore()
	m := NewManager(ManagerOptions{Store: store})
	defer m.Close()
	runOne(t, m, httpConfig("a", PhaseRequest, `$persistentStore.write('v1','k'); $persistentStore.write('sh','@shared/s'); $done({});`), reqInput("https://e/"))
	if v, ok, _ := store.Get("a", "k"); !ok || v != "v1" {
		t.Fatal(v, ok)
	}
	if v, ok, _ := store.Get(SharedNamespace, "s"); !ok || v != "sh" {
		t.Fatal(v, ok)
	}
	res := runOne(t, m, httpConfig("b", PhaseRequest, `var a = $persistentStore.read('k'); var s = $persistentStore.read('@shared/s'); $done({url: 'https://e/' + a + '-' + s});`), reqInput("https://e/"))
	if res.URL != "https://e/null-sh" {
		t.Fatal(res.URL)
	}
}

func TestNotification(t *testing.T) {
	n := &testNotifier{}
	m := NewManager(ManagerOptions{Notifier: n})
	defer m.Close()
	runOne(t, m, httpConfig("a", PhaseRequest, `$notification.post('T', 'S', 'B', {url: 'https://x'}); $done({});`), reqInput("https://e/"))
	if len(n.n) != 1 || n.n[0].Title != "T" || n.n[0].URL != "https://x" || n.n[0].Script != "a" {
		t.Fatalf("%+v", n.n)
	}
}

func TestConsoleLogs(t *testing.T) {
	l := &testLogger{}
	m := NewManager(ManagerOptions{Logger: l})
	defer m.Close()
	res := runOne(t, m, httpConfig("a", PhaseRequest, `console.log('a', {b:1}); console.error('bad'); $done({});`), reqInput("https://e/"))
	if len(res.Logs) != 2 || res.Logs[0].Message != `a {"b":1}` || res.Logs[1].Level != "error" {
		t.Fatalf("%+v", res.Logs)
	}
	if len(l.entries) != 2 || l.entries[0].Script != "a" {
		t.Fatalf("%+v", l.entries)
	}
}

func TestBinaryBody(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseResponse, `var b = $response.body; var out = new Uint8Array(b.length + 1); out.set(b); out[b.length] = 0x21; $done({body: out});`)
	cfg.RequiresBody, cfg.BinaryBody = true, true
	in := respInput(200, "")
	in.Response.Body = []byte{0, 1, 2, 0xff}
	res := runOne(t, m, cfg, in)
	if res.Action != ActionModify || string(res.Body) != "\x00\x01\x02\xff!" {
		t.Fatalf("%+v", res)
	}
}

func TestHeaderMergeSemantics(t *testing.T) {
	m := newTestManager(t)
	res := runOne(t, m, httpConfig("a", PhaseResponse, `
var h = $response.headers;
h['X-New'] = '1';
h['Set-Cookie'] = 'only=1';
$done({headers: h});`), respInput(200, "", "Set-Cookie", "a=1", "X-Keep", "k", "set-cookie", "b=2", "Y", "y"))
	if !res.HeadersChanged {
		t.Fatalf("%+v", res)
	}
	want := []Header{{"Set-Cookie", "only=1"}, {"X-Keep", "k"}, {"Y", "y"}, {"X-New", "1"}}
	if len(res.Headers) != len(want) {
		t.Fatalf("%+v", res.Headers)
	}
	for i := range want {
		if res.Headers[i] != want[i] {
			t.Fatalf("%+v", res.Headers)
		}
	}
	// Untouched duplicates stay as they were.
	res = runOne(t, m, httpConfig("a", PhaseResponse, `var h = $response.headers; h['X-New']='1'; $done({headers: h});`), respInput(200, "", "Set-Cookie", "a=1", "Set-Cookie", "b=2"))
	if headerValue(res.Headers, "Set-Cookie") != "a=1|b=2" || headerValue(res.Headers, "X-New") != "1" {
		t.Fatalf("%+v", res.Headers)
	}
}

func TestGeneric(t *testing.T) {
	m := newTestManager(t)
	cfg := Config{Tag: "g", Type: PhaseGeneric, Source: `$persistentStore.write('1','n'); $done({ok: true, arg: $argument});`, Argument: "x=1"}
	res := runOne(t, m, cfg, nil)
	if res.Action != ActionNone || res.Output != `{"ok":true,"arg":"x=1"}` {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateDry(t *testing.T) {
	store := NewMemoryStore()
	m := NewManager(ManagerOptions{Store: store})
	defer m.Close()
	res, err := m.Evaluate(t.Context(), Config{Type: PhaseRequest, Source: `$persistentStore.write('1','k'); $notification.post('t','','',''); $done({});`}, reqInput("https://e/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notifications) != 1 {
		t.Fatalf("%+v", res)
	}
	if _, ok, _ := store.Get("eval", "k"); ok {
		t.Fatal("dry run wrote to the real store")
	}
}
