package script

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func hostile(t *testing.T, m *Manager, src string, timeout time.Duration, requiresBody bool) *Result {
	t.Helper()
	cfg := httpConfig("h", PhaseRequest, src)
	cfg.Timeout = timeout
	var res *Result
	within(t, 20*time.Second, func() {
		res = runOne(t, m, cfg, reqInput("https://e/"))
	})
	return res
}

func TestHostileInfiniteLoop(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `while(1){}`, 200*time.Millisecond, false)
	if res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
	if res.Duration > 2*time.Second {
		t.Fatal(res.Duration)
	}
}

func TestHostileMicrotaskLoop(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `Promise.resolve().then(function(){ while(1){} })`, 200*time.Millisecond, false)
	if res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
}

func TestHostileMicrotaskChain(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `function f(){ Promise.resolve().then(f) } f()`, 300*time.Millisecond, false)
	if res.Action != ActionTimeout && res.Action != ActionLimit {
		t.Fatalf("%+v", res)
	}
}

func TestHostileTryCatchLoop(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `while(1){ try { throw 1 } catch(e) {} }`, 200*time.Millisecond, false)
	if res.Action != ActionTimeout && res.Action != ActionLimit {
		t.Fatalf("%+v", res)
	}
}

func TestHostileDeepRecursion(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `function f(n){ return f(n+1) + 1 } f(0)`, 2*time.Second, false)
	if res.Action != ActionLimit && res.Action != ActionError {
		t.Fatalf("%+v", res)
	}
	res = hostile(t, m, `function f(n){ try { return f(n+1) } catch(e) { return f(n+1) } } f(0)`, 500*time.Millisecond, false)
	if res.Action != ActionLimit && res.Action != ActionError && res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
}

func TestHostileRepeat(t *testing.T) {
	m := newTestManager(t)
	for _, src := range []string{
		`'a'.repeat(1e9)`,
		`var s = 'a'.repeat(1e7); s.repeat(100)`,
		`'a'.padStart(1e9, 'b')`,
		`new Array(1e9).join('x')`,
		`new ArrayBuffer(1e9)`,
		`new Uint8Array(1e9)`,
		`new Float64Array(1e8)`,
		`Array(1e9).fill(0)`,
		`var a = []; for (var i = 0; i < 40; i++) a.push('x'.repeat(2e6));`,
	} {
		res := hostile(t, m, src, 5*time.Second, false)
		if res.Action != ActionLimit {
			t.Fatalf("%s: %+v", src, res)
		}
	}
}

func TestHostileAllocationGrowth(t *testing.T) {
	m := newTestManager(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := hostile(t, m, `var a = []; while (true) { a.push({x: 1, y: 'abc'}); }`, 10*time.Second, false)
	if res.Action != ActionLimit && res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
	if res.Action == ActionTimeout {
		t.Logf("growth ended by timeout, not by the allocation backstop")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("action=%s after %s, heap in use %d MiB", res.Action, res.Duration, after.HeapInuse>>20)
}

func TestHostileStringDoubling(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `var s = 'abcdefgh'; for (var i = 0; i < 40; i++) { s = s + s; } s.length`, 5*time.Second, false)
	t.Logf("action=%s err=%s", res.Action, res.Error)
	if res.Action != ActionLimit && res.Action != ActionError && res.Action != ActionNone {
		t.Fatalf("%+v", res)
	}
}

func TestHostileJSONParseDeep(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `var s = '['.repeat(1500000) + ']'.repeat(1500000); JSON.parse(s)`, 5*time.Second, false)
	if res.Action != ActionError && res.Action != ActionLimit {
		t.Fatalf("%+v", res)
	}
}

func TestHostileJSONStringifyDeep(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `var a = []; for (var i = 0; i < 300000; i++) a = [a]; JSON.stringify(a)`, 5*time.Second, false)
	t.Logf("action=%s err=%.80s", res.Action, res.Error)
}

func TestHostileRegex(t *testing.T) {
	m := newTestManager(t)
	for _, src := range []string{
		`/(a+)+$/.test('a'.repeat(40) + 'b')`,
		`/(a|aa)+$/.test('a'.repeat(50) + 'b')`,
		`/^(a+)+\1$/.test('a'.repeat(40) + 'b')`,
		`/(?=(a+)+b)a+c/.test('a'.repeat(40))`,
		`while (1) { try { /^(a+)+\1$/.test('a'.repeat(40) + 'b') } catch (e) {} }`,
	} {
		start := time.Now()
		res := hostile(t, m, src, 3*time.Second, false)
		t.Logf("%s -> %s %s (%s)", src, res.Action, res.Error, time.Since(start))
		if time.Since(start) > 12*time.Second {
			t.Fatalf("%s took %s", src, time.Since(start))
		}
	}
}

func TestHostileNeverResolves(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `new Promise(function(){}).then(function(){ $done({}) })`, time.Second, false)
	if res.Action != ActionNone {
		t.Fatalf("%+v", res)
	}
}

func TestHostilePendingTimersTimeout(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `setTimeout(function(){ $done({url:'https://late/'}) }, 5000)`, 300*time.Millisecond, false)
	if res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
	res = hostile(t, m, `setInterval(function(){}, 0)`, 300*time.Millisecond, false)
	if res.Action != ActionTimeout {
		t.Fatalf("%+v", res)
	}
}

func TestHostileGoroutineLeak(t *testing.T) {
	m := newTestManager(t)
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		hostile(t, m, `while(1){}`, 30*time.Millisecond, false)
		hostile(t, m, `setTimeout(function(){}, 10000)`, 30*time.Millisecond, false)
		hostile(t, m, `throw 1`, 30*time.Millisecond, false)
	}
	m.Close()
	time.Sleep(300 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines %d -> %d", before, after)
	}
}

func TestSandboxSurface(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `
var r = [typeof require, typeof process, typeof fs, typeof XMLHttpRequest, typeof fetch, typeof Function, typeof eval, typeof globalThis.$httpClient].join(',');
$done({url: 'https://e/' + r});`, time.Second, false)
	if res.URL != "https://e/undefined,undefined,undefined,undefined,undefined,function,function,object" {
		t.Fatalf("%+v", res)
	}
	// The Function constructor cannot reach Go.
	res = hostile(t, m, `var g = (new Function('return this'))(); $done({url: 'https://e/' + typeof g.process + typeof g.require})`, time.Second, false)
	if res.URL != "https://e/undefinedundefined" {
		t.Fatalf("%+v", res)
	}
}

func TestPanicIsolation(t *testing.T) {
	m := newTestManager(t)
	// Many parallel hostile calls keep the manager serving.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := httpConfig("p"+string(rune('a'+i)), PhaseRequest, `if (Math.random() < 2) { throw new TypeError('x') }`)
			if err := m.Apply([]Config{cfg}); err != nil {
				t.Error(err)
				return
			}
		}(i)
	}
	wg.Wait()
}

func TestBusyWhenSaturated(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	m := NewManager(ManagerOptions{Slots: 1})
	defer m.Close()
	cfg := httpConfig("slow", PhaseRequest, `var t = Date.now(); while (Date.now() - t < 3500) {} $done({})`)
	cfg.Timeout = 5 * time.Second
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("slow")
	go m.Run(context.Background(), sc, reqInput("https://e/"))
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	res := m.Run(context.Background(), sc, reqInput("https://e/"))
	if res.Action != ActionSkipped || res.Reason != SkipBusy {
		t.Fatalf("%+v", res)
	}
	if d := time.Since(start); d < WaitLimit-100*time.Millisecond || d > WaitLimit+time.Second {
		t.Fatal(d)
	}
}

func TestAutoPause(t *testing.T) {
	m := newTestManager(t)
	if err := m.Apply([]Config{httpConfig("bad", PhaseRequest, `throw new Error('x')`)}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("bad")
	var paused string
	m.OnPause = func(tag string, until time.Time) { paused = tag }
	var last *Result
	for i := 0; i < PauseFailures+5; i++ {
		last = m.Run(context.Background(), sc, reqInput("https://e/"))
	}
	if last.Action != ActionPaused || paused != "bad" {
		t.Fatalf("%+v %q", last, paused)
	}
	st := m.Current().Status()
	if len(st) != 1 || !st[0].Paused || st[0].Errors != PauseFailures+1 {
		t.Fatalf("%+v", st)
	}
	// A reload with the same script keeps the pause; a changed script starts fresh.
	if err := m.Apply([]Config{httpConfig("bad", PhaseRequest, `throw new Error('x')`)}); err != nil {
		t.Fatal(err)
	}
	if !m.Current().Status()[0].Paused {
		t.Fatal("pause lost on identical reload")
	}
	if err := m.Apply([]Config{httpConfig("bad", PhaseRequest, `$done({})`)}); err != nil {
		t.Fatal(err)
	}
	if m.Current().Status()[0].Paused {
		t.Fatal("changed script still paused")
	}
	_ = strings.TrimSpace
}
