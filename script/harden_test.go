package script

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hardened runs a hostile source and requires that it ends, with one of the given actions,
// within the time bound. An empty list accepts any action.
func hardened(t *testing.T, name, src string, bound time.Duration, accept ...Action) *Result {
	t.Helper()
	m := newTestManager(t)
	cfg := httpConfig("h", PhaseRequest, src)
	cfg.Timeout = 2 * time.Second
	start := time.Now()
	var res *Result
	within(t, bound+10*time.Second, func() {
		if err := m.Apply([]Config{cfg}); err != nil {
			res = &Result{Action: ActionError, Error: "compile: " + err.Error()}
			return
		}
		res = m.Run(context.Background(), m.Current().Lookup("h"), reqInput("https://e/"))
	})
	if d := time.Since(start); d > bound {
		t.Errorf("%s took %s (bound %s)", name, d, bound)
	}
	if len(accept) > 0 {
		ok := false
		for _, a := range accept {
			ok = ok || res.Action == a
		}
		if !ok {
			t.Errorf("%s: action %s (%s), want one of %v", name, res.Action, res.Error, accept)
		}
	}
	return res
}

// TestHardenedNativeRecursion: cyclic and deeply nested arrays used to overflow the Go stack
// in native join, toString, toLocaleString and flat.
func TestHardenedNativeRecursion(t *testing.T) {
	for name, src := range map[string]string{
		"console":    `var a=[1]; a.push(a); console.log(a)`,
		"String":     `var a=[1]; a.push(a); String(a)`,
		"concat":     `var a=[1]; a.push(a); a+''`,
		"toString":   `var a=[1]; a.push(a); a.toString()`,
		"locale":     `var a=[1]; a.push(a); a.toLocaleString()`,
		"flat":       `var a=[1]; a.push(a); a.flat(Infinity)`,
		"objJoin":    `var o={length:1}; o[0]=o; Array.prototype.join.call(o)`,
		"nested":     `var a=[]; for (var i=0;i<800000;i++) a=[a]; String(a)`,
		"nestedFlat": `var a=[]; for (var i=0;i<800000;i++) a=[a]; a.flat(Infinity)`,
		"template":   "var a=[1]; a.push(a); `${a}`",
	} {
		t.Run(name, func(t *testing.T) {
			hardened(t, name, src, 5*time.Second, ActionNone, ActionError)
		})
	}
	res := hardened(t, "values", `var a=[1,[2,[3]]]; var b=[1]; b.push(b); $done({url: 'https://e/' + a.join('-') + '/' + a.toString() + '/' + a.flat(Infinity).join('') + '/' + b.join(',')});`, time.Second, ActionModify)
	if res.URL != "https://e/1-2,3/1,2,3/123/1," {
		t.Fatalf("results changed: %s", res.URL)
	}
}

func TestHardenedDoneExports(t *testing.T) {
	for name, src := range map[string]string{
		"deepBody":   `var a=[]; for (var i=0;i<900000;i++) a=[a]; $done({body:a})`,
		"deepHeader": `var a=[]; for (var i=0;i<900000;i++) a=[a]; $done({headers:{X:a}})`,
		"cyclic":     `var a=[]; a.push(a); $done({headers:{X:a}})`,
		"deepUrl":    `var a=[]; for (var i=0;i<900000;i++) a=[a]; $done({url:a})`,
		"deepStatus": `var a=[]; for (var i=0;i<900000;i++) a=[a]; $done({status:a})`,
	} {
		t.Run(name, func(t *testing.T) {
			hardened(t, name, src, 10*time.Second)
		})
	}
	m := newTestManager(t)
	cfg := Config{Tag: "g", Type: PhaseGeneric, Source: `var a=[]; for (var i=0;i<900000;i++) a=[a]; $done(a)`}
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	res, _ := m.RunGeneric(context.Background(), "g", "")
	if res.Action != ActionError && res.Action != ActionLimit {
		t.Fatalf("%+v", res)
	}
}

func TestHardenedEvalAndFunction(t *testing.T) {
	for name, src := range map[string]string{
		"parens300k": `eval('('.repeat(300000)+'1'+')'.repeat(300000))`,
		"bang2m":     `eval('!'.repeat(2000000)+'1')`,
		"plus50k":    `eval('1+'.repeat(50000)+'1')`,
		"fn":         `new Function('return ' + '['.repeat(300000) + ']'.repeat(300000))`,
		"fnCall":     `Function('return ' + '1+'.repeat(50000) + '1')`,
		"ctor":       `(function(){}).constructor('return ' + '('.repeat(300000) + '1' + ')'.repeat(300000))`,
		"async":      `Object.getPrototypeOf(async function(){}).constructor('return ' + '!'.repeat(1000000) + '1')`,
		"generator":  `Object.getPrototypeOf(function*(){}).constructor('return ' + '!'.repeat(1000000) + '1')`,
		"indirect":   `(0, eval)('!'.repeat(1000000) + '1')`,
	} {
		t.Run(name, func(t *testing.T) {
			res := hardened(t, name, src, 3*time.Second, ActionError)
			if !strings.Contains(res.Error, "source") {
				t.Errorf("unexpected error %q", res.Error)
			}
		})
	}
	// Ordinary use stays available.
	res := hardened(t, "ok", `var f = new Function('a', 'b', 'return a + b'); var g = Function('return 7'); $done({url: 'https://e/' + f(1, 2) + eval('1+1') + g() + (function(){}).constructor('return 5')()})`, time.Second, ActionModify)
	if res.URL != "https://e/3275" {
		t.Fatal(res.URL)
	}
}

func TestHardenedAllocation(t *testing.T) {
	for name, src := range map[string]string{
		"arrayFrom":   `Array.from({length:1e9})`,
		"lengthMap":   `var a=[]; a.length=4e9-1; a.map(function(x){return x})`,
		"apply":       `Array.apply(null,{length:1e8})`,
		"reflect":     `Reflect.apply(Array, null, {length:1e8})`,
		"sort":        `Array(1e8).sort()`,
		"newArray":    `new Array(1e8).fill(0)`,
		"split":       `'a'.repeat(6e7).split('')`,
		"replace":     `'a'.repeat(1e7).replace(/a/g, 'b'.repeat(64))`,
		"replaceAll":  `'a'.repeat(1e7).replaceAll('a', 'b'.repeat(64))`,
		"indexOf":     `var a=[]; a.length=4e9-1; a.indexOf(1)`,
		"concat":      `var a=[]; a.length=2e9; a.concat(a)`,
		"reverse":     `var a=[]; a.length=2e9; a.reverse()`,
		"typedFrom":   `Uint8Array.from({length:1e9})`,
		"spreadApply": `var a=[]; a.length=1e9; Math.max.apply(null, a)`,
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			hardened(t, name, src, 6*time.Second, ActionLimit, ActionError, ActionTimeout)
			runtime.ReadMemStats(&after)
			if grew := int64(after.TotalAlloc - before.TotalAlloc); grew > 600<<20 {
				t.Errorf("%s allocated %d MiB", name, grew>>20)
			}
		})
	}
}

// TestCompileBounds: sources that compile in quadratic time or recurse per token are refused
// at validation, quickly.
func TestCompileBounds(t *testing.T) {
	rep := strings.Repeat
	m := newTestManager(t)
	for name, src := range map[string]string{
		"plus":     rep("1+", 500000) + "1",
		"minus":    rep("- ", 500000) + "1",
		"label":    rep("a:", 500000) + ";",
		"arrow":    rep("x=>", 300000) + "1",
		"pow":      rep("1**", 300000) + "1",
		"or":       rep("1||", 300000) + "1",
		"void":     rep("void ", 200000) + "1",
		"bang":     rep("!", 1000000) + "1",
		"call":     "a" + rep("()", 500000),
		"member":   "a" + rep(".a", 500000),
		"if":       rep("if(1)", 200000) + ";",
		"tmpl":     rep("a`x`", 200000),
		"nestTmpl": rep("`${", 100000) + "1" + rep("}`", 100000),
		"parens":   rep("(", 100000) + "1" + rep(")", 100000),
	} {
		start := time.Now()
		err := m.Apply([]Config{httpConfig("c", PhaseRequest, src)})
		if err == nil {
			t.Errorf("%s accepted", name)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s took %s to refuse", name, d)
		}
	}
	// Ordinary large sources pass: a long comma list, many statements, a big object literal.
	big := "var x = {" + rep(`"k":1,`, 50000) + `"z":2}; ` + rep("a=1,", 20000) + "b=2; " + rep("var q=1;\n", 20000) + "$done({});"
	if err := m.Apply([]Config{httpConfig("big", PhaseRequest, big)}); err != nil {
		t.Fatalf("a large ordinary script was refused: %v", err)
	}
	if res := m.Run(context.Background(), m.Current().Lookup("big"), reqInput("https://e/")); res.Action != ActionNone || res.Error != "" {
		t.Fatalf("%+v", res)
	}
}

// TestNoMisfireUnderTraffic: a CPU-bound script is not killed by allocation going on elsewhere
// in the process at a normal rate.
func TestNoMisfireUnderTraffic(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("cpu", PhaseRequest, `var t = Date.now(); var n = 0; while (Date.now() - t < 400) { n++ } $done({});`)
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var allocated atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b := make([]byte, 1<<20)
				b[0] = 1
				allocated.Add(int64(len(b)))
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	res := m.Run(context.Background(), m.Current().Lookup("cpu"), reqInput("https://e/"))
	close(stop)
	wg.Wait()
	t.Logf("competing traffic: %d MiB during the call", allocated.Load()>>20)
	if res.Action != ActionNone {
		t.Fatalf("%+v", res)
	}
}

func TestNotificationRateIsPerScript(t *testing.T) {
	n := &testNotifier{}
	m := NewManager(ManagerOptions{Notifier: n})
	defer m.Close()
	if err := m.Apply([]Config{httpConfig("a", PhaseRequest, `$notification.post('t','','',''); $done({})`)}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	for i := 0; i < 50; i++ {
		m.Run(context.Background(), sc, reqInput("https://e/"))
	}
	if len(n.n) != maxNotifyRate {
		t.Fatalf("%d notifications, want %d", len(n.n), maxNotifyRate)
	}
}

func TestPoolStateIsolation(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseRequest, `
if (({}).polluted === 1) { throw new Error('prototype pollution leaked'); }
Object.prototype.polluted = 1;
$done({});`)
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	for i := 0; i < 5; i++ {
		if res := m.Run(context.Background(), sc, reqInput("https://e/")); res.Action != ActionNone {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
	frozen := httpConfig("f", PhaseRequest, `
if (Object.isFrozen(globalThis)) { throw new Error('frozen global leaked'); }
var url = $request.url;
Object.freeze(globalThis);
Object.freeze(Object.prototype);
$done({url: url + '/x'});`)
	if err := m.Apply([]Config{frozen}); err != nil {
		t.Fatal(err)
	}
	sc = m.Current().Lookup("f")
	for i := 0; i < 5; i++ {
		res := m.Run(context.Background(), sc, reqInput("https://e/"+strings.Repeat("a", i)))
		if res.Action != ActionModify || res.URL != "https://e/"+strings.Repeat("a", i)+"/x" {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
	// A tampered VM is not put back.
	if idle := sc.pool.idleCount(); idle != 0 {
		t.Fatalf("%d tampered VMs were kept", idle)
	}
	// An untouched script keeps its pooled VM.
	clean := httpConfig("c", PhaseRequest, `$done({})`)
	if err := m.Apply([]Config{clean}); err != nil {
		t.Fatal(err)
	}
	sc = m.Current().Lookup("c")
	m.Run(context.Background(), sc, reqInput("https://e/"))
	if sc.pool.idleCount() != 1 {
		t.Fatal("a clean VM was dropped")
	}
}

func TestCanceledCallIsNotAFailure(t *testing.T) {
	m := newTestManager(t)
	if err := m.Apply([]Config{httpConfig("a", PhaseRequest, `while (true) {}`)}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	for i := 0; i < PauseFailures+10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
		res := m.Run(ctx, sc, reqInput("https://e/"))
		cancel()
		if res.Action == ActionPaused {
			t.Fatal("canceled calls paused the script")
		}
	}
}

func TestReloadKeepsStateOnlyForIdenticalScripts(t *testing.T) {
	m := newTestManager(t)
	base := httpConfig("a", PhaseRequest, `throw new Error('x')`)
	if err := m.Apply([]Config{base}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	for i := 0; i < PauseFailures+2; i++ {
		m.Run(context.Background(), sc, reqInput("https://e/"))
	}
	for name, change := range map[string]func(*Config){
		"timeout":  func(c *Config) { c.Timeout = 3 * time.Second },
		"body":     func(c *Config) { c.RequiresBody = true },
		"binary":   func(c *Config) { c.RequiresBody, c.BinaryBody = true, true },
		"max_size": func(c *Config) { c.MaxSize = 4096 },
	} {
		next := base
		change(&next)
		if err := m.Apply([]Config{next}); err != nil {
			t.Fatal(err)
		}
		if m.Current().Status()[0].Paused {
			t.Errorf("%s: the new settings inherited the pause", name)
		}
		if err := m.Apply([]Config{base}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSleepingCallReleasesItsSlot(t *testing.T) {
	m := NewManager(ManagerOptions{Slots: 1})
	defer m.Close()
	if err := m.Apply([]Config{
		httpConfig("slow", PhaseRequest, `setTimeout(function(){ $done({}) }, 500)`),
		httpConfig("fast", PhaseRequest, `$done({url: 'https://e/fast'})`),
	}); err != nil {
		t.Fatal(err)
	}
	go m.Run(context.Background(), m.Current().Lookup("slow"), reqInput("https://e/"))
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	res := m.Run(context.Background(), m.Current().Lookup("fast"), reqInput("https://e/"))
	if res.URL != "https://e/fast" || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("%+v after %s", res, time.Since(start))
	}
}
