package script

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A rule or dns script that answers, but needs more than half of its timeout every time,
// is bypassed like one that fails, and the bypass is logged.
func TestRuleScriptSlowBreaker(t *testing.T) {
	logger := &testLogger{}
	cfg := ruleConfig("slow", PhaseDNS, `var t = Date.now(); while (Date.now() - t < 120) {} $done({})`)
	cfg.Timeout = 200 * time.Millisecond
	m := ruleManager(t, cfg)
	m.SetLogger(logger)
	now := time.Unix(2_000_000, 0)
	m.clock = func() time.Time { return now }
	for i := 0; i < RuleSlowFailures; i++ {
		out := m.RunDNS("slow", &RuleInput{Domain: "d" + strings.Repeat("x", i) + ".example"})
		if out.Err != "" {
			t.Fatalf("run %d: %+v", i, out)
		}
	}
	out := m.RunDNS("slow", &RuleInput{Domain: "next.example"})
	if out.Err != errBreaker || out.Decision.Kind != DNSPass {
		t.Fatalf("after %d slow runs: %+v", RuleSlowFailures, out)
	}
	if n := runsOf(m, "slow"); n != RuleSlowFailures {
		t.Fatalf("%d runs, want %d", n, RuleSlowFailures)
	}
	logger.mu.Lock()
	warned := false
	for _, e := range logger.entries {
		warned = warned || e.Level == "warn" && strings.Contains(e.Message, "bypassed")
	}
	logger.mu.Unlock()
	if !warned {
		t.Fatal("no bypass warning")
	}
	now = now.Add(RuleBreakerPause + time.Second)
	if out := m.RunDNS("slow", &RuleInput{Domain: "later.example"}); out.Err != "" {
		t.Fatalf("after the pause: %+v", out)
	}
}

// A fast script never trips the slow breaker, and a fast run resets the count.
func TestRuleScriptFastIsNotBreaker(t *testing.T) {
	m := ruleManager(t, ruleConfig("fast", PhaseDNS, `$done({})`))
	for i := 0; i < 3*RuleSlowFailures; i++ {
		if out := m.RunDNS("fast", &RuleInput{Domain: "f" + strings.Repeat("y", i) + ".example"}); out.Err != "" {
			t.Fatalf("run %d: %+v", i, out)
		}
	}
}

// The concurrent calls of one script share an allocation allowance; the charge is given back
// when the calls end.
func TestScriptSharedAllocationLimit(t *testing.T) {
	m := NewManager(ManagerOptions{Slots: 16})
	t.Cleanup(m.Close)
	cfg := httpConfig("h", PhaseRequest, `var a = new Uint8Array(40 << 20); setTimeout(function () { $done({url: 'https://e/ok'}); }, 400);`)
	cfg.Timeout = 5 * time.Second
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("h")
	var wg sync.WaitGroup
	var limited, ok atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := m.Run(context.Background(), sc, reqInput("https://e/"))
			switch res.Action {
			case ActionLimit:
				limited.Add(1)
			case ActionModify:
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if limited.Load() == 0 || ok.Load() == 0 {
		t.Fatalf("limited %d, ok %d: want some of each", limited.Load(), ok.Load())
	}
	if n := sc.state.liveCharge.Load(); n != 0 {
		t.Fatalf("script charge %d after the calls", n)
	}
	if n := m.liveCharge.Load(); n != 0 {
		t.Fatalf("manager charge %d after the calls", n)
	}
	if res := m.Run(context.Background(), sc, reqInput("https://e/")); res.Action != ActionModify {
		t.Fatalf("after release: %+v", res)
	}
}

// Another script is not charged for the first one's allowance until the manager limit.
func TestScriptAllocationIsPerScript(t *testing.T) {
	m := NewManager(ManagerOptions{Slots: 16})
	t.Cleanup(m.Close)
	slow := `var a = new Uint8Array(40 << 20); setTimeout(function () { $done({url: 'https://e/ok'}); }, 500);`
	var configs []Config
	for _, tag := range []string{"a", "b"} {
		cfg := httpConfig(tag, PhaseRequest, slow)
		cfg.Timeout = 5 * time.Second
		configs = append(configs, cfg)
	}
	if err := m.Apply(configs); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]*Result, 4)
	for i, tag := range []string{"a", "a", "b", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = m.Run(context.Background(), m.Current().Lookup(tag), reqInput("https://e/"))
		}()
	}
	wg.Wait()
	for i, res := range results {
		if res.Action != ActionModify {
			t.Errorf("call %d: %s %s", i, res.Action, res.Error)
		}
	}
}

// Persistent store writes are limited per script and minute; a dry run is not.
func TestStoreWriteRateLimit(t *testing.T) {
	m := newTestManager(t)
	src := `var n = 0; for (var i = 0; i < ` + "700" + `; i++) { if ($persistentStore.write('v', 'k' + (i % 5))) n++; } $done({url: 'https://e/' + n});`
	res := runOne(t, m, httpConfig("w", PhaseRequest, src), reqInput("https://e/"))
	if res.URL != "https://e/"+"600" {
		t.Fatalf("%+v", res)
	}
	// A script with other source starts a new allowance.
	res = runOne(t, m, httpConfig("w", PhaseRequest, `$done({url: 'https://e/' + $persistentStore.remove('k0')})`), reqInput("https://e/"))
	if res.URL != "https://e/true" {
		t.Fatalf("a different source is a different script: %+v", res)
	}
	dry, err := m.Evaluate(context.Background(), httpConfig("w", PhaseRequest, src), reqInput("https://e/"), nil)
	if err != nil || dry.URL != "https://e/700" {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
}

// The globals a script sees are the language built-ins and the documented API; nothing that
// reaches the host. New names fail this test so they get reviewed.
func TestSandboxGlobalsAreWhitelisted(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `$done({url: 'https://e/' + Object.getOwnPropertyNames(globalThis).join(',')});`, time.Second, false)
	if res.Action != ActionModify {
		t.Fatalf("%+v", res)
	}
	got := strings.Split(strings.TrimPrefix(res.URL, "https://e/"), ",")
	allowed := map[string]bool{}
	for _, name := range strings.Fields(sandboxGlobals) {
		allowed[name] = true
	}
	var extra []string
	for _, name := range got {
		if !allowed[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Fatalf("globals outside the whitelist: %v", extra)
	}
	for _, banned := range []string{"require", "process", "fs", "fetch", "XMLHttpRequest", "WebSocket", "importScripts", "module", "exports", "Buffer", "Deno", "Bun", "SharedArrayBuffer", "Atomics", "WebAssembly", "WeakRef", "FinalizationRegistry", "queueMicrotask", "structuredClone", "navigator", "location", "document", "window", "self", "global", "$app"} {
		for _, name := range got {
			if name == banned {
				t.Errorf("global %s is exposed", banned)
			}
		}
	}
}

const sandboxGlobals = `Object Function Array Number parseFloat parseInt Infinity NaN undefined Boolean String Symbol Date Promise RegExp Error AggregateError EvalError RangeError ReferenceError SyntaxError TypeError URIError globalThis JSON Math Intl ArrayBuffer Uint8Array Int8Array Uint8ClampedArray Int16Array Uint16Array Int32Array Uint32Array Float32Array Float64Array BigInt64Array BigUint64Array DataView GoError Map Set WeakMap WeakSet Proxy Reflect decodeURI decodeURIComponent encodeURI encodeURIComponent escape unescape eval isFinite isNaN BigInt console TextEncoder TextDecoder atob btoa setTimeout clearTimeout setInterval clearInterval setImmediate $httpClient $utils $persistentStore $notification $environment $done`

// Tampering with the built-ins or the API object is local to the call that did it.
func TestSandboxTamperingDoesNotLeak(t *testing.T) {
	m := newTestManager(t)
	polluter := httpConfig("p", PhaseRequest, `
Object.prototype.polluted = 'yes';
Array.prototype.push = function () { return -1; };
JSON.parse = function () { return {hacked: true}; };
try { $httpClient.get = function () {}; $httpClient = null; } catch (e) {}
String.prototype.toString = function () { return 'x'; };
$done({url: 'https://e/done'});`)
	victim := httpConfig("v", PhaseRequest, `
var a = []; a.push(1);
$done({url: 'https://e/' + typeof ({}).polluted + a.length + JSON.stringify(JSON.parse('{"a":1}')) + typeof $httpClient.get + String(5)});`)
	if err := m.Apply([]Config{polluter, victim}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if res := m.Run(context.Background(), m.Current().Lookup("p"), reqInput("https://e/")); res.Action != ActionModify {
			t.Fatalf("polluter %d: %+v", i, res)
		}
		res := m.Run(context.Background(), m.Current().Lookup("v"), reqInput("https://e/"))
		if res.URL != `https://e/undefined1{"a":1}function5` {
			t.Fatalf("victim after run %d: %+v", i, res)
		}
	}
	// The polluting script itself starts every call clean.
	again := httpConfig("p2", PhaseRequest, `var seen = typeof ({}).polluted; Object.prototype.polluted = 1; $done({url: 'https://e/' + seen});`)
	if err := m.Apply([]Config{again}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if res := m.Run(context.Background(), m.Current().Lookup("p2"), reqInput("https://e/")); res.URL != "https://e/undefined" {
			t.Fatalf("p2 run %d: %+v", i, res)
		}
	}
}

// Ways around the allocation hooks and the length checks: dynamic property names, the
// Reflect and Proxy built-ins, indirect calls, constructors reached through other objects.
func TestSandboxIndirectAllocation(t *testing.T) {
	for name, src := range map[string]string{
		"reflectConstruct":  `Reflect.construct(Uint8Array, [1 << 30])`,
		"reflectConstructA": `Reflect.construct(Array, [4e9])`,
		"dynamicName":       `this['Uint8' + 'Array'](1 << 30)`,
		"constructorChain":  `new ([].constructor)(4e9).fill(0)`,
		"viaProxy":          `new (new Proxy(Uint8Array, {}))(1 << 30)`,
		"viaBind":           `new (Uint8Array.bind(null))(1 << 30)`,
		"viaCall":           `Array.prototype.map.call({length: 1e9}, function () {})`,
		"viaReflectApply":   `Reflect.apply(Array.prototype.fill, {length: 1e9}, [0])`,
		"viaProxyLength":    `Array.prototype.forEach.call(new Proxy({length: 1e9}, {}), function () {})`,
		"typedFromGetter":   `Array.from({get length() { return 1e9; }})`,
		"repeatDynamic":     `'ab'['re' + 'peat'](1 << 30)`,
		"padDynamic":        `''['padStart'](1 << 30, 'x')`,
		"joinHuge":          `new Array(1e7).join('abcdefghij'.repeat(100))`,
		"arrayBufferSlice":  `new ArrayBuffer(1 << 20).constructor.call ? new ArrayBuffer(1 << 31) : 0`,
		"dataView":          `new DataView(new ArrayBuffer(1 << 31))`,
		"mapDeepSet":        `var m = new Map(); for (var i = 0; ; i++) m.set(i, 'x'.repeat(1 << 16));`,
		"concatLoop":        `var a = 'x'.repeat(1 << 20); for (;;) a = a + a;`,
		"promiseChain":      `var p = Promise.resolve(); for (;;) p = p.then(function () { return new Uint8Array(1 << 24); });`,
	} {
		t.Run(name, func(t *testing.T) {
			res := hardened(t, name, src, 6*time.Second)
			if res.Action == ActionNone || res.Action == ActionModify {
				t.Errorf("%s was not stopped: %+v", name, res)
			}
		})
	}
}

// The Function constructor and eval reach the same sandbox as the script, whichever way they
// are named.
func TestSandboxFunctionConstructorsSeeNoHost(t *testing.T) {
	m := newTestManager(t)
	res := hostile(t, m, `
var names = ['Function', 'eval'];
var g1 = (new Function('return this'))();
var g2 = (0, eval)('this');
var g3 = [].constructor.constructor('return this')();
var g4 = (function () { return this; }).call(undefined);
var g5 = Reflect.construct(Function, ['return this'])();
var g6 = Object.getPrototypeOf(async function () {}).constructor('return this')();
var g7 = (() => this)();
var out = [g1, g2, g3, g4, g5, g6, g7].map(function (g) {
  return [typeof g.process, typeof g.require, typeof g.fetch, typeof g.Go, typeof g.go].join('');
}).join('|');
$done({url: 'https://e/' + out});`, 2*time.Second, false)
	want := strings.Repeat("undefinedundefinedundefinedundefinedundefined|", 6) + "undefinedundefinedundefinedundefinedundefined"
	if res.URL != "https://e/"+want {
		t.Fatalf("%+v", res)
	}
}
