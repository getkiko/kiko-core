package script

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ruleConfig(tag string, phase Phase, src string) Config {
	return Config{Tag: tag, Type: phase, Source: src}
}

func ruleManager(t testing.TB, configs ...Config) *Manager {
	t.Helper()
	m := newTestManager(t)
	if err := m.Apply(configs); err != nil {
		t.Fatal(err)
	}
	return m
}

func runsOf(m *Manager, tag string) uint64 {
	for _, st := range m.Current().Status() {
		if st.Tag == tag {
			return st.Runs
		}
	}
	return 0
}

func TestRuleScriptValue(t *testing.T) {
	m := ruleManager(t,
		ruleConfig("r", PhaseRule, `$done($request.domain === 'a.example' && $domain === 'a.example' && $request.hostname === $domain && $request.port === 443)`),
		ruleConfig("obj", PhaseRule, `$done({matched: $request.network === 'tcp'})`),
		ruleConfig("none", PhaseRule, `var x = 1;`),
		ruleConfig("bad", PhaseRule, `$done('yes')`),
	)
	in := &RuleInput{Domain: "a.example", Port: 443, Network: "tcp"}
	if out := m.RunRule("r", in); out.Err != "" || !out.Matched {
		t.Fatalf("r: %+v", out)
	}
	if out := m.RunRule("r", &RuleInput{Domain: "b.example", Port: 443}); out.Err != "" || out.Matched {
		t.Fatalf("r other: %+v", out)
	}
	if out := m.RunRule("obj", in); out.Err != "" || !out.Matched {
		t.Fatalf("obj: %+v", out)
	}
	if out := m.RunRule("none", in); out.Err != "" || out.Matched {
		t.Fatalf("none: %+v", out)
	}
	if out := m.RunRule("bad", in); out.Err == "" || out.Matched {
		t.Fatalf("bad: %+v", out)
	}
}

func TestRuleScriptUnknownAndWrongType(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done(true)`), ruleConfig("d", PhaseDNS, `$done()`))
	if out := m.RunRule("missing", &RuleInput{}); out.Err == "" || out.Matched {
		t.Fatalf("missing: %+v", out)
	}
	if out := m.RunRule("d", &RuleInput{}); out.Err == "" || out.Matched {
		t.Fatalf("dns script used as rule: %+v", out)
	}
	if out := m.RunDNS("r", &RuleInput{}); out.Err == "" || out.Decision.Kind != DNSPass {
		t.Fatalf("rule script used as dns: %+v", out)
	}
}

func TestRuleScriptCache(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done($request.domain.length > 3)`))
	now := time.Unix(1_000_000, 0)
	m.clock = func() time.Time { return now }
	in := &RuleInput{Domain: "abcd.example"}

	first := m.RunRule("r", in)
	if first.Err != "" || !first.Matched || first.Cached {
		t.Fatalf("first: %+v", first)
	}
	second := m.RunRule("r", in)
	if !second.Matched || !second.Cached {
		t.Fatalf("second should come from the cache: %+v", second)
	}
	if n := runsOf(m, "r"); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
	// Another input is another entry.
	if out := m.RunRule("r", &RuleInput{Domain: "ab"}); out.Matched || out.Cached {
		t.Fatalf("other input: %+v", out)
	}
	if n := runsOf(m, "r"); n != 2 {
		t.Fatalf("runs = %d, want 2", n)
	}
	// Still cached just before 60 s, run again after.
	now = now.Add(RuleCacheTTL - time.Second)
	if out := m.RunRule("r", in); !out.Cached {
		t.Fatalf("59 s: %+v", out)
	}
	now = now.Add(2 * time.Second)
	if out := m.RunRule("r", in); out.Cached || !out.Matched {
		t.Fatalf("61 s: %+v", out)
	}
	if n := runsOf(m, "r"); n != 3 {
		t.Fatalf("runs = %d, want 3", n)
	}
}

func TestRuleScriptCacheKeyedOnScript(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done(true)`))
	in := &RuleInput{Domain: "x.example"}
	if out := m.RunRule("r", in); !out.Matched {
		t.Fatalf("v1: %+v", out)
	}
	// A reload with other source must not be answered from the old outcome.
	if err := m.Apply([]Config{ruleConfig("r", PhaseRule, `$done(false)`)}); err != nil {
		t.Fatal(err)
	}
	if out := m.RunRule("r", in); out.Matched || out.Cached || out.Err != "" {
		t.Fatalf("v2: %+v", out)
	}
	// The argument is part of the script too.
	cfg := ruleConfig("r", PhaseRule, `$done($argument === 'on')`)
	cfg.Argument = "on"
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	if out := m.RunRule("r", in); !out.Matched || out.Cached {
		t.Fatalf("v3: %+v", out)
	}
	cfg.Argument = "off"
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	if out := m.RunRule("r", in); out.Matched || out.Cached {
		t.Fatalf("v4: %+v", out)
	}
}

func TestRuleScriptJoinsIdenticalCalls(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `setTimeout(function () { $done(true) }, 30)`))
	var wg sync.WaitGroup
	var matched, cached atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := m.RunRule("r", &RuleInput{Domain: "same.example"})
			if out.Err == "" && out.Matched {
				matched.Add(1)
			}
			if out.Cached {
				cached.Add(1)
			}
		}()
	}
	within(t, 5*time.Second, wg.Wait)
	if matched.Load() != 24 {
		t.Fatalf("matched %d of 24", matched.Load())
	}
	if n := runsOf(m, "r"); n != 1 {
		t.Fatalf("runs = %d, want 1 (identical calls share one run)", n)
	}
	if cached.Load() != 23 {
		t.Fatalf("cached %d, want 23", cached.Load())
	}
}

func TestRuleScriptTimeout(t *testing.T) {
	cfg := ruleConfig("loop", PhaseRule, `while (true) {}`)
	cfg.Timeout = 50 * time.Millisecond
	m := ruleManager(t, cfg)
	begin := time.Now()
	out := m.RunRule("loop", &RuleInput{Domain: "t.example"})
	took := time.Since(begin)
	if out.Matched || !strings.Contains(out.Err, "timed out") {
		t.Fatalf("outcome: %+v", out)
	}
	if took > 1500*time.Millisecond {
		t.Fatalf("a 50 ms script took %s", took)
	}
	// The failure is cached for the same input: the loop does not run again.
	again := m.RunRule("loop", &RuleInput{Domain: "t.example"})
	if !again.Cached || again.Err == "" {
		t.Fatalf("again: %+v", again)
	}
	if n := runsOf(m, "loop"); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
	// A timed out VM is not reused, and the next input runs normally on a fresh one.
	if err := m.Apply([]Config{cfg, ruleConfig("ok", PhaseRule, `$done(true)`)}); err != nil {
		t.Fatal(err)
	}
	if out := m.RunRule("ok", &RuleInput{}); !out.Matched {
		t.Fatalf("ok: %+v", out)
	}
}

func TestRuleScriptDefaultTimeoutIs100ms(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done(true)`), ruleConfig("d", PhaseDNS, `$done()`))
	for _, tag := range []string{"r", "d"} {
		if got := m.Current().Lookup(tag).Config().Timeout; got != 100*time.Millisecond {
			t.Fatalf("%s timeout = %s", tag, got)
		}
	}
	long := ruleConfig("long", PhaseRule, `$done(true)`)
	long.Timeout = 2 * time.Second
	if err := m.Apply([]Config{long}); err == nil {
		t.Fatal("a rule script timeout above 1s must be rejected")
	}
	withPattern := ruleConfig("p", PhaseRule, `$done(true)`)
	withPattern.Pattern = ".*"
	if err := m.Apply([]Config{withPattern}); err == nil {
		t.Fatal("a rule script takes no pattern")
	}
	withBody := ruleConfig("b", PhaseDNS, `$done()`)
	withBody.RequiresBody = true
	if err := m.Apply([]Config{withBody}); err == nil {
		t.Fatal("a dns script takes no body")
	}
}

// The first run of a script builds its VM; this records what that costs and holds it to a
// fraction of the 100 ms budget, so that a cold start never decides a rule on its own.
func TestRuleScriptColdStart(t *testing.T) {
	var worst time.Duration
	for i := 0; i < 5; i++ {
		m := NewManager(ManagerOptions{})
		if err := m.Apply([]Config{ruleConfig("r", PhaseRule, `$done($request.domain.endsWith('.example'))`)}); err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		out := m.RunRule("r", &RuleInput{Domain: "cold.example"})
		took := time.Since(begin)
		if out.Err != "" || !out.Matched {
			t.Fatalf("outcome: %+v", out)
		}
		if took > worst {
			worst = took
		}
		m.Close()
	}
	t.Logf("cold start of a rule script: worst of 5 = %s (budget 100ms)", worst)
	if worst > 50*time.Millisecond {
		t.Fatalf("cold start %s uses over half of the 100 ms budget", worst)
	}
}

func TestRuleScriptBreaker(t *testing.T) {
	m := ruleManager(t, ruleConfig("bad", PhaseRule, `throw new Error('boom')`))
	now := time.Unix(2_000_000, 0)
	m.clock = func() time.Time { return now }
	for i := 0; i < RuleBreakerFailures; i++ {
		out := m.RunRule("bad", &RuleInput{Domain: "d" + strconv.Itoa(i)})
		if out.Err == "" || !strings.Contains(out.Err, "boom") {
			t.Fatalf("run %d: %+v", i, out)
		}
	}
	if n := runsOf(m, "bad"); n != RuleBreakerFailures {
		t.Fatalf("runs = %d", n)
	}
	out := m.RunRule("bad", &RuleInput{Domain: "next"})
	if out.Err != errBreaker || out.Matched {
		t.Fatalf("breaker: %+v", out)
	}
	if n := runsOf(m, "bad"); n != RuleBreakerFailures {
		t.Fatalf("the open breaker must not run the script (runs = %d)", n)
	}
	// After the pause the script runs again.
	now = now.Add(RuleBreakerPause + time.Second)
	out = m.RunRule("bad", &RuleInput{Domain: "later"})
	if !strings.Contains(out.Err, "boom") {
		t.Fatalf("after the pause: %+v", out)
	}
}

type countingHTTP struct{ calls atomic.Int32 }

func (c *countingHTTP) Do(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	c.calls.Add(1)
	return &HTTPResponse{Status: 200}, nil
}

func TestRuleScriptHTTPClientRefused(t *testing.T) {
	m := ruleManager(t,
		ruleConfig("r", PhaseRule, `$httpClient.get('https://example.com/', function () { $done(true) })`),
		ruleConfig("d", PhaseDNS, `$httpClient.post({url: 'https://example.com/'}, function () { $done({address: '1.1.1.1'}) })`),
	)
	client := &countingHTTP{}
	m.SetHTTPClient(client)
	out := m.RunRule("r", &RuleInput{Domain: "a.example"})
	if out.Matched || !strings.Contains(out.Err, "not available in rule and dns scripts") {
		t.Fatalf("rule: %+v", out)
	}
	dns := m.RunDNS("d", &RuleInput{Domain: "a.example", QueryType: "A"})
	if dns.Decision.Kind != DNSPass || !strings.Contains(dns.Err, "not available in rule and dns scripts") {
		t.Fatalf("dns: %+v", dns)
	}
	if client.calls.Load() != 0 {
		t.Fatalf("the HTTP client was called %d times", client.calls.Load())
	}
}

func TestRuleScriptCloseEndsRunningCall(t *testing.T) {
	cfg := ruleConfig("loop", PhaseRule, `while (true) {}`)
	cfg.Timeout = time.Second
	m := NewManager(ManagerOptions{})
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *RuleOutcome, 1)
	go func() { done <- m.RunRule("loop", &RuleInput{Domain: "x"}) }()
	time.Sleep(50 * time.Millisecond)
	begin := time.Now()
	m.Close()
	select {
	case out := <-done:
		if out.Matched || out.Err == "" {
			t.Fatalf("outcome: %+v", out)
		}
		if time.Since(begin) > 500*time.Millisecond {
			t.Fatalf("Close took %s to end the call", time.Since(begin))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the call outlived Close")
	}
}

func TestRuleScriptDoesNotQueueBehindHTTPScripts(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done(true)`))
	for i := 0; i < cap(m.slots); i++ {
		m.slots <- struct{}{}
	}
	begin := time.Now()
	out := m.RunRule("r", &RuleInput{Domain: "busy.example"})
	if !out.Matched || out.Err != "" {
		t.Fatalf("outcome with the shared slots taken: %+v", out)
	}
	if time.Since(begin) > time.Second {
		t.Fatalf("took %s", time.Since(begin))
	}
}

func TestRuleScriptBusyIsNotCached(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done(true)`))
	for i := 0; i < cap(m.ruleSlots); i++ {
		m.ruleSlots <- struct{}{}
	}
	out := m.RunRule("r", &RuleInput{Domain: "busy.example"})
	if out.Err != errBusy || out.Matched {
		t.Fatalf("busy: %+v", out)
	}
	for i := 0; i < cap(m.ruleSlots); i++ {
		<-m.ruleSlots
	}
	out = m.RunRule("r", &RuleInput{Domain: "busy.example"})
	if out.Err != "" || !out.Matched {
		t.Fatalf("after the slots are free the same input runs: %+v", out)
	}
}

func TestRuleCacheBounded(t *testing.T) {
	c := newRuleCache()
	now := time.Unix(3_000_000, 0)
	for i := 0; i < RuleCacheEntries*2; i++ {
		key := "k" + strconv.Itoa(i)
		e, leader := c.enter(key, now)
		if !leader {
			t.Fatalf("%s: not a leader", key)
		}
		c.finish(key, e, ruleRun{output: "true"}, RuleCacheTTL, now)
		if n := c.size(); n > RuleCacheEntries {
			t.Fatalf("size %d after %d inserts", n, i+1)
		}
	}
}

func TestRuleCacheTransientNotKept(t *testing.T) {
	c := newRuleCache()
	now := time.Unix(3_000_000, 0)
	e, _ := c.enter("k", now)
	c.finish("k", e, ruleRun{err: errBusy}, 0, now)
	if c.size() != 0 {
		t.Fatalf("size = %d", c.size())
	}
}

func TestParseRuleOutput(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    bool
		wantErr bool
	}{
		{"", false, false},
		{"null", false, false},
		{"true", true, false},
		{"false", false, false},
		{`{"matched":true}`, true, false},
		{`{"match":true}`, true, false},
		{`{"matched":false,"match":true}`, false, false},
		{`{}`, false, false},
		{`{"matched":"yes"}`, false, true},
		{`"yes"`, false, true},
		{`1`, false, true},
		{`[true]`, false, true},
		{`{`, false, true},
	} {
		got, err := ParseRuleOutput(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("%q: got %v, %v", tc.in, got, err)
		}
	}
}

func TestParseDNSOutput(t *testing.T) {
	ok := func(in string) DNSDecision {
		t.Helper()
		d, err := ParseDNSOutput(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		return d
	}
	if d := ok(``); d.Kind != DNSPass {
		t.Fatalf("empty: %+v", d)
	}
	if d := ok(`{}`); d.Kind != DNSPass {
		t.Fatalf("{}: %+v", d)
	}
	for _, in := range []string{`{"addresses":null}`, `{"address":null,"rcode":null}`, `{"ttl":null}`, `{"server":null,"addresses":null,"ttl":null}`} {
		if d := ok(in); d.Kind != DNSPass {
			t.Fatalf("%s: %+v", in, d)
		}
	}
	if d := ok(`{"server":null,"address":"1.1.1.1"}`); d.Kind != DNSAnswer || len(d.Addresses) != 1 {
		t.Fatalf("null server with address: %+v", d)
	}
	if d := ok(`{"ttl":5}`); d.Kind != DNSPass {
		t.Fatalf("ttl only: %+v", d)
	}
	d := ok(`{"addresses":["1.2.3.4","::ffff:5.6.7.8","2001:db8::1"],"ttl":30}`)
	if d.Kind != DNSAnswer || len(d.Addresses) != 3 || d.TTL != 30 || !d.Addresses[1].Is4() {
		t.Fatalf("addresses: %+v", d)
	}
	if d := ok(`{"address":"9.9.9.9"}`); d.Kind != DNSAnswer || d.TTL != 60 || len(d.Addresses) != 1 {
		t.Fatalf("address: %+v", d)
	}
	if d := ok(`{"addresses":[]}`); d.Kind != DNSAnswer || len(d.Addresses) != 0 || d.Summary() != "empty answer" {
		t.Fatalf("empty list: %+v", d)
	}
	if d := ok(`{"rcode":"nxdomain"}`); d.Kind != DNSAnswer || d.Rcode != 3 || d.Summary() != "NXDOMAIN" {
		t.Fatalf("rcode: %+v", d)
	}
	if d := ok(`{"rcode":2}`); d.Rcode != 2 {
		t.Fatalf("rcode number: %+v", d)
	}
	if d := ok(`{"server":"local"}`); d.Kind != DNSServer || d.Server != "local" {
		t.Fatalf("server: %+v", d)
	}
	for _, bad := range []string{
		`true`, `"1.1.1.1"`, `{"addresses":"1.1.1.1"}`, `{"addresses":["nope"]}`, `{"ttl":-1}`, `{"ttl":999999}`,
		`{"rcode":"BOGUS"}`, `{"rcode":9}`, `{"server":"a","addresses":["1.1.1.1"]}`, `{"server":""}`,
		`{"rcode":"NXDOMAIN","addresses":["1.1.1.1"]}`,
	} {
		if d, err := ParseDNSOutput(bad); err == nil || d.Kind != DNSPass {
			t.Errorf("%q: want an error, got %+v", bad, d)
		}
	}
}

func TestDNSScriptRun(t *testing.T) {
	m := ruleManager(t, ruleConfig("d", PhaseDNS, `
		if ($request.domain === 'block.example') { $done({rcode: 'NXDOMAIN'}); }
		else if ($domain === 'fast.example' && $request.queryType === 'A') { $done({addresses: ['10.0.0.1'], ttl: 120}); }
		else if ($domain === 'via.example') { $done({server: 'doh'}); }
	`))
	run := func(domain, qtype string) *DNSOutcome {
		return m.RunDNS("d", &RuleInput{Domain: domain, QueryType: qtype})
	}
	if out := run("fast.example", "A"); out.Err != "" || out.Decision.Kind != DNSAnswer || out.Decision.TTL != 120 || out.Decision.Addresses[0].String() != "10.0.0.1" {
		t.Fatalf("fast: %+v", out)
	}
	if out := run("fast.example", "AAAA"); out.Decision.Kind != DNSPass {
		t.Fatalf("fast AAAA: %+v", out)
	}
	if out := run("block.example", "A"); out.Decision.Rcode != 3 {
		t.Fatalf("block: %+v", out)
	}
	if out := run("via.example", "A"); out.Decision.Kind != DNSServer || out.Decision.Server != "doh" {
		t.Fatalf("via: %+v", out)
	}
	if out := run("other.example", "A"); out.Decision.Kind != DNSPass || out.Err != "" {
		t.Fatalf("other: %+v", out)
	}
	if out := run("fast.example", "A"); !out.Cached {
		t.Fatalf("repeat should be cached: %+v", out)
	}
}

func BenchmarkRuleScriptCacheHit(b *testing.B) {
	m := ruleManager(b, ruleConfig("r", PhaseRule, `$done($request.domain === 'a.example')`))
	in := &RuleInput{Domain: "a.example", Port: 443, Network: "tcp"}
	m.RunRule("r", in)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RunRule("r", in)
	}
}

func BenchmarkRuleScriptRun(b *testing.B) {
	m := ruleManager(b, ruleConfig("r", PhaseRule, `$done($request.domain === 'a.example')`))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RunRule("r", &RuleInput{Domain: "d" + strconv.Itoa(i) + ".example"})
		if i%2048 == 0 {
			m.ruleCache.clear()
		}
	}
}

func TestRuleScriptOversizedOutputNotCached(t *testing.T) {
	m := ruleManager(t, ruleConfig("r", PhaseRule, `$done("x".repeat(70000))`))
	in := &RuleInput{Domain: "x.example"}
	out := m.RunRule("r", in)
	if out.Err == "" || out.Matched {
		t.Fatalf("oversized value must fail: %+v", out)
	}
	m.ruleCache.mu.Lock()
	defer m.ruleCache.mu.Unlock()
	for key, e := range m.ruleCache.entries {
		if len(e.run.output) > maxRuleOutput {
			t.Fatalf("cache keeps %d bytes under %q", len(e.run.output), key)
		}
	}
}

func TestRuleScriptCacheKeyedOnTag(t *testing.T) {
	src := `$done($script.name === "a")`
	a := ruleConfig("a", PhaseRule, src)
	b := ruleConfig("b", PhaseRule, src)
	m := ruleManager(t, a, b)
	in := &RuleInput{Domain: "x.example"}
	if out := m.RunRule("a", in); !out.Matched {
		t.Fatalf("a: %+v", out)
	}
	if out := m.RunRule("b", in); out.Matched || out.Cached {
		t.Fatalf("b must not reuse a's outcome: %+v", out)
	}
}
