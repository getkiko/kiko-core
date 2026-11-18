package script

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentRunsKeepVMsIsolated(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseRequest, `
var n = $request.url.split('/').pop();
var h = $request.headers;
h['X-N'] = n;
leaked = n;
$done({headers: h});`)
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				n := strings.Repeat("x", i+1)
				res := m.Run(context.Background(), sc, reqInput("https://e/"+n, "Accept", "*/*"))
				if res.Action != ActionModify || headerValue(res.Headers, "X-N") != n {
					bad.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d wrong results", bad.Load())
	}
	if idle := m.Current().Status()[0].IdleVMs; idle > PoolSize {
		t.Fatalf("pool holds %d VMs", idle)
	}
}

func TestInFlightCallsFinishOnOldSet(t *testing.T) {
	m := newTestManager(t)
	slow := httpConfig("a", PhaseRequest, `setTimeout(function(){ $done({url: 'https://old/'}) }, 200)`)
	if err := m.Apply([]Config{slow}); err != nil {
		t.Fatal(err)
	}
	old := m.Current().Lookup("a")
	done := make(chan *Result)
	go func() { done <- m.Run(context.Background(), old, reqInput("https://e/")) }()
	time.Sleep(50 * time.Millisecond)
	if err := m.Apply([]Config{httpConfig("a", PhaseRequest, `$done({url: 'https://new/'})`)}); err != nil {
		t.Fatal(err)
	}
	res := m.Run(context.Background(), m.Current().Lookup("a"), reqInput("https://e/"))
	if res.URL != "https://new/" {
		t.Fatalf("%+v", res)
	}
	if res := <-done; res.URL != "https://old/" {
		t.Fatalf("%+v", res)
	}
}

func TestVMReuseAndCap(t *testing.T) {
	m := newTestManager(t)
	if err := m.Apply([]Config{httpConfig("a", PhaseRequest, `setTimeout(function(){ $done({}) }, 30)`)}); err != nil {
		t.Fatal(err)
	}
	sc := m.Current().Lookup("a")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.Run(context.Background(), sc, reqInput("https://e/")) }()
	}
	wg.Wait()
	if idle := sc.pool.idleCount(); idle != PoolSize {
		t.Fatalf("idle VMs %d, want %d", idle, PoolSize)
	}
}

func TestCancelStopsCall(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("a", PhaseRequest, `while (true) {}`)
	cfg.Timeout = 10 * time.Second
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := m.Run(ctx, m.Current().Lookup("a"), reqInput("https://e/"))
	if res.Action != ActionSkipped || res.Reason != ReasonCanceled || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %s", res, time.Since(start))
	}
}

func TestValidation(t *testing.T) {
	bad := map[string]Config{
		"tag":      {Tag: "a b", Type: PhaseRequest, Pattern: ".*", Source: "1"},
		"type":     {Tag: "a", Type: "cron", Pattern: ".*", Source: "1"},
		"pattern":  {Tag: "a", Type: PhaseRequest, Source: "1"},
		"regex":    {Tag: "a", Type: PhaseRequest, Pattern: "(", Source: "1"},
		"generic":  {Tag: "a", Type: PhaseGeneric, Pattern: ".*", Source: "1"},
		"source":   {Tag: "a", Type: PhaseRequest, Pattern: ".*", Source: " "},
		"syntax":   {Tag: "a", Type: PhaseRequest, Pattern: ".*", Source: "var ="},
		"timeout":  {Tag: "a", Type: PhaseRequest, Pattern: ".*", Source: "1", Timeout: 31 * time.Second},
		"max_size": {Tag: "a", Type: PhaseRequest, Pattern: ".*", Source: "1", MaxSize: MaxMaxSize + 1},
	}
	for name, cfg := range bad {
		if _, err := compileSet([]Config{cfg}, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := compileSet([]Config{{Tag: "a", Type: PhaseGeneric, Source: "1", Timeout: time.Minute}}, nil); err != nil {
		t.Errorf("generic timeout 60s: %v", err)
	}
}

func TestMemoryStoreLimits(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Set("ns", "k", strings.Repeat("v", MaxStoreValue+1)); err == nil {
		t.Fatal("oversize value accepted")
	}
	for i := 0; i < 16; i++ {
		if err := s.Set("ns", "k"+string(rune('a'+i)), strings.Repeat("v", MaxStoreValue)); err != nil {
			if i < 15 {
				t.Fatalf("write %d: %v", i, err)
			}
			return
		}
	}
	t.Fatal("total limit not enforced")
}

func FuzzSplitSetCookie(f *testing.F) {
	f.Add("a=1; Path=/, b=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT")
	f.Add(",,,=,")
	f.Fuzz(func(t *testing.T, s string) {
		parts := splitSetCookie(s)
		if len(parts) == 0 {
			t.Fatal("no parts")
		}
		if strings.Join(parts, "") == "" && s != "" && strings.Trim(s, ", \t") != "" {
			t.Fatal("content lost")
		}
	})
}

func FuzzScriptSource(f *testing.F) {
	f.Add("var a = 1;")
	f.Add("(((((")
	f.Add("function(){")
	f.Add("/[/*]/((((((")
	f.Add("/a\\//((((")
	f.Add("/'/;var x=1+1+1")
	f.Add("var r = /\\/\\*/g; `${a/b}` // '")
	f.Add("a/b/c; /*/ /\"/")
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 4096 {
			return
		}
		// Compiling arbitrary text must neither panic nor hang.
		_, _ = compileSet([]Config{{Tag: "a", Type: PhaseRequest, Pattern: ".*", Source: src}}, nil)
	})
}
