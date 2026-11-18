package script

// Process memory measurements of the script runtime (package R, r1). Skipped unless
// KIKO_SCRIPT_MEM_CASE is set; every case runs in its own process so that the peak RSS
// (getrusage maxrss) belongs to the case. scripts/script-mem.sh drives the cases.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func memMaxRSS() int64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	if runtime.GOOS == "linux" {
		return ru.Maxrss << 10
	}
	return ru.Maxrss
}

func memRSS() int64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return -1
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return v << 10
}

func memEnvInt(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return fallback
}

// memPeakWatcher samples the current RSS every 10 ms and keeps the largest, because maxrss
// never falls and cannot show the plateau between phases.
type memPeakWatcher struct {
	stop chan struct{}
	done chan struct{}
	peak int64
}

func startMemWatcher() *memPeakWatcher {
	w := &memPeakWatcher{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				return
			case <-time.After(20 * time.Millisecond):
				if v := memRSS(); v > w.peak {
					w.peak = v
					if v > 2560<<20 {
						// Keep the shared build machine alive: report and die.
						fmt.Printf("ABORT rss=%.0f MiB over the 2.5 GiB guard\n", float64(v)/(1<<20))
						os.Exit(3)
					}
				}
			}
		}
	}()
	return w
}

func (w *memPeakWatcher) finish() int64 {
	close(w.stop)
	<-w.done
	return w.peak
}

func memReport(name string, baseline int64, extra string) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Printf("RESULT case=%s baseline_rss_mib=%.1f peak_rss_mib=%.1f end_rss_mib=%.1f heap_sys_mib=%.1f sys_mib=%.1f %s\n",
		name, float64(baseline)/(1<<20), float64(memMaxRSS())/(1<<20), float64(memRSS())/(1<<20), float64(ms.HeapSys)/(1<<20), float64(ms.Sys)/(1<<20), extra)
}

func memSettle() {
	runtime.GC()
	debug.FreeOSMemory()
	time.Sleep(200 * time.Millisecond)
}

var memBigJSON = func() []byte {
	body := []byte(`{"items":[`)
	for i := 0; i < 30000; i++ {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, `{"id":1234,"name":"item name","tags":["a","b"],"ok":true}`...)
	}
	return append(body, `]}`...)
}()

func TestScriptMemoryR1(t *testing.T) {
	name := os.Getenv("KIKO_SCRIPT_MEM_CASE")
	if name == "" {
		t.Skip("set KIKO_SCRIPT_MEM_CASE")
	}
	n := memEnvInt("KIKO_SCRIPT_MEM_N", 1)
	slots := memEnvInt("KIKO_SCRIPT_MEM_SLOTS", 0)
	memSettle()
	baseline := memRSS()
	watcher := startMemWatcher()
	defer func() {
		peak := watcher.finish()
		memSettle()
		memReport(name+fmt.Sprintf("/n=%d/slots=%d", n, slots), baseline, fmt.Sprintf("sampled_peak_rss_mib=%.1f", float64(peak)/(1<<20)))
	}()
	m := NewManager(ManagerOptions{Slots: slots})
	defer m.Close()

	switch name {
	case "idle":
		// n distinct scripts, each run once so a VM is pooled.
		var cfgs []Config
		for i := 0; i < n; i++ {
			cfgs = append(cfgs, httpConfig(fmt.Sprintf("s%d", i), PhaseRequest, fmt.Sprintf(`var h = $request.headers; h['X-%d'] = '1'; $done({headers: h});`, i)))
		}
		if err := m.Apply(cfgs); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			res := m.Run(context.Background(), m.Current().Lookup(fmt.Sprintf("s%d", i)), benchInput())
			if res.Action != ActionModify {
				t.Fatal(res.Action, res.Error)
			}
		}
	case "json":
		// n concurrent calls, each parsing and re-serializing a ~1.7 MiB JSON body.
		cfg := httpConfig("j", PhaseRequest, `var o = JSON.parse($request.body); o.x = 1; $done({body: JSON.stringify(o)});`)
		cfg.RequiresBody = true
		cfg.MaxSize = MaxMaxSize
		if err := m.Apply([]Config{cfg}); err != nil {
			t.Fatal(err)
		}
		sc := m.Current().Lookup("j")
		var wg sync.WaitGroup
		for round := 0; round < 3; round++ {
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					in := benchInput()
					in.Request.Body, in.Request.HasBody = memBigJSON, true
					if res := m.Run(context.Background(), sc, in); res.Action != ActionModify {
						fmt.Println("json run:", res.Action, res.Error)
					}
				}()
			}
			wg.Wait()
		}
		fmt.Printf("body_bytes=%d\n", len(memBigJSON))
	case "httpclient", "httpclient-binary":
		// n script calls at once, each starting 16 requests (4 in flight per call); the client
		// answers with 8 MiB once `target` requests wait together.
		target := memEnvInt("KIKO_SCRIPT_MEM_TARGET", 64)
		var mu sync.Mutex
		waiting := 0
		release := make(chan struct{})
		var releaseOnce sync.Once
		peakWaiting := 0
		client := &fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
			mu.Lock()
			waiting++
			peakWaiting = max(peakWaiting, waiting)
			if waiting >= target {
				releaseOnce.Do(func() { close(release) })
			}
			mu.Unlock()
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
			}
			mu.Lock()
			waiting--
			mu.Unlock()
			return &HTTPResponse{Status: 200, Body: make([]byte, 8<<20)}, nil
		}}
		m.SetHTTPClient(client)
		binary := ""
		if name == "httpclient-binary" {
			binary = ", 'binary-mode': true"
		}
		src := fmt.Sprintf(`
var left = 16, total = 0;
for (var i = 0; i < 16; i++) {
  $httpClient.get({url: 'https://a.example/' + i%s}, function (err, resp, data) {
    if (data) total += data.length || data.byteLength || 0;
    if (--left === 0) $done({headers: {'X-Total': String(total)}});
  });
}`, binary)
		cfg := httpConfig("h", PhaseRequest, src)
		cfg.Timeout = 30 * time.Second
		if err := m.Apply([]Config{cfg}); err != nil {
			t.Fatal(err)
		}
		sc := m.Current().Lookup("h")
		var wg sync.WaitGroup
		results := make([]*Result, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = m.Run(context.Background(), sc, benchInput())
			}()
		}
		wg.Wait()
		actions := map[Action]int{}
		for _, r := range results {
			actions[r.Action]++
		}
		fmt.Printf("peak_waiting=%d calls=%d actions=%v first_error=%q\n", peakWaiting, n, actions, results[0].Error)
	default:
		src, ok := memHostile[name]
		if !ok {
			t.Fatalf("unknown case %q", name)
		}
		cfg := httpConfig("evil", PhaseRequest, src)
		cfg.Timeout = 5 * time.Second
		if err := m.Apply([]Config{cfg}); err != nil {
			t.Fatal(err)
		}
		sc := m.Current().Lookup("evil")
		var wg sync.WaitGroup
		results := make([]*Result, n)
		start := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = m.Run(context.Background(), sc, benchInput())
			}()
		}
		wg.Wait()
		actions := map[Action]int{}
		for _, r := range results {
			actions[r.Action]++
		}
		fmt.Printf("elapsed=%s actions=%v first_error=%q\n", time.Since(start).Round(time.Millisecond), actions, results[0].Error)
	}
}

// memHostile are scripts that try to exhaust memory.
var memHostile = map[string]string{
	"huge-array":          `var a = new Array(1e9); a.fill(1); $done({});`,
	"array-push":          `var a = []; while (true) a.push({x: a.length, y: 'abcdefghij'});`,
	"array-int-push":      `var a = []; while (true) a.push(1);`,
	"string-double":       `var s = 'x'; while (true) s += s;`,
	"string-repeat":       `var s = 'x'.repeat(1 << 29); $done({body: s});`,
	"string-concat":       `var s = ''; for (var i = 0; i < 1e8; i++) s += 'abcdefghijklmnopqrstuvwxyz';`,
	"arraybuffer":         `var b = new ArrayBuffer(2e9); $done({});`,
	"typed-chain":         `var l = []; for (var i = 0; i < 1000; i++) l.push(new Uint8Array(32 << 20)); $done({});`,
	"object-churn":        `var l = []; while (true) { l.push({a: [1,2,3], b: {c: 'd'}}); }`,
	"churn-no-keep":       `var t = 0; for (var i = 0; i < 3e7; i++) { var o = {a: [i, i], s: 'x' + i}; t += o.a.length; } $done({});`,
	"regex-backtrack":     `var s = ''; for (var i = 0; i < 40; i++) s += 'a'; /^(a+)+$/.test(s + 'b'); $done({});`,
	"regex-big-match":     `var s = 'ab'.repeat(500000); var m = s.match(/a/g); $done({});`,
	"regex-replace-fn":    `var s = 'ab'.repeat(500000); s.replace(/a/g, function (x) { return x + x; }); $done({});`,
	"split-bomb":          `var s = 'a,'.repeat(500000); var p = s.split(','); var q = []; for (var i = 0; i < 100; i++) q.push(p.slice()); $done({});`,
	"json-deep":           `var s = '['.repeat(100000) + ']'.repeat(100000); JSON.parse(s); $done({});`,
	"json-stringify-bomb": `var a = [1]; for (var i = 0; i < 40; i++) a = [a, a]; JSON.stringify(a); $done({});`,
	"map-set":             `var m = new Map(); var i = 0; while (true) m.set(i, 'v' + i++);`,
	"closure-chain":       `var f = function () { return 1; }; while (true) { var g = f; f = (function (h) { return function () { return h() + 1; }; })(g); }`,
}
