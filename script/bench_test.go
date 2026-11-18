package script

import (
	"context"
	"slices"
	"testing"
	"time"
)

const benchSource = `
var h = $request.headers;
h['X-Bench'] = '1';
$done({headers: h});`

func benchSetup(b testing.TB, source string, requiresBody bool) (*Manager, *Script) {
	m := NewManager(ManagerOptions{})
	cfg := httpConfig("bench", PhaseRequest, source)
	cfg.RequiresBody = requiresBody
	if err := m.Apply([]Config{cfg}); err != nil {
		b.Fatal(err)
	}
	return m, m.Current().Lookup("bench")
}

func benchInput() *Input {
	return reqInput("https://example.com/path?q=1", "Accept", "*/*", "User-Agent", "bench/1.0", "Cookie", "a=b", "Accept-Language", "en")
}

// BenchmarkRunNoBody is a pooled VM running a header-only script.
func BenchmarkRunNoBody(b *testing.B) {
	m, sc := benchSetup(b, benchSource, false)
	defer m.Close()
	in := benchInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res := m.Run(context.Background(), sc, in); res.Action != ActionModify {
			b.Fatal(res.Action, res.Error)
		}
	}
}

// BenchmarkRunColdVM builds a fresh VM for every call (a pool miss).
func BenchmarkRunColdVM(b *testing.B) {
	m, sc := benchSetup(b, benchSource, false)
	defer m.Close()
	in := benchInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.pool.close()
		sc.pool = &pool{}
		if res := m.Run(context.Background(), sc, in); res.Action != ActionModify {
			b.Fatal(res.Action, res.Error)
		}
	}
}

// BenchmarkRunJSONBody parses and rewrites a 100 KiB JSON body.
func BenchmarkRunJSONBody(b *testing.B) {
	m, sc := benchSetup(b, `var o = JSON.parse($request.body); o.x = 1; $done({body: JSON.stringify(o)});`, true)
	defer m.Close()
	body := []byte(`{"items":[`)
	for i := 0; i < 1500; i++ {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, `{"id":1234,"name":"item name","tags":["a","b"],"ok":true}`...)
	}
	body = append(body, `]}`...)
	in := benchInput()
	in.Request.Body, in.Request.HasBody = body, true
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res := m.Run(context.Background(), sc, in); res.Action != ActionModify {
			b.Fatal(res.Action, res.Error)
		}
	}
}

// TestLatencyPercentiles records the distribution of a no-body call. The threshold is the
// contract's p50 <= 2 ms; the check is loose so that a busy machine does not fail it.
func TestLatencyPercentiles(t *testing.T) {
	m, sc := benchSetup(t, benchSource, false)
	defer m.Close()
	in := benchInput()
	for i := 0; i < 50; i++ {
		m.Run(context.Background(), sc, in)
	}
	const n = 2000
	samples := make([]time.Duration, n)
	for i := range samples {
		start := time.Now()
		m.Run(context.Background(), sc, in)
		samples[i] = time.Since(start)
	}
	slices.Sort(samples)
	t.Logf("no-body call: p50=%s p90=%s p99=%s max=%s", samples[n/2], samples[n*9/10], samples[n*99/100], samples[n-1])
	if samples[n/2] > 2*time.Millisecond {
		t.Fatalf("p50 %s exceeds 2ms", samples[n/2])
	}
}
