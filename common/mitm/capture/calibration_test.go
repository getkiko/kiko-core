package capture

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/flow"
)

// typicalExchange adds a finished record shaped like browser traffic. Every
// string is a fresh allocation, as in the engine.
func typicalExchange(m *Manager, conn *flow.ConnectionInfo, i int) {
	x := m.NewExchange(conn)
	reqHeaders := make([]flow.Header, 0, 14)
	for _, h := range [][2]string{
		{"Host", "api.example.com"}, {"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
		{"Accept", "application/json, text/plain, */*"}, {"Accept-Language", "en-US,en;q=0.9"}, {"Accept-Encoding", "gzip, deflate, br"},
		{"Referer", "https://www.example.com/dashboard"}, {"Origin", "https://www.example.com"},
		{"Content-Type", "application/json"}, {"Content-Length", "128"}, {"Cache-Control", "no-cache"},
		{"Sec-Fetch-Site", "same-site"}, {"Sec-Fetch-Mode", "cors"}, {"Sec-Fetch-Dest", "empty"},
	} {
		reqHeaders = append(reqHeaders, flow.Header{Name: strings.Clone(h[0]), Value: h[1] + fmt.Sprint(i%10)})
	}
	x.RequestHead(flow.RequestHead{
		Method: "GET", Scheme: "https", Authority: "api.example.com", Path: fmt.Sprintf("/v1/items/%d?page=%d&limit=50", i, i%7),
		Proto: "h2", Headers: reqHeaders,
	})
	respHeaders := make([]flow.Header, 0, 10)
	for _, h := range [][2]string{
		{"Content-Type", "application/json; charset=utf-8"}, {"Content-Length", "2048"}, {"Server", "nginx"},
		{"Date", "Mon, 02 Jan 2006 15:04:05 GMT"}, {"Cache-Control", "private, max-age=0"}, {"Vary", "Accept-Encoding"},
		{"X-Request-Id", "5f0c9d2e-8f6a-4a43-9f63-0a1b2c3d4e5f"}, {"Strict-Transport-Security", "max-age=31536000"},
	} {
		respHeaders = append(respHeaders, flow.Header{Name: h[0], Value: h[1] + fmt.Sprint(i%10)})
	}
	x.ResponseHead(200, respHeaders)
	x.Finish(nil)
}

// minimalExchange is a record with a bare request and response.
func minimalExchange(m *Manager, conn *flow.ConnectionInfo, i int) {
	x := m.NewExchange(conn)
	x.RequestHead(flow.RequestHead{
		Method: "GET", Scheme: "http", Authority: "a.test", Path: "/" + fmt.Sprint(i), Proto: "http/1.1",
		Headers: []flow.Header{{Name: "Host", Value: "a.test"}},
	})
	x.ResponseHead(204, nil)
	x.Finish(nil)
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// TestRecordBaseSizeCalibration compares the byte estimate of the store with
// the heap it really takes, so that the memory budget means what it says. The
// connection is shared by the requests of one client connection, as in the
// engine, and is not part of the per-record estimate.
func TestRecordBaseSizeCalibration(t *testing.T) {
	const count = 4000
	for name, add := range map[string]func(*Manager, *flow.ConnectionInfo, int){"typical": typicalExchange, "minimal": minimalExchange} {
		m := New(Options{Enabled: true, MaxRecords: 100000, MaxMemory: 1 << 30})
		conn := &flow.ConnectionInfo{ID: "c1", ProcessName: "Safari"}
		before := heapInUse()
		for i := 0; i < count; i++ {
			add(m, conn, i)
		}
		after := heapInUse()
		estimate := m.Stats().Bytes
		real := int64(after) - int64(before)
		ratio := float64(real) / float64(estimate)
		t.Logf("%s: records=%d estimate=%d (%.0f/record) heap=%d (%.0f/record) ratio=%.3f recordBaseSize=%d",
			name, count, estimate, float64(estimate)/count, real, float64(real)/count, ratio, recordBaseSize)
		// The estimate may be a little high but must not undershoot.
		if ratio < 0.95 || ratio > 1.1 {
			t.Fatalf("%s: estimate is off by %.0f%%", name, (ratio-1)*100)
		}
		runtime.KeepAlive(m)
	}
}

// BenchmarkBodyCountLock measures the cost of the manager lock that every
// body read takes, also when no body is kept: parallel readers on separate
// exchanges against the same counting without the manager.
func BenchmarkBodyCountLock(b *testing.B) {
	chunk := make([]byte, 16<<10)
	for _, workers := range []int{1, 8, 64} {
		b.Run(fmt.Sprintf("manager/%d", workers), func(b *testing.B) {
			m := New(Options{Enabled: true})
			var wg sync.WaitGroup
			per := b.N/workers + 1
			exchanges := make([]flow.Body, workers)
			for i := range exchanges {
				x := m.NewExchange(newConn("b"))
				x.RequestHead(head("/"))
				exchanges[i] = x.ResponseBody()
			}
			b.SetBytes(int64(len(chunk)))
			b.ResetTimer()
			for _, body := range exchanges {
				wg.Add(1)
				go func(body flow.Body) {
					defer wg.Done()
					for i := 0; i < per; i++ {
						body.Write(chunk)
					}
				}(body)
			}
			wg.Wait()
		})
		b.Run(fmt.Sprintf("tee-only/%d", workers), func(b *testing.B) {
			var wg sync.WaitGroup
			per := b.N/workers + 1
			b.SetBytes(int64(len(chunk)))
			b.ResetTimer()
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var tee body.Tee
					for i := 0; i < per; i++ {
						tee.Write(chunk)
					}
				}()
			}
			wg.Wait()
		})
	}
}
