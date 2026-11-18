package capture

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

func newConn(id string) *flow.ConnectionInfo { return &flow.ConnectionInfo{ID: id} }

func head(path string) flow.RequestHead {
	return flow.RequestHead{
		Method: "GET", Scheme: "https", Authority: "Example.com:443", Path: path, Proto: "h2",
		Headers: []flow.Header{{Name: "Host", Value: "example.com"}, {Name: "X-A", Value: "1"}, {Name: "x-a", Value: "2"}},
	}
}

func complete(m *Manager, conn *flow.ConnectionInfo, path string) {
	x := m.NewExchange(conn)
	x.RequestHead(head(path))
	x.ResponseHead(200, []flow.Header{{Name: "Content-Type", Value: "text/plain"}})
	x.Finish(nil)
}

func TestRecordLifecycleAndEvents(t *testing.T) {
	m := New(Options{Enabled: true})
	view := m.Poll("", 0)
	if !view.Reset || view.Gap || len(view.Events) != 0 {
		t.Fatalf("first poll %+v", view)
	}
	x := m.NewExchange(newConn("c1"))
	x.RequestHead(head("/a?b=1"))
	view = m.Poll(view.Instance, view.Seq)
	if view.Reset || len(view.Events) != 1 || view.Events[0].Kind != EventNew {
		t.Fatalf("new event %+v", view)
	}
	r := view.Events[0].Record
	if r.Host != "example.com" || r.URL != "https://Example.com:443/a?b=1" || r.ConnectionID != "c1" || r.RequestIndex != 1 || r.State != StateInProgress {
		t.Fatalf("record %+v", r)
	}
	if len(r.RequestHeaders) != 3 || r.RequestHeaders[1].Name != "X-A" || r.RequestHeaders[2].Name != "x-a" {
		t.Fatalf("header order %+v", r.RequestHeaders)
	}
	x.ResponseHead(200, nil)
	view = m.Poll(view.Instance, view.Seq)
	if len(view.Events) != 1 || view.Events[0].Kind != EventUpdate || view.Events[0].Record.Status != 200 {
		t.Fatalf("update %+v", view)
	}
	x.Finish(nil)
	view = m.Poll(view.Instance, view.Seq)
	if len(view.Events) != 1 || view.Events[0].Kind != EventDone || view.Events[0].Record.State != StateComplete {
		t.Fatalf("done %+v", view)
	}
	again := m.Poll(view.Instance, view.Seq)
	if len(again.Events) != 0 || again.Reset {
		t.Fatalf("idle %+v", again)
	}
}

func TestCoalescedUpdatesDeliverLatestOnce(t *testing.T) {
	m := New(Options{Enabled: true})
	base := m.Poll("", 0)
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/"))
	x.ResponseHead(200, nil)
	x.Finish(errors.New("boom"))
	view := m.Poll(base.Instance, base.Seq)
	if len(view.Events) != 1 || view.Events[0].Kind != EventDone || view.Events[0].Record.Error != "boom" || view.Events[0].Record.State != StateFailed {
		t.Fatalf("%+v", view)
	}
}

func TestEvictionOnlyFinished(t *testing.T) {
	m := New(Options{Enabled: true, MaxRecords: 3})
	var running []flow.Exchange
	for i := 0; i < 3; i++ {
		x := m.NewExchange(newConn("run"))
		x.RequestHead(head(fmt.Sprintf("/run%d", i)))
		running = append(running, x)
	}
	for i := 0; i < 10; i++ {
		complete(m, newConn("done"), fmt.Sprintf("/done%d", i))
	}
	stats := m.Stats()
	if stats.InProgress != 3 {
		t.Fatalf("in progress %d", stats.InProgress)
	}
	list := m.List(Filter{})
	inProgress := 0
	for _, r := range list.Records {
		if r.State == StateInProgress {
			inProgress++
		}
	}
	if inProgress != 3 {
		t.Fatalf("running records evicted: %d left", inProgress)
	}
	for _, x := range running {
		x.Finish(nil)
	}
	if got := m.Stats().Records; got != 3 {
		t.Fatalf("records %d", got)
	}
}

func TestGapAndReset(t *testing.T) {
	m := New(Options{Enabled: true, MaxRecords: 4})
	complete(m, newConn("c"), "/0")
	view := m.Poll("", 0)
	cursor := view.Seq
	for i := 0; i < 10; i++ {
		complete(m, newConn("c"), fmt.Sprintf("/%d", i+1))
	}
	gap := m.Poll(view.Instance, cursor)
	if !gap.Reset || !gap.Gap || len(gap.Events) != 4 {
		t.Fatalf("gap %+v events=%d", gap.Gap, len(gap.Events))
	}
	if gap.Floor == 0 {
		t.Fatal("floor must move")
	}
	ok := m.Poll(gap.Instance, gap.Seq)
	if ok.Reset || len(ok.Events) != 0 {
		t.Fatalf("caught up %+v", ok)
	}
	reset := m.Poll("other-instance", gap.Seq)
	if !reset.Reset || reset.Gap {
		t.Fatalf("instance mismatch: reset=%v gap=%v", reset.Reset, reset.Gap)
	}
	future := m.Poll(gap.Instance, gap.Seq+100)
	if !future.Reset {
		t.Fatal("cursor ahead of seq must reset")
	}
	for i := 1; i < len(gap.Events); i++ {
		if gap.Events[i-1].Record.CreatedSeq >= gap.Events[i].Record.CreatedSeq {
			t.Fatal("snapshot must be in creation order")
		}
	}
}

func TestClearKeepsRunningAndInstance(t *testing.T) {
	m := New(Options{Enabled: true})
	for i := 0; i < 3; i++ {
		complete(m, newConn("c"), "/")
	}
	running := m.NewExchange(newConn("c"))
	running.RequestHead(head("/running"))
	view := m.Poll("", 0)
	m.Clear()
	if m.Instance() != view.Instance {
		t.Fatal("instance changed")
	}
	after := m.Poll(view.Instance, view.Seq)
	if !after.Reset || !after.Gap || len(after.Events) != 1 || after.Events[0].Record.Path != "/running" {
		t.Fatalf("%+v", after)
	}
	if after.Floor <= view.Floor {
		t.Fatal("floor must move")
	}
	if m.Stats().Records != 1 {
		t.Fatalf("records %d", m.Stats().Records)
	}
	running.Finish(nil)
	done := m.Poll(after.Instance, after.Seq)
	if len(done.Events) != 1 || done.Events[0].Kind != EventDone {
		t.Fatalf("%+v", done)
	}
}

func TestBodyCaptureAndTruncation(t *testing.T) {
	m := New(Options{Enabled: true, Body: true, MaxBody: 1000})
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/up"))
	payload := bytes.Repeat([]byte("0123456789"), 300)
	var forwarded bytes.Buffer
	if _, err := io.Copy(&forwarded, x.RequestBody().Reader(bytes.NewReader(payload))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forwarded.Bytes(), payload) {
		t.Fatal("forwarded bytes changed")
	}
	x.ResponseHead(200, nil)
	rb := x.ResponseBody()
	rb.Write([]byte("short"))
	rb.Done()
	x.Finish(nil)
	list := m.List(Filter{})
	r := list.Records[0]
	if r.RequestBytes != 3000 || r.RequestBodyStored != 1000 || !r.RequestBodyTruncated || !r.RequestBodySaved {
		t.Fatalf("request %+v", r)
	}
	if r.ResponseBytes != 5 || r.ResponseBodyStored != 5 || r.ResponseBodyTruncated {
		t.Fatalf("response %+v", r)
	}
	res, err := m.GetBody(BodyRequest{ID: r.ID, Instance: r.Instance, Side: flow.Request, Offset: 990, Length: 100})
	if err != nil || len(res.Data) != 10 || !res.Truncated || res.Total != 1000 || res.Original != 3000 || !res.Complete {
		t.Fatalf("%+v %v", res, err)
	}
	if !bytes.Equal(res.Data, payload[990:1000]) {
		t.Fatal("range mismatch")
	}
}

func TestBodyDisabledStillCounts(t *testing.T) {
	m := New(Options{Enabled: true})
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/"))
	io.Copy(io.Discard, x.ResponseBody().Reader(strings.NewReader("12345")))
	x.Finish(nil)
	r := m.List(Filter{}).Records[0]
	if r.ResponseBytes != 5 || r.ResponseBodySaved || r.ResponseBodyStored != 0 {
		t.Fatalf("%+v", r)
	}
	res, err := m.GetBody(BodyRequest{ID: r.ID, Side: flow.Response})
	if err != nil || len(res.Data) != 0 || res.Saved || res.Original != 5 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGetBodyDecoded(t *testing.T) {
	m := New(Options{Enabled: true, Body: true})
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(strings.Repeat("decoded text ", 100)))
	w.Close()
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/"))
	x.ResponseHead(200, []flow.Header{{Name: "Content-Encoding", Value: "gzip"}})
	body := x.ResponseBody()
	body.Write(buf.Bytes())
	body.Done()
	x.Finish(nil)
	r := m.List(Filter{}).Records[0]
	raw, _ := m.GetBody(BodyRequest{ID: r.ID, Side: flow.Response})
	if int64(len(raw.Data)) != int64(buf.Len()) || raw.Encoding != "gzip" {
		t.Fatalf("raw %+v", raw)
	}
	dec, err := m.GetBody(BodyRequest{ID: r.ID, Side: flow.Response, Decoded: true, Offset: 13, Length: 12})
	if err != nil || string(dec.Data) != "decoded text" || dec.Total != 1300 || dec.DecodeError != "" {
		t.Fatalf("%+v %v", dec, err)
	}
}

func TestGetBodyDecodedGarbageReportsError(t *testing.T) {
	m := New(Options{Enabled: true, Body: true, MaxBody: 200})
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(bytes.Repeat([]byte("abcdefghij"), 5000))
	w.Close()
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/"))
	x.ResponseHead(200, []flow.Header{{Name: "content-encoding", Value: "gzip"}})
	b := x.ResponseBody()
	b.Write(bytes.Repeat([]byte{0x1f}, 10))
	b.Done()
	x.Finish(nil)
	r := m.List(Filter{}).Records[0]
	dec, err := m.GetBody(BodyRequest{ID: r.ID, Side: flow.Response, Decoded: true})
	if err != nil {
		t.Fatal(err)
	}
	if dec.DecodeError == "" {
		t.Fatalf("garbage must report a decode error")
	}
}

func TestGetBodyErrors(t *testing.T) {
	m := New(Options{Enabled: true})
	if _, err := m.GetBody(BodyRequest{ID: "99"}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	complete(m, newConn("c"), "/")
	if _, err := m.GetBody(BodyRequest{ID: "1", Instance: "stale"}); !errors.Is(err, ErrReset) {
		t.Fatal(err)
	}
}

func TestBudgetStopsBodiesButKeepsMetadata(t *testing.T) {
	m := New(Options{Enabled: true, Body: true, MaxBody: 1 << 20, MaxMemory: 1 << 20, MaxRecords: 100})
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	var running []flow.Exchange
	for i := 0; i < 4; i++ {
		x := m.NewExchange(newConn("c"))
		x.RequestHead(head("/big"))
		running = append(running, x)
		b := x.ResponseBody()
		for j := 0; j < 8; j++ {
			b.Write(chunk)
		}
		b.Done()
	}
	stats := m.Stats()
	if stats.Bytes > stats.MaxMemory {
		t.Fatalf("bytes %d over budget", stats.Bytes)
	}
	if stats.BodyDropped == 0 {
		t.Fatal("expected dropped bodies")
	}
	dropped := 0
	for _, r := range m.List(Filter{}).Records {
		if r.BodyDropped {
			dropped++
			if !r.ResponseBodyTruncated || r.ResponseBytes != 512<<10 {
				t.Fatalf("dropped record %+v", r)
			}
		}
	}
	if dropped == 0 {
		t.Fatal("no record marked")
	}
	for _, x := range running {
		x.Finish(nil)
	}
}

func TestBudgetEvictsFinishedForBodies(t *testing.T) {
	m := New(Options{Enabled: true, Body: true, MaxMemory: 1 << 20, MaxRecords: 1000})
	chunk := bytes.Repeat([]byte("y"), 100<<10)
	for i := 0; i < 30; i++ {
		x := m.NewExchange(newConn("c"))
		x.RequestHead(head("/"))
		b := x.ResponseBody()
		b.Write(chunk)
		b.Done()
		x.Finish(nil)
	}
	stats := m.Stats()
	if stats.Bytes > stats.MaxMemory || stats.Evicted == 0 || stats.BodyDropped != 0 {
		t.Fatalf("%+v", stats)
	}
}

func TestUpgradeCountsAsFinished(t *testing.T) {
	m := New(Options{Enabled: true, MaxRecords: 1})
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/ws"))
	x.Upgrade(101, []flow.Header{{Name: "Upgrade", Value: "websocket"}})
	complete(m, newConn("c"), "/next")
	if m.Stats().Records != 1 {
		t.Fatalf("records %d", m.Stats().Records)
	}
	x.Finish(errors.New("closed"))
}

func TestListFilters(t *testing.T) {
	m := New(Options{Enabled: true})
	for i := 0; i < 5; i++ {
		x := m.NewExchange(newConn(fmt.Sprintf("c%d", i%2)))
		h := head(fmt.Sprintf("/p%d", i))
		if i == 4 {
			h.Authority = "api.other.org"
		}
		x.RequestHead(h)
		x.ResponseHead(200+i, nil)
		x.Finish(nil)
	}
	if got := len(m.List(Filter{ConnectionID: "c0"}).Records); got != 3 {
		t.Fatalf("conn %d", got)
	}
	if got := len(m.List(Filter{Host: "other.org"}).Records); got != 1 {
		t.Fatalf("host %d", got)
	}
	if got := len(m.List(Filter{Search: "P2"}).Records); got != 1 {
		t.Fatalf("search %d", got)
	}
	if got := len(m.List(Filter{Search: "203"}).Records); got != 1 {
		t.Fatalf("status search %d", got)
	}
	page := m.List(Filter{Limit: 2})
	if len(page.Records) != 2 || page.Records[0].Path != "/p4" || page.NextBefore != 4 {
		t.Fatalf("%+v", page)
	}
	next := m.List(Filter{Limit: 2, Before: page.NextBefore})
	if len(next.Records) != 2 || next.Records[0].Path != "/p2" {
		t.Fatalf("%+v", next)
	}
	if _, ok := m.Get("3"); !ok {
		t.Fatal("get")
	}
	if _, ok := m.Get("abc"); ok {
		t.Fatal("bad id")
	}
}

func TestObserverNilWhenDisabled(t *testing.T) {
	m := New(Options{})
	if m.Observer() != nil {
		t.Fatal("disabled store must hand out a nil observer")
	}
	m.SetOptions(Options{Enabled: true})
	if m.Observer() == nil {
		t.Fatal("enabled")
	}
	m.SetOptions(Options{})
	if _, ok := m.NewExchange(nil).(flow.NopExchange); !ok {
		t.Fatal("late exchange must be a no-op")
	}
}

func TestSlowSubscriberDoesNotBlockWriters(t *testing.T) {
	m := New(Options{Enabled: true})
	wake, cancel := m.Subscribe()
	defer cancel()
	_ = wake
	done := make(chan struct{})
	go func() {
		for i := 0; i < 20000; i++ {
			complete(m, newConn("c"), "/")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("writers blocked by an idle subscriber")
	}
	<-wake
}

func TestConcurrentSubscribers(t *testing.T) {
	m := New(Options{Enabled: true, Body: true, MaxRecords: 200})
	var writers, readers sync.WaitGroup
	stop := make(chan struct{})
	counts := make([]int, 4)
	for i := range counts {
		readers.Add(1)
		go func(i int) {
			defer readers.Done()
			wake, cancel := m.Subscribe()
			defer cancel()
			instance, after := "", uint64(0)
			for {
				view := m.Poll(instance, after)
				instance, after = view.Instance, view.Seq
				counts[i] += len(view.Events)
				m.List(Filter{Limit: 20})
				select {
				case <-stop:
					return
				case <-wake:
				}
			}
		}(i)
	}
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < 500; i++ {
				x := m.NewExchange(newConn(fmt.Sprintf("w%d", w)))
				x.RequestHead(head("/"))
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					io.Copy(io.Discard, x.RequestBody().Reader(strings.NewReader("request body")))
				}()
				go func() {
					defer wg.Done()
					x.ResponseHead(200, nil)
					io.Copy(io.Discard, x.ResponseBody().Reader(strings.NewReader("response body")))
				}()
				wg.Wait()
				x.Finish(nil)
				if i%100 == 0 {
					m.Clear()
				}
			}
		}(w)
	}
	writers.Wait()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	readers.Wait()
	for i, c := range counts {
		if c == 0 {
			t.Errorf("subscriber %d saw nothing", i)
		}
	}
	if s := m.Stats(); s.InProgress != 0 || s.Total != 2000 {
		t.Fatalf("%+v", s)
	}
}

func cpuSeconds() float64 {
	sample := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindFloat64 {
		return sample[0].Value.Float64()
	}
	return 0
}

// ringReport simulates a steady request rate and checks the budget.
func ringReport(tb testing.TB, rate, seconds, bodySize, maxRecords int, report func(format string, args ...any)) {
	m := New(Options{Enabled: true, Body: true, MaxBody: 512 << 10, MaxMemory: 64 << 20, MaxRecords: maxRecords})
	conn := newConn("bench")
	body := bytes.Repeat([]byte("b"), bodySize)
	reqHead := head("/v1/items?id=42&token=abcdef")
	respHeaders := []flow.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Content-Length", Value: "600"}, {Name: "Server", Value: "x"}, {Name: "Date", Value: "Mon, 02 Jan 2006 15:04:05 GMT"}}
	var peak int64
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	baseHeap := base.HeapAlloc
	cpuBefore := cpuSeconds()
	wake, cancel := m.Subscribe()
	defer cancel()
	instance, after := "", uint64(0)
	events := 0
	start := time.Now()
	total := rate * seconds
	for i := 0; i < total; i++ {
		x := m.NewExchange(conn)
		x.RequestHead(reqHead)
		x.ResponseHead(200, respHeaders)
		b := x.ResponseBody()
		b.Write(body)
		b.Done()
		x.Finish(nil)
		if i%rate == 0 || i%100 == 0 {
			select {
			case <-wake:
				view := m.Poll(instance, after)
				instance, after = view.Instance, view.Seq
				events += len(view.Events)
			default:
			}
		}
		if s := m.Stats(); s.Bytes > peak {
			peak = s.Bytes
		}
	}
	elapsed := time.Since(start)
	cpu := cpuSeconds() - cpuBefore
	var mem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mem)
	stats := m.Stats()
	report("records=%d total=%d estimate=%d (budget %d) peak=%d heap=%d process-cpu=%.3fs wall=%s per-request=%s events=%d evicted=%d",
		stats.Records, total, stats.Bytes, stats.MaxMemory, peak, mem.HeapAlloc, cpu, elapsed, elapsed/time.Duration(total), events, stats.Evicted)
	runtime.KeepAlive(m)
	if float64(peak) > 1.1*float64(stats.MaxMemory) {
		tb.Fatalf("peak %d exceeds 1.1x budget %d", peak, stats.MaxMemory)
	}
	if float64(mem.HeapAlloc) > 1.1*float64(stats.MaxMemory)+float64(baseHeap) {
		tb.Fatalf("heap %d exceeds 1.1x budget %d", mem.HeapAlloc, stats.MaxMemory)
	}
}

func TestRing1000RPSBudget(t *testing.T) {
	// Count-bound: 5000 records of small bodies.
	ringReport(t, 1000, 20, 600, 5000, t.Logf)
	// Memory-bound: the byte budget evicts long before the record cap.
	ringReport(t, 1000, 60, 2000, 100000, t.Logf)
}

// BenchmarkRing1000RPS replays a 1000 request per second load for 30 seconds
// of simulated traffic per iteration and prints memory and CPU time.
func BenchmarkRing1000RPS(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		report := func(format string, args ...any) { b.Logf(format, args...) }
		ringReport(b, 1000, 30, 600, 5000, report)
		ringReport(b, 1000, 60, 2000, 100000, report)
	}
}

func TestGetBodyRangeOverflowAndNegative(t *testing.T) {
	m := New(Options{Enabled: true, Body: true})
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(strings.Repeat("abc", 100)))
	w.Close()
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/"))
	x.ResponseHead(200, []flow.Header{{Name: "Content-Encoding", Value: "gzip"}})
	rb := x.ResponseBody()
	rb.Write(gz.Bytes())
	rb.Done()
	x.Finish(nil)
	id := m.List(Filter{}).Records[0].ID
	for _, decoded := range []bool{false, true} {
		res, err := m.GetBody(BodyRequest{ID: id, Side: flow.Response, Decoded: decoded, Offset: 1, Length: 1<<63 - 1})
		if err != nil || len(res.Data) == 0 {
			t.Fatalf("decoded=%v %+v %v", decoded, res, err)
		}
		res, err = m.GetBody(BodyRequest{ID: id, Side: flow.Response, Decoded: decoded, Offset: 1<<63 - 1, Length: 1<<63 - 1})
		if err != nil || len(res.Data) != 0 {
			t.Fatalf("decoded=%v %+v %v", decoded, res, err)
		}
		for _, bad := range []BodyRequest{{Offset: -1}, {Length: -1}, {Offset: -1 << 63, Length: -1 << 63}} {
			bad.ID, bad.Side, bad.Decoded = id, flow.Response, decoded
			if _, err = m.GetBody(bad); !errors.Is(err, ErrRange) {
				t.Fatalf("decoded=%v %+v err=%v", decoded, bad, err)
			}
		}
	}
}

func TestBodyWriteAfterSelfEviction(t *testing.T) {
	m := New(Options{Enabled: true, Body: true, MaxBody: 8 << 20, MaxMemory: 1 << 20, MaxRecords: 1000})
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/"))
	rb := x.RequestBody()
	x.ResponseHead(200, nil)
	x.Finish(nil)
	chunk := bytes.Repeat([]byte("z"), 100<<10)
	for i := 0; i < 30; i++ {
		rb.Write(chunk)
	}
	rb.Done()
	stats := m.Stats()
	if stats.Bytes < 0 || stats.Bytes > stats.MaxMemory || stats.BodyDropped != 0 || stats.Evicted == 0 {
		t.Fatalf("%+v", stats)
	}
	m.Clear()
	if stats = m.Stats(); stats.Bytes != 0 || stats.Records != 0 {
		t.Fatalf("leaked %+v", stats)
	}
}

func TestRewriteHitsCountTowardsBudget(t *testing.T) {
	m := New(Options{Enabled: true, MaxMemory: 64 << 10, MaxRecords: 1000})
	big := strings.Repeat("v", 1<<10)
	for i := 0; i < 200; i++ {
		x := m.NewExchange(newConn("c"))
		x.RequestHead(head("/"))
		x.Rewritten([]flow.RewriteHit{{Kind: "header", Rule: "r", Changes: []flow.RewriteChange{
			{Op: "replace", Name: "X-A", Before: big, After: big}, {Op: "replace", Name: "X-B", Before: big, After: big}}}})
		x.Finish(nil)
	}
	stats := m.Stats()
	if stats.Bytes > stats.MaxMemory || stats.Evicted == 0 {
		t.Fatalf("%+v", stats)
	}
}
