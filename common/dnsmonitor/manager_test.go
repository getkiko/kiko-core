package dnsmonitor

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/service"
)

func monitorContext(t testing.TB, options Options) (context.Context, *Manager) {
	t.Helper()
	m := New(options)
	t.Cleanup(func() { m.Close() })
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, m)
	return ctx, m
}
func question(name string) *dns.Msg { m := new(dns.Msg); m.SetQuestion(name, dns.TypeA); return m }

func TestExchangeResponseAddressesAndEffectiveResult(t *testing.T) {
	ctx, m := monitorContext(t, Options{})
	request := question("x.com.")
	response := new(dns.Msg)
	response.SetReply(request)
	for _, text := range []string{
		"x.com. 60 IN CNAME target.example.",
		"target.example. 60 IN A 172.66.0.227",
		"target.example. 60 IN A 172.66.0.227",
		"target.example. 60 IN AAAA 2001:db8::1",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		response.Answer = append(response.Answer, rr)
	}
	for _, cache := range []string{"miss", "hit"} {
		qctx, trace := Begin(ctx, request, "query")
		Cache(qctx, cache)
		trace.End(response, nil)
		q, _ := m.Get(trace.ID())
		want := []string{"172.66.0.227", "2001:db8::1"}
		if !slices.Equal(q.ResolvedAddresses, want) {
			t.Fatalf("%s response addresses: %v; want %v", cache, q.ResolvedAddresses, want)
		}
		brief := m.List(Filter{}).Queries[0]
		if !slices.Equal(brief.ResolvedAddresses, want) {
			t.Fatalf("list addresses: %v", brief.ResolvedAddresses)
		}
	}
	qctx, trace := Begin(ctx, request, "query")
	Result(qctx, response)
	q, _ := m.Get(trace.ID())
	if len(q.ResolvedAddresses) != 2 {
		t.Fatalf("pending result addresses: %v", q.ResolvedAddresses)
	}
	empty := new(dns.Msg)
	empty.SetReply(request)
	trace.End(empty, nil)
	q, _ = m.Get(trace.ID())
	if len(q.ResolvedAddresses) != 0 {
		t.Fatalf("effective empty answer retained earlier addresses: %v", q.ResolvedAddresses)
	}
}

func TestPendingCompletionSnapshotsAndCursors(t *testing.T) {
	ctx, m := monitorContext(t, Options{})
	request := question("example.org.")
	ctx, trace := Begin(ctx, request, "query")
	initial := m.Poll("", 0)
	if !initial.Reset || len(initial.Queries) != 1 || initial.Queries[0].Status != "pending" {
		t.Fatalf("initial: %+v", initial)
	}
	ctx, attempt := StartAttempt(ctx, "udp")
	attempt.Sent(478, nil)
	response := new(dns.Msg)
	response.SetReply(request)
	rr, _ := dns.NewRR("example.org. 321 IN A 192.0.2.4")
	response.Answer = []dns.RR{rr}
	attempt.End(response, nil)
	response.Answer[0].Header().Ttl = 88
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { trace.End(response, nil) })
	}
	wg.Wait()
	response.Answer[0].Header().Ttl = 1
	q, ok := m.Get(trace.ID())
	if !ok || q.Status != "success" || q.Response.Answer[0].TTL != 88 || q.Attempts[0].Response.Answer[0].TTL != 321 {
		t.Fatalf("query: %+v", q)
	}
	q.Response.Answer[0].TTL = 0
	again, _ := m.Get(trace.ID())
	if again.Response.Answer[0].TTL != 88 {
		t.Fatal("mutable snapshot")
	}
	next := m.Poll(initial.Instance, initial.Seq)
	if next.Reset || len(next.Queries) != 1 || next.Seq <= initial.Seq || next.Stats.Pending != 0 || next.Stats.Total != 1 {
		t.Fatalf("next: %+v", next)
	}
	if len(m.Poll(next.Instance, next.Seq).Queries) != 0 {
		t.Fatal("duplicate revisions")
	}
	Delivery(ctx, fmt.Errorf("broken pipe"), false)
	last, _ := m.Get(trace.ID())
	if last.Delivery != "error" || last.Status != "success" {
		t.Fatal("delivery overwrote DNS outcome")
	}
}

func TestBudgetExpiryResetAndConcurrentReaders(t *testing.T) {
	ctx, m := monitorContext(t, Options{Entries: 3, Bytes: 8192, Age: time.Minute})
	old := m.Poll("", 0)
	for i := range 40 {
		_, trace := Begin(ctx, question(fmt.Sprintf("q%d.example.", i)), "query")
		trace.End(nil, nil)
	}
	v := m.Poll(old.Instance, old.Seq)
	if len(v.Queries) > 3 || v.Stats.Bytes > 8192 || v.Stats.Evicted == 0 || !v.Gap {
		t.Fatalf("budget: %+v", v)
	}
	reset := m.Clear()
	if reset.Instance == v.Instance || len(reset.Queries) != 0 || reset.Stats.Bytes != 0 {
		t.Fatalf("clear: %+v", reset)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 15 {
				c, tr := Begin(ctx, question(fmt.Sprintf("%d-%d.example.", i, j)), "query")
				Cache(c, "hit")
				tr.End(nil, nil)
				m.Poll(reset.Instance, 0)
				m.List(Filter{Search: "example"})
			}
		})
	}
	wg.Wait()
	v = m.List(Filter{})
	if v.Stats.Pending != 0 || len(v.Queries) > 3 {
		t.Fatalf("final: %+v", v)
	}
	_, trace := Begin(ctx, question("expired.example."), "query")
	trace.End(nil, nil)
	trace.mu.Lock()
	expired := time.Now().Add(-2 * time.Minute)
	trace.q.FinishedAt = &expired
	trace.mu.Unlock()
	if _, ok := m.Get(trace.ID()); ok {
		t.Fatal("age limit ignored")
	}
}

func TestActiveAdmissionAndClosedManager(t *testing.T) {
	ctx, m := monitorContext(t, Options{Bytes: 128 << 10})
	_, first := Begin(ctx, question("a.example."), "query")
	_, second := Begin(ctx, question("b.example."), "query")
	if first == nil || second != nil || m.List(Filter{}).Stats.Dropped != 1 {
		t.Fatal("active budget ignored")
	}
	first.End(nil, context.DeadlineExceeded)
	v := m.List(Filter{})
	if v.Stats.Timeouts != 1 || v.Queries[0].Status != "timeout" {
		t.Fatalf("timeout: %+v", v)
	}
	m.Close()
	_, closed := Begin(ctx, question("closed.example."), "query")
	if closed != nil {
		t.Fatal("admitted after close")
	}
}

func TestCaptureBudgetAndSlowSubscriber(t *testing.T) {
	ctx, m := monitorContext(t, Options{CaptureWire: true})
	ctx, trace := Begin(ctx, question("large.example."), "query")
	response := new(dns.Msg)
	response.SetReply(question("large.example."))
	for i := range 200 {
		rr, _ := dns.NewRR(fmt.Sprintf("large.example. 60 IN TXT \"%0200d\"", i))
		response.Answer = append(response.Answer, rr)
	}
	for range 20 {
		_, a := StartAttempt(ctx, "udp")
		a.End(response, nil)
	}
	trace.End(response, nil)
	q, _ := m.Get(trace.ID())
	if !q.Incomplete || len(q.Attempts) != 16 || !q.Attempts[0].Response.TruncatedCapture {
		t.Fatal("capture budget ignored")
	}
	encodedSize := messageBytes(q.Response)
	for _, a := range q.Attempts {
		encodedSize += messageBytes(a.Response)
	}
	if encodedSize > 96<<10 {
		t.Fatalf("excess capture %d", encodedSize)
	}
	// A subscriber only carries its cursor. DNS capture never queues its output.
	before := m.Poll("", 0)
	for range 100 {
		_, tr := Begin(ctx, question("fast.example."), "query")
		tr.End(nil, nil)
	}
	if m.Poll(before.Instance, before.Seq).Seq <= before.Seq {
		t.Fatal("slow reader blocked capture")
	}
}

func BenchmarkObserve(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprint(enabled), func(b *testing.B) {
			ctx := context.Background()
			if enabled {
				ctx, _ = monitorContext(b, Options{Entries: 200})
			}
			request := question("bench.example.")
			response := new(dns.Msg)
			response.SetReply(request)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_, trace := Begin(ctx, request, "query")
				trace.End(response, nil)
			}
		})
	}
}
