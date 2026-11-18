package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

func dnsMonitorTestContext(t *testing.T) (context.Context, *dnsmonitor.Manager) {
	m := dnsmonitor.New(dnsmonitor.Options{})
	t.Cleanup(func() { m.Close() })
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, m)
	return ctx, m
}

func TestMonitorCacheCoalescingAndRawTTL(t *testing.T) {
	ctx, m := dnsMonitorTestContext(t)
	transport := &fakeDNSTransport{tag: "resolver", delay: 30 * time.Millisecond, address: netip.MustParseAddr("192.0.2.1")}
	client := NewClient(ClientOptions{Context: ctx, Logger: log.NewNOPFactory().Logger()})
	request := new(dns.Msg)
	request.SetQuestion("cache.example.", dns.TypeA)
	ttl := uint32(42)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_, err := client.Exchange(ctx, transport, request.Copy(), adapter.DNSQueryOptions{RewriteTTL: &ttl}, nil)
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	queries := m.List(dnsmonitor.Filter{}).Queries
	if len(queries) != 10 || transport.queryCount.Load() != 1 {
		t.Fatalf("queries %d, wire %d", len(queries), transport.queryCount.Load())
	}
	shared, attempts := 0, 0
	for _, q := range queries {
		full, _ := m.Get(q.ID)
		if full.Response.Answer[0].TTL > 42 || full.Response.Answer[0].TTL == 0 {
			t.Fatal("effective TTL lost")
		}
		if full.SharedWith != "" {
			shared++
		}
		for _, a := range full.Attempts {
			attempts++
			if a.Response.Answer[0].TTL != 300 {
				t.Fatal("upstream TTL overwritten")
			}
		}
	}
	if shared == 0 || attempts != 1 {
		t.Fatalf("shared %d attempts %d", shared, attempts)
	}
	_, err := client.Exchange(ctx, transport, request.Copy(), adapter.DNSQueryOptions{RewriteTTL: &ttl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	queries = m.List(dnsmonitor.Filter{}).Queries
	foundHit := false
	for _, q := range queries {
		if q.Cache == "hit" && q.SharedWith == "" && len(q.Attempts) == 0 {
			foundHit = true
		}
	}
	if !foundHit || transport.queryCount.Load() != 1 {
		t.Fatal("cache hit initiated exchange")
	}
}

func TestMonitorRouterAsyncAndLookupChildren(t *testing.T) {
	ctx, m := dnsMonitorTestContext(t)
	transport := &fakeDNSTransport{tag: "final", delay: time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transport)
	request := new(dns.Msg)
	request.SetQuestion("async.example.", dns.TypeA)
	done := make(chan struct{})
	router.ExchangeAsync(ctx, request, adapter.DNSQueryOptions{Transport: transport}, func(response *dns.Msg, err error) {
		if err != nil {
			t.Error(err)
		}
		close(done)
	})
	<-done
	if len(m.List(dnsmonitor.Filter{}).Queries) != 1 {
		t.Fatal("async duplicate query")
	}
	_, err := router.Lookup(ctx, "lookup.example", adapter.DNSQueryOptions{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	queries := m.List(dnsmonitor.Filter{}).Queries
	if len(queries) != 4 {
		t.Fatalf("want query + operation + A/AAAA, got %d", len(queries))
	}
	var parent string
	children := 0
	for _, q := range queries {
		if q.Role == "lookup_operation" {
			parent = q.ID
		}
	}
	for _, q := range queries {
		if q.ParentID == parent && q.OperationID != "" {
			children++
		}
	}
	if parent == "" || children != 2 {
		t.Fatalf("parent %s children %d", parent, children)
	}
}

func TestMonitorBackgroundRefreshAndCancellation(t *testing.T) {
	ctx, m := dnsMonitorTestContext(t)
	transport := &fakeDNSTransport{tag: "resolver", delay: time.Millisecond, address: netip.MustParseAddr("192.0.2.3")}
	client := NewClient(ClientOptions{Context: ctx, Logger: log.NewNOPFactory().Logger()})
	request := new(dns.Msg)
	request.SetQuestion("refresh.example.", dns.TypeA)
	ctx, parent := dnsmonitor.Begin(ctx, request, "query")
	key := client.newCacheKey(transport, request.Question[0], request, adapter.DNSQueryOptions{})
	client.backgroundRefreshDNS(ctx, transport, key, request, adapter.DNSQueryOptions{}, nil)
	deadline := time.Now().Add(time.Second)
	for transport.queryCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for {
		queries := m.List(dnsmonitor.Filter{}).Queries
		found := false
		for _, q := range queries {
			if q.Role == "background_refresh" && q.ParentID == parent.ID() && q.Status == "success" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background refresh: %+v", queries)
		}
		time.Sleep(time.Millisecond)
	}
	parent.End(nil, nil)
	ctx2, cancel := context.WithCancel(ctx)
	cancel()
	_, err := client.Exchange(ctx2, transport, request, adapter.DNSQueryOptions{}, nil)
	if err == nil {
		t.Fatal("canceled exchange succeeded")
	}
}
