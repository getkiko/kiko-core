package group

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestDNSMonitorActualSelectionAndFrozenConnection(t *testing.T) {
	m := dnsmonitor.New(dnsmonitor.Options{})
	defer m.Close()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, m)
	request := new(dns.Msg)
	request.SetQuestion("route.example.", dns.TypeA)
	ctx, trace := dnsmonitor.Begin(ctx, request, "query")
	defer trace.End(nil, nil)
	manager := &selectorTestManager{t: t}
	a := &selectorTestTarget{tag: "a", manager: manager}
	b := &selectorTestTarget{tag: "b", manager: manager}
	selector := newTestSelector(manager, a, b, false)
	conn, err := selector.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.1:853"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	frozen := dnsmonitor.Freeze(ctx, conn, "tls", "192.0.2.1:853")
	selector.selected.Store(b)
	if frozen.Outbound[len(frozen.Outbound)-1] != "a" {
		t.Fatalf("old connection chain: %+v", frozen)
	}
	conn2, err := selector.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.1:853"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	second := dnsmonitor.Freeze(ctx, conn2, "tls", "192.0.2.1:853")
	if second.Outbound[len(second.Outbound)-1] != "b" {
		t.Fatal("new selection lost")
	}
	// URLTest can concurrently select different nodes for TCP and UDP.
	auto := &URLTest{logger: log.NewNOPFactory().Logger(), group: &URLTestGroup{selectedOutboundTCP: a, selectedOutboundUDP: b, interruptGroup: interrupt.NewGroup(), history: urltest.NewHistoryStorage()}}
	tcp, err := auto.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.1:853"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := auto.DialContext(ctx, "udp", M.ParseSocksaddr("192.0.2.1:853"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	chainTCP := dnsmonitor.Freeze(ctx, tcp, "tls", "").Outbound
	chainUDP := dnsmonitor.Freeze(ctx, udp, "quic", "").Outbound
	if reflect.DeepEqual(chainTCP, chainUDP) || chainTCP[len(chainTCP)-1] != "a" || chainUDP[len(chainUDP)-1] != "b" {
		t.Fatalf("TCP %v UDP %v", chainTCP, chainUDP)
	}
}
