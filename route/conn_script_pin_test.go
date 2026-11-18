package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type pinDNSRouter struct {
	adapter.DNSRouter
	mu      sync.Mutex
	answers []netip.Addr
	lookups int
}

func (r *pinDNSRouter) Lookup(_ context.Context, _ string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	return r.answers, nil
}

type pinOutbound struct {
	adapter.Outbound
	mu    sync.Mutex
	dials []M.Socksaddr
}

func (o *pinOutbound) Type() string { return C.TypeDirect }
func (o *pinOutbound) Tag() string  { return "direct" }

func (o *pinOutbound) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	o.mu.Lock()
	o.dials = append(o.dials, destination)
	o.mu.Unlock()
	client, server := net.Pipe()
	go func() { _, _ = server.Read(make([]byte, 1)); server.Close() }()
	return &remoteConn{Conn: client, remote: &net.TCPAddr{IP: destination.Addr.AsSlice(), Port: int(destination.Port)}}, nil
}

func (o *pinOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func pinManager(answers ...string) (*ConnectionManager, *pinDNSRouter) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	router := &pinDNSRouter{}
	for _, text := range answers {
		router.answers = append(router.answers, netip.MustParseAddr(text))
	}
	service.MustRegister[adapter.DNSRouter](ctx, router)
	return &ConnectionManager{logger: logger.NOP(), urlTestHistory: urltest.NewHistoryStorage(), mitm: scriptGuardEngine{}, ctx: ctx}, router
}

func runPinned(manager *ConnectionManager, outbound *pinOutbound, destination string) error {
	client, inbound := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr(destination), ScriptClient: true}
	manager.NewConnection(context.Background(), outbound, inbound, metadata, func(err error) { done <- err })
	select {
	case err := <-done:
		return err
	case <-time.After(200 * time.Millisecond):
		inbound.Close()
		return nil
	}
}

// A name that resolves to several addresses is dialed at the addresses that pass, never as a
// name that the dialer would resolve a second time.
func TestScriptClientPinsResolvedAddresses(t *testing.T) {
	manager, router := pinManager("10.0.0.1", "127.0.0.1", "8.8.8.8", "2606:4700::1111")
	outbound := &pinOutbound{}
	_ = runPinned(manager, outbound, "rebind.test:80")
	outbound.mu.Lock()
	defer outbound.mu.Unlock()
	if router.lookups != 1 {
		t.Fatalf("%d lookups", router.lookups)
	}
	if len(outbound.dials) == 0 {
		t.Fatal("no dial")
	}
	for _, destination := range outbound.dials {
		if !destination.IsIP() || destination.Port != 80 {
			t.Fatalf("dialed %v: a name or a wrong port", destination)
		}
		if destination.Addr.String() == "10.0.0.1" || destination.Addr.String() == "127.0.0.1" {
			t.Fatalf("dialed refused address %v", destination)
		}
	}
}

// Every answer is local: refused before any dial, whether the port would answer or not.
func TestScriptClientRefusesAllLocalAnswers(t *testing.T) {
	manager, _ := pinManager("10.0.0.1", "::1", "::ffff:127.0.0.1")
	outbound := &pinOutbound{}
	err := runPinned(manager, outbound, "rebind.test:22")
	if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
		t.Fatalf("error %v", err)
	}
	if len(outbound.dials) != 0 {
		t.Fatalf("dialed %v", outbound.dials)
	}
}

// Without a script marker nothing changes: the name goes to the dialer.
func TestOrdinaryConnectionKeepsName(t *testing.T) {
	manager, router := pinManager("10.0.0.1")
	outbound := &pinOutbound{}
	client, inbound := net.Pipe()
	defer client.Close()
	manager.NewConnection(context.Background(), outbound, inbound, adapter.InboundContext{Destination: M.ParseSocksaddr("ordinary.test:80")}, func(error) {})
	time.Sleep(100 * time.Millisecond)
	inbound.Close()
	outbound.mu.Lock()
	defer outbound.mu.Unlock()
	if router.lookups != 0 || len(outbound.dials) != 1 || outbound.dials[0].IsIP() {
		t.Fatalf("lookups %d, dials %v", router.lookups, outbound.dials)
	}
}

// Other outbounds resolve on the far side and are left alone.
func TestScriptClientProxyOutboundNotPinned(t *testing.T) {
	manager, router := pinManager("10.0.0.1")
	outbound := &proxyPinOutbound{}
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("far.test:80"), ScriptClient: true}
	if err := manager.pinScriptDestination(context.Background(), outbound, &metadata); err != nil || router.lookups != 0 || len(metadata.DestinationAddresses) != 0 {
		t.Fatalf("err %v lookups %d addresses %v", err, router.lookups, metadata.DestinationAddresses)
	}
}

type proxyPinOutbound struct{ pinOutbound }

func (*proxyPinOutbound) Type() string { return C.TypeSOCKS }

var _ N.Dialer = (*pinOutbound)(nil)
