package group

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type selectorTestManager struct {
	adapter.ConnectionManager
	t *testing.T
}

func (m *selectorTestManager) NewConnection(ctx context.Context, dialer N.Dialer, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		m.t.Fatal(err)
	}
	m.t.Cleanup(func() { conn.Close() })
}

func (m *selectorTestManager) NewPacketConnection(ctx context.Context, dialer N.Dialer, _ N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	conn, err := dialer.ListenPacket(ctx, metadata.Destination)
	if err != nil {
		m.t.Fatal(err)
	}
	m.t.Cleanup(func() { conn.Close() })
}

type selectorTestConn struct {
	net.Conn
	closed bool
}

func (c *selectorTestConn) Close() error { c.closed = true; return c.Conn.Close() }

type selectorTestPacketConn struct {
	net.PacketConn
	closed bool
}

func (c *selectorTestPacketConn) Close() error { c.closed = true; return c.PacketConn.Close() }

type selectorTestTarget struct {
	adapter.Outbound
	tag     string
	manager *selectorTestManager
	tcp     *selectorTestConn
	udp     *selectorTestPacketConn
}

func (o *selectorTestTarget) Tag() string { return o.tag }
func (o *selectorTestTarget) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	o.manager.t.Cleanup(func() { server.Close() })
	o.tcp = &selectorTestConn{Conn: client}
	return o.tcp, nil
}
func (o *selectorTestTarget) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	o.udp = &selectorTestPacketConn{PacketConn: conn}
	return o.udp, nil
}
func (o *selectorTestTarget) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	o.manager.NewConnection(ctx, o, conn, metadata, onClose)
}
func (o *selectorTestTarget) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	o.manager.NewPacketConnection(ctx, o, conn, metadata, onClose)
}

func newTestSelector(manager *selectorTestManager, selected, alternative adapter.Outbound, interruptExisting bool) *Selector {
	s := &Selector{
		ctx: context.Background(), connection: manager, logger: log.NewNOPFactory().Logger(),
		outbounds:      map[string]adapter.Outbound{selected.Tag(): selected, alternative.Tag(): alternative},
		interruptGroup: interrupt.NewGroup(), interruptExternalConnections: interruptExisting,
	}
	s.selected.Store(selected)
	return s
}

func TestSelectorInterruptsNestedHandlerConnections(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		for _, level := range []string{"parent", "deep"} {
			for _, interruptExisting := range []bool{false, true} {
				name := network + "/" + level
				if interruptExisting {
					name += "/interrupt"
				} else {
					name += "/keep"
				}
				t.Run(name, func(t *testing.T) {
					manager := &selectorTestManager{t: t}
					target := &selectorTestTarget{tag: "target", manager: manager}
					alternative := &selectorTestTarget{tag: "alternative", manager: manager}
					inner := newTestSelector(manager, target, alternative, interruptExisting)
					// The empty tag gives the nested selector a distinct map key.
					outer := newTestSelector(manager, inner, alternative, interruptExisting)
					metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("example.com:443")}
					var isClosed func() bool
					var unrelatedClosed func() bool
					if network == N.NetworkTCP {
						unrelated, err := target.DialContext(context.Background(), network, metadata.Destination)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { unrelated.Close() })
						unrelatedTracked := target.tcp
						unrelatedClosed = func() bool { return unrelatedTracked.closed }
						outer.NewConnection(context.Background(), nil, metadata, nil)
						isClosed = func() bool { return target.tcp.closed }
					} else {
						unrelated, err := target.ListenPacket(context.Background(), metadata.Destination)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { unrelated.Close() })
						unrelatedTracked := target.udp
						unrelatedClosed = func() bool { return unrelatedTracked.closed }
						outer.NewPacketConnection(context.Background(), nil, metadata, nil)
						isClosed = func() bool { return target.udp.closed }
					}
					switched := outer
					if level == "deep" {
						switched = inner
					}
					if !switched.SelectOutbound(switched.Now()) {
						t.Fatal("select current target failed")
					}
					if isClosed() {
						t.Fatal("selecting current target closed connection")
					}
					if !switched.SelectOutbound(alternative.Tag()) {
						t.Fatal("select alternative failed")
					}
					if isClosed() != interruptExisting {
						t.Fatalf("closed = %v, want %v", isClosed(), interruptExisting)
					}
					if unrelatedClosed() {
						t.Fatal("switch closed unrelated connection")
					}
				})
			}
		}
	}
}
