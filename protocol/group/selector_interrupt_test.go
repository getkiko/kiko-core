package group

import (
	"context"
	"fmt"
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
		ctx: context.Background(), logger: log.NewNOPFactory().Logger(),
		outbounds:      map[string]adapter.Outbound{selected.Tag(): selected, alternative.Tag(): alternative},
		interruptGroup: interrupt.NewGroup(), interruptExternalConnections: interruptExisting,
	}
	s.selected.Store(selected)
	return s
}

// A routed connection attaches to every group of its chain; switching any
// of them interrupts it when the group interrupts existing connections.
func TestSelectorInterruptsNestedAttachedConnections(t *testing.T) {
	for _, level := range []string{"parent", "deep"} {
		for _, interruptExisting := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/interrupt=%v", level, interruptExisting), func(t *testing.T) {
				manager := &selectorTestManager{t: t}
				target := &selectorTestTarget{tag: "target", manager: manager}
				alternative := &selectorTestTarget{tag: "alternative", manager: manager}
				inner := newTestSelector(manager, target, alternative, interruptExisting)
				outer := newTestSelector(manager, inner, alternative, interruptExisting)
				client, server := net.Pipe()
				t.Cleanup(func() { server.Close() })
				conn := &selectorTestConn{Conn: client}
				for _, group := range []*Selector{outer, inner} {
					detach := group.AttachConnection(conn)
					t.Cleanup(detach)
				}
				switched := outer
				if level == "deep" {
					switched = inner
				}
				if !switched.SelectOutbound(switched.Selected(N.NetworkTCP).Tag()) {
					t.Fatal("select current target failed")
				}
				if conn.closed {
					t.Fatal("selecting current target closed connection")
				}
				if !switched.SelectOutbound(alternative.Tag()) {
					t.Fatal("select alternative failed")
				}
				if conn.closed != interruptExisting {
					t.Fatalf("closed = %v, want %v", conn.closed, interruptExisting)
				}
			})
		}
	}
}

type delayedSelectorTarget struct {
	*selectorTestTarget
	started chan struct{}
	resume  chan struct{}
}

func (o *delayedSelectorTarget) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	close(o.started)
	<-o.resume
	return o.selectorTestTarget.DialContext(ctx, network, destination)
}

func (o *delayedSelectorTarget) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	close(o.started)
	<-o.resume
	return o.selectorTestTarget.ListenPacket(ctx, destination)
}

func TestSelectorInterruptsConnectionsEstablishedDuringSwitch(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		for _, external := range []bool{false, true} {
			for _, interruptExisting := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/external=%v/interrupt=%v", network, external, interruptExisting), func(t *testing.T) {
					manager := &selectorTestManager{t: t}
					target := &delayedSelectorTarget{selectorTestTarget: &selectorTestTarget{tag: "a", manager: manager}, started: make(chan struct{}), resume: make(chan struct{})}
					alternative := &selectorTestTarget{tag: "b", manager: manager}
					selector := newTestSelector(manager, target, alternative, interruptExisting)
					ctx := context.Background()
					if external {
						ctx = interrupt.ContextWithIsExternalConnection(ctx, true)
					}
					result := make(chan error, 1)
					go func() {
						if network == N.NetworkTCP {
							conn, err := selector.DialContext(ctx, network, M.ParseSocksaddr("example.com:443"))
							if conn != nil {
								t.Cleanup(func() { conn.Close() })
							}
							result <- err
						} else {
							conn, err := selector.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
							if conn != nil {
								t.Cleanup(func() { conn.Close() })
							}
							result <- err
						}
					}()
					<-target.started
					if !selector.SelectOutbound("b") {
						t.Fatal("switch failed")
					}
					close(target.resume)
					err := <-result
					wantClosed := !external || interruptExisting
					if (err != nil) != wantClosed {
						t.Fatalf("late dial error = %v; want interrupted=%v", err, wantClosed)
					}
					closed := target.tcp != nil && target.tcp.closed || target.udp != nil && target.udp.closed
					if closed != wantClosed {
						t.Fatalf("old target closed = %v, want %v", closed, wantClosed)
					}
				})
			}
		}
	}
}
