package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type scriptGuardEngine struct {
	adapter.MITMEngine
}

func (scriptGuardEngine) ScriptAddressRefused(addr netip.Addr) string {
	if addr.Unmap().IsLoopback() || addr.Unmap().IsPrivate() {
		return "local address"
	}
	return ""
}

// remoteConn reports a chosen remote address, as a dialed TCP connection does.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

// scriptTestOutbound is a dialer that connects to a pipe and says it reached remote.
type scriptTestOutbound struct {
	adapter.Outbound
	kind   string
	remote net.IP
	server net.Conn
}

func (o *scriptTestOutbound) Type() string { return o.kind }
func (o *scriptTestOutbound) Tag() string  { return "test" }

func (o *scriptTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	o.server = server
	return &remoteConn{Conn: client, remote: &net.TCPAddr{IP: o.remote, Port: 80}}, nil
}

func (o *scriptTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestScriptAddressRefusedByDirectOutbound(t *testing.T) {
	manager := &ConnectionManager{logger: logger.NOP(), urlTestHistory: urltest.NewHistoryStorage(), mitm: scriptGuardEngine{}}
	dial := func(kind string, remote string) error {
		outbound := &scriptTestOutbound{kind: kind, remote: net.ParseIP(remote)}
		conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("name.test:80"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		defer outbound.server.Close()
		return manager.scriptAddressRefused(outbound, conn)
	}
	for _, remote := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.1.2.3"} {
		err := dial(C.TypeDirect, remote)
		if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
			t.Fatalf("direct to %s: %v", remote, err)
		}
	}
	if err := dial(C.TypeDirect, "8.8.8.8"); err != nil {
		t.Fatalf("public address refused: %v", err)
	}
	// Other outbounds resolve on the far side: the remote address is the proxy's.
	if err := dial(C.TypeSOCKS, "127.0.0.1"); err != nil {
		t.Fatalf("proxy outbound refused: %v", err)
	}
	// Without a guard the connection is refused.
	bare := &ConnectionManager{logger: logger.NOP()}
	outbound := &scriptTestOutbound{kind: C.TypeDirect, remote: net.ParseIP("8.8.8.8")}
	conn, _ := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("name.test:80"))
	defer conn.Close()
	defer outbound.server.Close()
	if bare.scriptAddressRefused(outbound, conn) == nil {
		t.Fatal("missing guard must refuse")
	}
}

// A script connection that a direct outbound connected to a local address is closed before any
// byte moves; the router sees the reason, an ordinary connection to the same address is served.
func TestNewConnectionScriptClientLocalAddress(t *testing.T) {
	manager := &ConnectionManager{logger: logger.NOP(), urlTestHistory: urltest.NewHistoryStorage(), mitm: scriptGuardEngine{}}
	run := func(scriptClient bool) (closeErr error, received []byte, outboundServer net.Conn) {
		outbound := &scriptTestOutbound{kind: C.TypeDirect, remote: net.ParseIP("127.0.0.1")}
		client, inbound := net.Pipe()
		defer client.Close()
		done := make(chan error, 1)
		metadata := adapter.InboundContext{
			Destination:  M.ParseSocksaddr("rebind.test:80"),
			ScriptClient: scriptClient,
		}
		manager.NewConnection(context.Background(), outbound, inbound, metadata, func(err error) { done <- err })
		go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\n\r\n")) }()
		buffer := make([]byte, 64)
		_ = outbound.server.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := outbound.server.Read(buffer)
		select {
		case closeErr = <-done:
		case <-time.After(200 * time.Millisecond):
		}
		outbound.server.Close()
		inbound.Close()
		return closeErr, buffer[:n], outbound.server
	}
	err, received, _ := run(true)
	if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
		t.Fatalf("script client: close error %v", err)
	}
	if len(received) != 0 {
		t.Fatalf("bytes reached the refused target: %q", received)
	}
	_, received, _ = run(false)
	if string(received) != "GET / HTTP/1.1\r\n\r\n"[:len(received)] || len(received) == 0 {
		t.Fatalf("ordinary connection not served: %q", received)
	}
}
