package daemon

import (
	std_bufio "bufio"
	"context"
	"net"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// OutboundProxyInbound is the inbound tag of connections an outbound proxy
// takes, as Connections show them.
const OutboundProxyInbound = "browser"

// StartOutboundProxy serves an HTTP proxy on a loopback port whose every
// connection goes through the requested outbound, without matching rules,
// for a browser to use that outbound alone. It listens while the stream
// is open: on the requested port, or one of its own, and after a restart
// of the core on the same port again, so a browser keeps working. Each
// event reports the address, or why there is none for now: the core
// stopped, the outbound missing from its configuration.
func (s *StartedService) StartOutboundProxy(request *OutboundProxyRequest, server grpc.ServerStreamingServer[OutboundProxyEvent]) error {
	if request.Outbound == "" {
		return status.Error(codes.InvalidArgument, "outbound is required")
	}
	if request.Port > 65535 {
		return status.Error(codes.InvalidArgument, "invalid port")
	}
	port := int(request.Port)
	return s.followInstance(server.Context(), func(ctx context.Context, instance *Instance) error {
		if instance == nil {
			err := server.Send(&OutboundProxyEvent{Error: "core is not running"})
			if err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		}
		if _, loaded := instance.outboundManager.Outbound(request.Outbound); !loaded {
			err := server.Send(&OutboundProxyEvent{Error: "outbound not found: " + request.Outbound})
			if err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		}
		// An attached service has the router in its context, a started
		// one in its box.
		router := service.FromContext[adapter.Router](instance.ctx)
		if router == nil && instance.instance != nil {
			router = instance.instance.Router()
		}
		if router == nil {
			return status.Error(codes.Unavailable, "router unavailable")
		}
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			return status.Error(codes.Unavailable, E.Cause(err, "listen").Error())
		}
		port = listener.Addr().(*net.TCPAddr).Port
		go func() {
			<-ctx.Done()
			listener.Close()
		}()
		err = server.Send(&OutboundProxyEvent{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
		if err != nil {
			listener.Close()
			return err
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return status.Error(codes.Unavailable, E.Cause(err, "accept").Error())
			}
			go serveOutboundProxy(instance.ctx, router, request.Outbound, conn)
		}
	})
}

// serveOutboundProxy reads a connection's HTTP proxy requests, CONNECT or
// plain, and routes each to outbound.
func serveOutboundProxy(ctx context.Context, router adapter.Router, outbound string, conn net.Conn) {
	source := M.SocksaddrFromNet(conn.RemoteAddr())
	metadata := adapter.InboundContext{
		Inbound:        OutboundProxyInbound,
		InboundType:    C.TypeHTTP,
		Source:         source,
		ForcedOutbound: outbound,
	}
	route := func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
		router.RouteConnectionEx(ctx, conn, metadata, onClose)
	}
	refuse := func(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
		N.CloseOnHandshakeFailure(conn, onClose, E.New("UDP is not supported"))
	}
	onClose := func(error) {}
	err := http.HandleConnectionEx(ctx, conn, std_bufio.NewReader(conn), nil, adapter.NewUpstreamHandler(metadata, route, refuse), source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
	}
}
