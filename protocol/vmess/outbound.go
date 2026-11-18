package vmess

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.VMessOutboundOptions](registry, C.TypeVMess, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	client          *vmess.Client
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	transport       adapter.V2RayClientTransport
	establisher     dialer.ConnectionEstablisher
	packetAddr      bool
	xudp            bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VMessOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeVMess, tag, options.Network.Build(), options.DialerOptions),
		logger:  logger,
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outboundDialer, options.ServerOptions.Build(), common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	establisher := newServerEstablisher(outboundDialer, options.ServerOptions.Build(), outbound.transport, outbound.tlsConfig)
	outbound.establisher = dialer.NewRetryEstablisher(establisher, dialer.RetryOptions{
		Retries: options.HandshakeRetries,
		Logger:  logger,
		Name:    "vmess",
	})
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*vmessDialer)(outbound), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	switch options.PacketEncoding {
	case "":
	case "packetaddr":
		outbound.packetAddr = true
	case "xudp":
		outbound.xudp = true
	default:
		return nil, E.New("unknown packet encoding: ", options.PacketEncoding)
	}
	var clientOptions []vmess.ClientOption
	if timeFunc := ntp.TimeFuncFromContext(ctx); timeFunc != nil {
		clientOptions = append(clientOptions, vmess.ClientWithTimeFunc(timeFunc))
	}
	if options.GlobalPadding {
		clientOptions = append(clientOptions, vmess.ClientWithGlobalPadding())
	}
	if options.AuthenticatedLength {
		clientOptions = append(clientOptions, vmess.ClientWithAuthenticatedLength())
	}
	security := options.Security
	if security == "" {
		security = "auto"
	}
	if security == "auto" && outbound.tlsConfig != nil {
		security = "zero"
	}
	client, err := vmess.NewClient(options.UUID, security, options.AlterId, clientOptions...)
	if err != nil {
		return nil, err
	}
	outbound.client = client
	return outbound, nil
}

func (h *Outbound) MultiplexEnabled() bool {
	if h.multiplexDialer != nil {
		return true
	}
	multiplexTransport, isMultiplexTransport := h.transport.(adapter.V2RayMultiplexClientTransport)
	return isMultiplexTransport && multiplexTransport.MultiplexEnabled()
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper)
	if isTransportKeeper {
		transportKeeper.SetKeepIdleConnections(keep)
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper)
	if isTransportKeeper {
		transportKeeper.CloseIdleConnections()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.CloseIdleConnections()
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.transport != nil {
		scope.Add(h.transport.Close)
	}
	if h.multiplexDialer != nil {
		scope.Add(h.multiplexDialer.Close)
	}
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*vmessDialer)(h).DialContext(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*vmessDialer)(h).ListenPacket(ctx, destination)
	} else {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

type vmessDialer Outbound

func (h *vmessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	conn, err := h.establisher.Establish(ctx)
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialEarlyConn(conn, destination), nil
	case N.NetworkUDP:
		return h.client.DialEarlyPacketConn(conn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vmessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	conn, err := h.establisher.Establish(ctx)
	if err != nil {
		return nil, err
	}
	if h.packetAddr {
		if destination.IsDomain() {
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		return packetaddr.NewConn(h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress}), destination), nil
	} else if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination), nil
	}
}
