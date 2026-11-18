package burrow

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/getkiko/burrow"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.BurrowInboundOptions](registry, C.TypeBurrow, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx     context.Context
	router  adapter.Router
	logger  log.ContextLogger
	cfg     burrow.Config       // TCP hole punching; used when network contains "tcp"
	packet  burrow.PacketConfig // UDP hole punching; used when network contains "udp"
	network []string
	detour  string

	listener       *burrow.Listener       // TCP
	packetListener *burrow.PacketListener // UDP
	cancel         context.CancelFunc
	done           chan struct{}
	packetDone     chan struct{}
	wg             sync.WaitGroup
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BurrowInboundOptions) (adapter.Inbound, error) {
	if options.Detour == "" {
		return nil, E.New("burrow inbound requires a detour to the inner protocol inbound")
	}
	resolveIP, err := newSignalResolver(ctx, options.DomainResolver)
	if err != nil {
		return nil, err
	}
	resolveIP, err = newSignalResolverWithHosts(options.Hosts, resolveIP)
	if err != nil {
		return nil, err
	}
	interfaceName, socketControl, interfaceAddr, err := socketBinding(ctx, options.BindInterface, options.AddressFamily, logger)
	if err != nil {
		return nil, err
	}
	packetInterfaceAddr := interfaceAddrFunc(service.FromContext[adapter.NetworkManager](ctx), burrow.AddressFamilyIPv4, logger)
	signalAddr := buildSignalAddr(options.Server, options.ServerPort, options.SignalPath)

	config := burrow.Config{
		SignalAddr:    signalAddr,
		DebugLog:      sdkDebugLog(logger),
		InfoLog:       sdkInfoLog(logger),
		ResolveIP:     resolveIP,
		InterfaceName: interfaceName,
		InterfaceAddr: interfaceAddr,
		Control:       socketControl,
	}
	applySDKOptions(&config, options.BurrowOptions)

	packetConfig := burrow.PacketConfig{
		SignalAddr:    signalAddr,
		DebugLog:      sdkDebugLog(logger),
		InfoLog:       sdkInfoLog(logger),
		ResolveIP:     resolveIP,
		InterfaceName: interfaceName,
		InterfaceAddr: packetInterfaceAddr,
		Control:       socketControl,
	}
	applyPacketSDKOptions(&packetConfig, options.BurrowOptions)

	return &Inbound{
		Adapter:    inbound.NewAdapter(C.TypeBurrow, tag),
		ctx:        ctx,
		router:     router,
		logger:     logger,
		cfg:        config,
		packet:     packetConfig,
		network:    networkList(options.Network),
		detour:     options.Detour,
		done:       make(chan struct{}),
		packetDone: make(chan struct{}),
	}, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(h.Close)
	ctx, cancel := context.WithCancel(h.ctx)
	h.cancel = cancel

	if common.Contains(h.network, N.NetworkTCP) {
		listener, err := burrow.Listen(h.cfg)
		if err != nil {
			cancel()
			return err
		}
		h.listener = listener
		go h.acceptLoop(ctx)
	} else {
		close(h.done) // TCP disabled: close done now so Close does not wait for an accept loop
	}

	if common.Contains(h.network, N.NetworkUDP) {
		packetListener, err := burrow.ListenPacket(h.packet)
		if err != nil {
			cancel()
			if h.listener != nil {
				_ = h.listener.Close()
			}
			return err
		}
		h.packetListener = packetListener
		go h.acceptPacketLoop(ctx)
	} else {
		close(h.packetDone)
	}
	return nil
}

// acceptLoop keeps accepting punched raw connections and hands each one to the
// connection chain in its own goroutine, so that routing or the inner handshake
// of one connection does not block later accepts.
func (h *Inbound) acceptLoop(ctx context.Context) {
	defer close(h.done)
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			if errors.Is(err, burrow.ErrClosed) || ctx.Err() != nil {
				return
			}
			h.logger.ErrorContext(ctx, E.Cause(err, "burrow accept"))
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.handle(ctx, conn)
		}()
	}
}

// handle builds the metadata and injects the raw TCP connection into the inner
// protocol inbound through the detour.
func (h *Inbound) handle(ctx context.Context, conn net.Conn) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.ParseSocksaddr(conn.RemoteAddr().String())
	//nolint:staticcheck
	metadata.InboundDetour = h.detour
	h.logger.InfoContext(ctx, "burrow inbound connection")
	h.router.RouteConnectionEx(log.ContextWithNewID(ctx), conn, metadata, nil)
}

// acceptPacketLoop keeps accepting punched UDP candidates, commits the single
// candidate and injects it through the detour into NewPacketConnectionEx of the
// inner UDP protocol inbound.
func (h *Inbound) acceptPacketLoop(ctx context.Context) {
	defer close(h.packetDone)
	for {
		attempt, err := h.packetListener.AcceptPacket(ctx)
		if err != nil {
			if errors.Is(err, burrow.ErrClosed) || ctx.Err() != nil {
				return
			}
			h.logger.ErrorContext(ctx, E.Cause(err, "burrow accept udp"))
			return
		}
		// With direct and predictive, Paths always has length 1, so Commit(0) is
		// the only valid candidate (as on the outbound side).
		var peer netip.AddrPort
		if len(attempt.Paths) > 0 && len(attempt.Paths[0].Remotes) > 0 {
			peer = attempt.Paths[0].Remotes[0]
		}
		packetConn, cerr := attempt.Commit(0, peer)
		if cerr != nil {
			_ = attempt.Close()
			h.logger.ErrorContext(ctx, E.Cause(cerr, "burrow commit udp candidate"))
			continue
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.handlePacket(ctx, packetConn, peer)
		}()
	}
}

// handlePacket builds the metadata and injects the punched UDP PacketConn
// through the detour into NewPacketConnectionEx of the inner protocol inbound
// (RoutePacketConnectionEx -> UDPInjectable).
func (h *Inbound) handlePacket(ctx context.Context, packetConn net.PacketConn, peer netip.AddrPort) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.SocksaddrFromNetIP(peer)
	//nolint:staticcheck
	metadata.InboundDetour = h.detour
	h.logger.InfoContext(ctx, "burrow inbound udp connection from ", peer)
	h.router.RoutePacketConnectionEx(log.ContextWithNewID(ctx), bufio.NewPacketConn(packetConn), metadata, nil)
}

func (h *Inbound) InterfaceUpdated() {
	if h.listener != nil {
		h.listener.ResetSignal()
	}
	if h.packetListener != nil {
		h.packetListener.ResetSignal()
	}
}

func (h *Inbound) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	var err error
	if h.listener != nil {
		err = h.listener.Close()
		<-h.done // wait for the TCP accept loop to exit
	}
	if h.packetListener != nil {
		if perr := h.packetListener.Close(); perr != nil && err == nil {
			err = perr
		}
		<-h.packetDone // wait for the UDP accept loop to exit
	}
	h.wg.Wait() // wait for in-flight connection and session goroutines
	return err
}
