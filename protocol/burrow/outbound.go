package burrow

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/getkiko/burrow"
)

// buildSignalAddr joins server, server_port and signal_path into the SDK
// SignalAddr.
//
// The signaling endpoint looks like "<path prefix>?command=xxx", where the
// prefix is the URL path built here. A path already present in server wins;
// signalPath is only added when server has no path.
func buildSignalAddr(server string, port uint16, signalPath string) string {
	if strings.Contains(server, "://") {
		u, err := url.Parse(server)
		if err == nil && u.Host != "" {
			if u.Port() == "" && port != 0 {
				u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(int(port)))
			}
			if strings.Trim(u.Path, "/") == "" {
				u.Path = normalizeSignalPath(signalPath)
			}
			return u.String()
		}
	}
	hostPort := net.JoinHostPort(server, strconv.Itoa(int(port)))
	if path := normalizeSignalPath(signalPath); path != "" {
		return "ws://" + hostPort + path
	}
	return hostPort
}

// normalizeSignalPath adds a leading slash and drops trailing slashes from the
// path prefix. An empty path stays empty.
func normalizeSignalPath(path string) string {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.BurrowOutboundOptions](registry, C.TypeBurrow, NewOutbound)
}

// errNoBindInterface is the panic message used when no bind interface can be
// determined.
//
// burrow must bind to a concrete physical interface: bound to 0.0.0.0, the
// kernel may pick an unroutable source address from a virtual interface such
// as a Docker bridge, so the SYN leaves through the wrong interface and hole
// punching always fails. Silently falling back to kernel routing would only
// show up later as unexplained punch timeouts, so this panics and exposes the
// missing configuration at startup instead of at runtime.
const errNoBindInterface = "burrow: cannot determine the bind interface, " +
	"set bind_interface, route.default_interface or route.auto_detect_interface: true"

// socketBinding connects the sockets burrow creates itself to the sing-box
// outbound interface selection. An explicit bind_interface wins, then
// route.default_interface, then the default interface detected by
// route.auto_detect_interface.
//
// It panics when none of them provides an interface; see errNoBindInterface.
//
// The third return value looks up the address of the configured address
// family by interface name; see interfaceAddrFunc.
func socketBinding(ctx context.Context, bindInterface, addressFamily string, logger log.ContextLogger) (func() string, func(network, address string, c syscall.RawConn) error, func(string) string) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	interfaceName, socketControl := socketBindingForNetworkManager(networkManager, bindInterface, logger)
	return interfaceName, socketControl, interfaceAddrFunc(networkManager, addressFamily, logger)
}

type interfaceBindingManager interface {
	InterfaceFinder() control.InterfaceFinder
	DefaultNetworkInterface() *adapter.NetworkInterface
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	DefaultOptions() adapter.NetworkOptions
}

func socketBindingForNetworkManager(networkManager interfaceBindingManager, bindInterface string, logger log.ContextLogger) (func() string, control.Func) {
	if bindInterface != "" {
		return func() string { return bindInterface }, bindInterfaceControl(networkManager, bindInterface, logger)
	}
	if networkManager == nil {
		panic(errNoBindInterface)
	}
	defaultInterface := networkManager.DefaultOptions().BindInterface
	if defaultInterface != "" {
		return func() string { return defaultInterface }, bindInterfaceControl(networkManager, defaultInterface, logger)
	}
	if !networkManager.AutoDetectInterface() {
		panic(errNoBindInterface)
	}
	return func() string {
		currentInterface := networkManager.DefaultNetworkInterface()
		if currentInterface == nil {
			// auto_detect_interface is enabled but finds no default interface
			// (for example with the network down). An empty name would mean
			// no binding at all, which is just as fatal.
			panic(errNoBindInterface)
		}
		return currentInterface.Name
	}, networkManager.AutoDetectInterfaceFunc()
}

// interfaceAddrFunc returns a function that looks up an interface address by
// interface name and address family for the burrow SDK.
//
// The Android platform interface (VpnService) fills the InterfaceFinder
// directly. On standalone Linux binaries the IPv4 path reads the address with
// SIOCGIFADDR. IPv6 global addresses come from the InterfaceFinder, and the SDK
// keeps its net.InterfaceByName/Addrs fallback.
func interfaceAddrFunc(networkManager interfaceBindingManager, addressFamily string, logger log.ContextLogger) func(string) string {
	if networkManager == nil {
		return nil
	}
	wantIPv6 := addressFamily == burrow.AddressFamilyIPv6
	finder := networkManager.InterfaceFinder()
	return func(name string) string {
		if finder != nil {
			iif, err := finder.ByName(name)
			if err == nil {
				for _, prefix := range iif.Addresses {
					addr := prefix.Addr().Unmap()
					if usableInterfaceAddr(addr, wantIPv6) {
						if logger != nil {
							logger.Debug("[burrow] interface ", name, " address resolved by finder: ", addr)
						}
						return addr.String()
					}
				}
				if logger != nil {
					logger.Debug("[burrow] finder returned no usable address for interface ", name, " and address family ", addressFamily)
				}
			} else if logger != nil {
				logger.Debug("[burrow] finder lookup failed for interface ", name, ": ", err)
			}
		}
		if wantIPv6 {
			return ""
		}
		address, supported, err := systemInterfaceIPv4(name)
		if !supported {
			return ""
		}
		if err != nil {
			if logger != nil {
				logger.Warn("[burrow] SIOCGIFADDR failed for interface ", name, ": ", err)
			}
			return ""
		}
		if !address.Is4() || address.IsLoopback() || address.IsUnspecified() {
			if logger != nil {
				logger.Warn("[burrow] SIOCGIFADDR returned unusable IPv4 for interface ", name, ": ", address)
			}
			return ""
		}
		if logger != nil {
			logger.Info("[burrow] interface ", name, " IPv4 resolved by SIOCGIFADDR: ", address)
		}
		return address.String()
	}
}

func usableInterfaceAddr(addr netip.Addr, wantIPv6 bool) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
		return false
	}
	if wantIPv6 {
		return addr.Is6()
	}
	return addr.Is4()
}

// bindInterfaceControl resolves the interface name to an index with ioctl for
// every socket on Linux and lets the sing control bind with SO_BINDTOIFINDEX.
// An explicit bind_interface then does not depend on the finder's netlink
// lookup and follows an interface that is recreated with a new index. Other
// platforms use the control's own binding.
func bindInterfaceControl(networkManager interfaceBindingManager, interfaceName string, logger log.ContextLogger) control.Func {
	var finder control.InterfaceFinder
	if networkManager != nil {
		finder = networkManager.InterfaceFinder()
	} else {
		interfaceFinder := control.NewDefaultInterfaceFinder()
		_ = interfaceFinder.Update()
		finder = interfaceFinder
	}
	interfaceIndex, supported, err := systemInterfaceIndex(interfaceName)
	if !supported {
		return control.BindToInterface(finder, interfaceName, -1)
	}
	var lastInterfaceIndex atomic.Int64
	if err == nil {
		lastInterfaceIndex.Store(int64(interfaceIndex))
		if logger != nil {
			logger.Info("[burrow] interface ", interfaceName, " index resolved by SIOCGIFINDEX: ", interfaceIndex, "; binding sockets with SO_BINDTOIFINDEX")
		}
	} else {
		if logger != nil {
			logger.Warn("[burrow] SIOCGIFINDEX failed for interface ", interfaceName, ": ", err, "; binding sockets by interface name")
		}
	}
	return func(network string, address string, conn syscall.RawConn) error {
		currentIndex, _, lookupErr := systemInterfaceIndex(interfaceName)
		if lookupErr != nil {
			previousIndex := lastInterfaceIndex.Swap(0)
			if previousIndex > 0 && logger != nil {
				logger.Warn("[burrow] SIOCGIFINDEX failed for interface ", interfaceName, " after index ", previousIndex, ": ", lookupErr, "; binding socket by interface name")
			}
			return control.BindToInterface0(finder, conn, network, address, interfaceName, -1, true)
		}
		previousIndex := lastInterfaceIndex.Swap(int64(currentIndex))
		if logger != nil {
			switch {
			case previousIndex == 0:
				logger.Info("[burrow] SIOCGIFINDEX recovered for interface ", interfaceName, "; current index: ", currentIndex)
			case previousIndex != int64(currentIndex):
				logger.Info("[burrow] interface ", interfaceName, " index changed from ", previousIndex, " to ", currentIndex)
			}
		}
		return control.BindToInterface0(finder, conn, network, address, interfaceName, currentIndex, false)
	}
}

type Outbound struct {
	outbound.Adapter
	logger       log.ContextLogger
	dialer       *burrow.Dialer       // TCP hole punching; non-nil when network contains "tcp"
	packetDialer *burrow.PacketDialer // UDP hole punching; non-nil when network contains "udp"
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BurrowOutboundOptions) (adapter.Outbound, error) {
	resolveIP, err := newSignalResolver(ctx, options.DomainResolver)
	if err != nil {
		return nil, err
	}
	resolveIP, err = newSignalResolverWithHosts(options.Hosts, resolveIP)
	if err != nil {
		return nil, err
	}
	interfaceName, socketControl, interfaceAddr := socketBinding(ctx, options.BindInterface, options.AddressFamily, logger)
	packetInterfaceAddr := interfaceAddrFunc(service.FromContext[adapter.NetworkManager](ctx), burrow.AddressFamilyIPv4, logger)
	signalAddr := buildSignalAddr(options.Server, options.ServerPort, options.SignalPath)

	networks := networkList(options.Network)
	out := &Outbound{logger: logger}
	var adapterNetworks []string

	if common.Contains(networks, N.NetworkTCP) {
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
		out.dialer, err = burrow.NewDialer(config)
		if err != nil {
			return nil, err
		}
		adapterNetworks = append(adapterNetworks, N.NetworkTCP)
	}
	if common.Contains(networks, N.NetworkUDP) {
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
		out.packetDialer, err = burrow.NewPacketDialer(packetConfig)
		if err != nil {
			return nil, err
		}
		adapterNetworks = append(adapterNetworks, N.NetworkUDP)
	}
	if len(adapterNetworks) == 0 {
		return nil, E.New("burrow: network must contain at least one of tcp/udp")
	}
	// No DialerOptions: burrow is the end of the chain and has no upstream detour.
	out.Adapter = outbound.NewAdapter(C.TypeBurrow, tag, adapterNetworks, nil)
	return out, nil
}

// DialContext ignores destination and returns a fresh raw net.Conn for every
// punch. burrow finds the peer through SignalAddr and Room; the protocol
// carried over the detour handles the real destination.
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if h.dialer == nil {
			return nil, os.ErrInvalid
		}
		h.logger.DebugContext(ctx, "burrow outbound connection")
		conn, err := h.dialer.Dial(ctx)
		if err != nil {
			return nil, markNonRetryable(err)
		}
		return conn, nil
	case N.NetworkUDP:
		if h.packetDialer == nil {
			return nil, os.ErrInvalid
		}
		h.logger.DebugContext(ctx, "burrow outbound udp connection")
		attempt, err := h.packetDialer.DialPacket(ctx)
		if err != nil {
			return nil, markNonRetryable(err)
		}
		// With direct and predictive, Paths always has length 1 (an SDK
		// contract), so Commit(0) is the only valid candidate; the SDK already
		// rejects birthday and auto. peer is the punched address and is only
		// used for diagnostics; Commit does not check it. The handshake of the
		// inner UDP protocol proves that the candidate works.
		var peer netip.AddrPort
		if len(attempt.Paths) > 0 && len(attempt.Paths[0].Remotes) > 0 {
			peer = attempt.Paths[0].Remotes[0]
		}
		packetConn, err := attempt.Commit(0, peer)
		if err != nil {
			_ = attempt.Close()
			return nil, err
		}
		// Wrap the net.PacketConn as a net.Conn with destination as the fixed
		// peer, so that NewUnbindPacketConnWithAddr of the inner UDP protocol
		// can unwrap it back to packet semantics. bindPacketConn.Close goes
		// through the embedded NetPacketConn.Close and closes the underlying
		// *net.UDPConn (see sing/common/bufio/bind.go).
		return bufio.NewBindPacketConn(packetConn, destination.UDPAddr()), nil
	default:
		return nil, os.ErrInvalid
	}
}

// markNonRetryable marks punch failures that retrying cannot fix, so the retry
// layer above gives up early.
//
// A room without a listener means the server side is not online, and retrying
// only repeats a request that is bound to fail. A signaling rate limit means
// the server already rejects us, and retrying deepens the limit. In practice
// the two amplify each other: retries exhaust the limit, and the limit is
// retried again as a retryable error.
func markNonRetryable(err error) error {
	if errors.Is(err, burrow.ErrNoListener) || errors.Is(err, burrow.ErrResourceLimit) {
		return &dialer.NonRetryableError{Err: err}
	}
	return err
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) InterfaceUpdated() {
	if h.dialer != nil {
		h.dialer.ResetSignal()
	}
	if h.packetDialer != nil {
		h.packetDialer.ResetSignal()
	}
}

func (h *Outbound) Close() error {
	var err error
	if h.dialer != nil {
		err = h.dialer.Close()
	}
	if h.packetDialer != nil {
		if cerr := h.packetDialer.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
