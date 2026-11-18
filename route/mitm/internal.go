package mitm

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	E "github.com/sagernet/sing/common/exceptions"
)

// SetControlEndpoints tells the engine the listen addresses of the core's own control APIs
// ("host:port" or ":port"). An internal rewrite whose target is a loopback or unspecified
// address on one of these ports is refused (the rule counts as not matching), so that a
// rewrite rule cannot be aimed at the API of the core itself. Names that merely resolve to
// loopback are not recognized.
func (e *Engine) SetControlEndpoints(addresses ...string) {
	var ports []int
	for _, address := range addresses {
		if address == "" {
			continue
		}
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(port); err == nil && n > 0 {
			ports = append(ports, n)
		}
	}
	e.controlPorts.Store(&ports)
}

// SetListenPorts adds the ports of the core's other listeners (inbounds, services) to the
// ports internal rewrites must not reach on this machine.
func (e *Engine) SetListenPorts(ports ...int) {
	var kept []int
	for _, port := range ports {
		if port > 0 && port <= 65535 {
			kept = append(kept, port)
		}
	}
	e.listenPorts.Store(&kept)
}

var (
	protectedMu    sync.Mutex
	protectedPorts = map[int]int{}
)

// ProtectPort marks a port of a listener in this process as off limits to internal
// rewrites aimed at this machine, for every engine. It serves programs that embed the core; the desktop app runs the core as a separate process
// and lists its own ports in http_rewrite.protected_ports instead (app/mitm_ports.go). The
// returned function removes the mark; calling it twice is harmless.
func ProtectPort(port int) (release func()) {
	if port <= 0 || port > 65535 {
		return func() {}
	}
	protectedMu.Lock()
	protectedPorts[port]++
	protectedMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			protectedMu.Lock()
			if protectedPorts[port]--; protectedPorts[port] <= 0 {
				delete(protectedPorts, port)
			}
			protectedMu.Unlock()
		})
	}
}

func portProtected(port int) bool {
	protectedMu.Lock()
	defer protectedMu.Unlock()
	return protectedPorts[port] > 0
}

// metadataAddresses are cloud metadata services outside the link-local ranges.
var metadataAddresses = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
}

// denyInternal is the guard of internal rewrite targets. Refused: link-local addresses and
// the metadata services always (also when an IPv6 address embeds one); an address of this
// machine (loopback, unspecified, one of its interface addresses, "localhost") on a port some
// listener of the core or the app owns: the control APIs, every inbound and service, and the
// ports registered with ProtectPort. Other ports of this machine and hosts of the local
// network stay reachable, as rules may point a name at a development server or a NAS.
func (e *Engine) denyInternal(host string, port int) bool {
	return e.denyInternalWith(host, port, nil)
}

// denyInternalWith is denyInternal with further protected ports (the configured
// http_rewrite.protected_ports).
func (e *Engine) denyInternalWith(host string, port int, extra []int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return e.localName(host) && e.portListened(port, extra)
	}
	return e.denyInternalAddr(addr.WithZone(""), port, 0, extra)
}

func (e *Engine) denyInternalAddr(addr netip.Addr, port int, depth int, extra []int) bool {
	addr = addr.Unmap()
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	for _, metadata := range metadataAddresses {
		if addr == metadata {
			return true
		}
	}
	if addr.Is6() && depth < 2 {
		for _, embedded := range embeddedIPv4s(addr.As16()) {
			if e.denyInternalAddr(embedded, port, depth+1, extra) {
				return true
			}
		}
	}
	if addr.IsLoopback() || addr.IsUnspecified() || e.local != nil && e.local.contains(addr) {
		return e.portListened(port, extra)
	}
	return false
}

// InternalAddressRefused reports whether an internal rewrite whose dial ended at addr:port
// (a host name that resolved there) must be refused: the same rule as for a literal target.
func (e *Engine) InternalAddressRefused(addr netip.Addr, port int) bool {
	var extra []int
	if config := e.config.Load(); config != nil {
		extra = config.protectedPorts
	}
	return e.denyInternalAddr(addr.WithZone(""), port, 0, extra)
}

func (e *Engine) localName(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "localhost.localdomain"
}

func (e *Engine) portListened(port int, extra []int) bool {
	if portProtected(port) {
		return true
	}
	for _, p := range extra {
		if p == port {
			return true
		}
	}
	for _, list := range []*[]int{e.controlPorts.Load(), e.listenPorts.Load()} {
		if list == nil {
			continue
		}
		for _, p := range *list {
			if p == port {
				return true
			}
		}
	}
	return false
}

// internalDialer returns the function the HTTP engines use for a request that an internal
// rewrite sends to another origin: a connection dialed through the outbound of the decrypted
// connection and, for an https target, handshaken like an upstream (new server name,
// certificate verification, fingerprint) with ALPN http/1.1 only. nil without a dialer.
func (e *Engine) internalDialer(metadata *adapter.InboundContext) func(ctx context.Context, in *rewrite.Internal) (net.Conn, error) {
	redialTo := metadata.MITMRedialTo
	if redialTo == nil {
		return nil
	}
	return func(ctx context.Context, in *rewrite.Internal) (net.Conn, error) {
		secure := in.Scheme == "https"
		raw, err := redialTo(ctx, in.Host, uint16(in.Port), secure)
		if err != nil {
			e.logger.WarnContext(ctx, "internal rewrite ", in.Host, ": ", err)
			return nil, err
		}
		raw = withDeadlineReader(raw)
		if !secure {
			return raw, nil
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
		defer cancel()
		conn, _, _, err := e.handshakeUpstream(handshakeCtx, e.config.Load(), raw, in.Host, uint16(in.Port), []string{protocolHTTP1})
		if err != nil {
			raw.Close()
			err = E.Cause(err, "upstream TLS handshake to ", in.Host)
			e.logger.WarnContext(ctx, "internal rewrite ", in.Host, ": ", err)
			return nil, err
		}
		return conn, nil
	}
}
