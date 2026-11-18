package mitm

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

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

// denyInternal is the guard of internal rewrite targets.
func (e *Engine) denyInternal(host string, port int) bool {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Unmap().IsLinkLocalUnicast() {
		// Cloud metadata services (169.254.169.254) and the like.
		return true
	}
	ports := e.controlPorts.Load()
	if ports == nil || len(*ports) == 0 || !loopbackHost(host) {
		return false
	}
	for _, p := range *ports {
		if p == port {
			return true
		}
	}
	return false
}

func loopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		return addr.IsLoopback() || addr.IsUnspecified()
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
