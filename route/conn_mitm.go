package route

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// mitmRedial returns the redial function of a decrypted connection: it dials
// the destination again like NewConnection did (same dialer and dial path,
// group dial reports, TLS fragment and spoof wrapping), and meter counts the
// new connection into the session's report, closed once by its onClose.
func (m *ConnectionManager) mitmRedial(this N.Dialer, metadata *adapter.InboundContext, meter *groupMeter) adapter.MITMRedialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		dialStart := time.Now()
		var (
			remoteConn net.Conn
			err        error
		)
		if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
			remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
		}
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			}
			err = E.Cause(err, "reopen connection to ", metadata.Destination, dialerString)
			m.deleteURLTestHistory(metadata.OutboundChain)
			reportGroupDial(metadata, N.NetworkTCP, dialStart, err)
			m.logger.ErrorContext(ctx, err)
			return nil, err
		}
		reportGroupDial(metadata, N.NetworkTCP, dialStart, nil)
		remoteConn = meter.wrap(remoteConn)
		if metadata.TLSFragment || metadata.TLSRecordFragment {
			remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
		}
		if metadata.TLSSpoof != "" {
			spoofConn, spoofErr := tlsspoof.NewConn(remoteConn, metadata.TLSSpoofMethod, metadata.TLSSpoof)
			if spoofErr != nil {
				remoteConn.Close()
				spoofErr = E.Cause(spoofErr, "tls_spoof setup")
				m.logger.ErrorContext(ctx, spoofErr)
				return nil, spoofErr
			}
			remoteConn = spoofConn
		}
		return remoteConn, nil
	}
}

// mitmRedialTo returns the function that dials another origin through the same
// dialer as the connection (internal rewrite), counted into the session's
// report like a redial.
func (m *ConnectionManager) mitmRedialTo(this N.Dialer, metadata *adapter.InboundContext, meter *groupMeter) adapter.MITMRedialToFunc {
	return func(ctx context.Context, host string, port uint16, withTLS bool) (net.Conn, error) {
		destination := M.ParseSocksaddrHostPort(host, port)
		dialStart := time.Now()
		remoteConn, err := this.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			}
			err = E.Cause(err, "open connection to ", destination, dialerString)
			m.deleteURLTestHistory(metadata.OutboundChain)
			reportGroupDial(metadata, N.NetworkTCP, dialStart, err)
			m.logger.ErrorContext(ctx, err)
			return nil, err
		}
		reportGroupDial(metadata, N.NetworkTCP, dialStart, nil)
		if refused := m.internalAddressRefused(this, destination, remoteConn); refused != nil {
			remoteConn.Close()
			m.logger.ErrorContext(ctx, refused)
			return nil, refused
		}
		remoteConn = meter.wrap(remoteConn)
		if !withTLS {
			return remoteConn, nil
		}
		if metadata.TLSFragment || metadata.TLSRecordFragment {
			remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
		}
		if metadata.TLSSpoof != "" {
			spoofConn, spoofErr := tlsspoof.NewConn(remoteConn, metadata.TLSSpoofMethod, metadata.TLSSpoof)
			if spoofErr != nil {
				remoteConn.Close()
				spoofErr = E.Cause(spoofErr, "tls_spoof setup")
				m.logger.ErrorContext(ctx, spoofErr)
				return nil, spoofErr
			}
			remoteConn = spoofConn
		}
		return remoteConn, nil
	}
}

// MITMInternalAllowLoopback lets internal rewrites reach names that resolve to loopback,
// unspecified or link-local addresses. Tests set it; it is never set in the core.
var MITMInternalAllowLoopback bool

// internalAddressRefused rejects a connection that an internal rewrite opened to a host name
// but that ended up at a loopback, unspecified or link-local address (a name pointed at the
// machine itself or at a metadata service). Private ranges stay allowed: rules may map names
// to hosts of the local network. Only a direct outbound shows where a name resolved to; for
// other outbounds the far side resolves it.
func (m *ConnectionManager) internalAddressRefused(this N.Dialer, destination M.Socksaddr, conn net.Conn) error {
	if MITMInternalAllowLoopback || destination.IsIP() {
		return nil
	}
	if outbound, isOutbound := this.(adapter.Outbound); !isOutbound || outbound.Type() != C.TypeDirect {
		return nil
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	addr, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return nil
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
		return E.New("internal rewrite: ", destination.Fqdn, " resolves to a local address (", addr, ")")
	}
	// A private or own address on a port that a listener of the core or the application owns.
	if guard, ok := m.mitm.(internalTargetGuard); ok && guard.InternalAddressRefused(addr, remote.Port) {
		return E.New("internal rewrite: ", destination.Fqdn, " resolves to a protected address (", addr, ":", remote.Port, ")")
	}
	return nil
}

// internalTargetGuard is implemented by the MITM engine: it refuses the addresses and ports
// the internal rewrite guard protects, for a host name that resolved to them.
type internalTargetGuard interface {
	InternalAddressRefused(addr netip.Addr, port int) bool
}

// scriptTargetGuard is implemented by the MITM engine: it names the reason an address is
// off limits to the script $httpClient, or returns "".
type scriptTargetGuard interface {
	ScriptAddressRefused(addr netip.Addr) string
}

// scriptAddressRefused closes the gap that a host name leaves for the script $httpClient:
// the name is only resolved by the dialer, so a direct outbound that ended up at an address
// of this machine or its local network (a name pointed there, DNS rebinding) is refused
// after the dial and before any byte is sent. Other outbounds resolve on the far side, where
// only the name rules apply; a direct outbound with a detour shows the detour's address.
func (m *ConnectionManager) scriptAddressRefused(this N.Dialer, conn net.Conn) error {
	if outbound, isOutbound := this.(adapter.Outbound); !isOutbound || outbound.Type() != C.TypeDirect {
		return nil
	}
	guard, ok := m.mitm.(scriptTargetGuard)
	if !ok {
		return E.New("refused: no target guard")
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	addr, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return nil
	}
	if reason := guard.ScriptAddressRefused(addr); reason != "" {
		return E.New("refused: ", reason, " (", addr.Unmap(), ")")
	}
	return nil
}
