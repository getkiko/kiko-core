package mitm

import (
	"crypto/x509"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/hostmatch"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	quicBlock = "block"
	quicAllow = "allow"

	fingerprintNone    = "none"
	fingerprintChrome  = "chrome"
	fingerprintSafari  = "safari"
	fingerprintFirefox = "firefox"

	sourceLocal = "local"
)

// deviceScope is the compiled `sources` option.
type deviceScope struct {
	local    bool
	prefixes []netip.Prefix
}

func compileScope(sources []string) (deviceScope, error) {
	if len(sources) == 0 {
		return deviceScope{local: true}, nil
	}
	var scope deviceScope
	for _, entry := range sources {
		entry = strings.TrimSpace(entry)
		switch {
		case strings.EqualFold(entry, sourceLocal):
			scope.local = true
		case strings.Contains(entry, "/"):
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return deviceScope{}, E.Cause(err, "sources: invalid CIDR ", strconv.Quote(entry))
			}
			if prefix.Addr().Zone() != "" {
				return deviceScope{}, E.New("sources: zoned CIDR ", strconv.Quote(entry))
			}
			if prefix.Addr().Is4In6() {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), max(prefix.Bits()-96, 0))
			}
			scope.prefixes = append(scope.prefixes, prefix.Masked())
		default:
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				return deviceScope{}, E.New("sources: ", strconv.Quote(entry), " is neither `local`, an IP address nor a CIDR prefix")
			}
			if addr.Zone() != "" {
				return deviceScope{}, E.New("sources: zoned address ", strconv.Quote(entry))
			}
			addr = addr.Unmap()
			scope.prefixes = append(scope.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return scope, nil
}

// contains reports whether a client at source is in scope. A connection
// without a source address (an inbound that has none) is local.
func (s *deviceScope) contains(source netip.Addr, local *localAddresses) bool {
	if !source.IsValid() {
		return s.local
	}
	source = source.Unmap().WithZone("")
	for i := range s.prefixes {
		if s.prefixes[i].Contains(source) {
			return true
		}
	}
	return s.local && local.contains(source)
}

// localRefreshInterval bounds how stale the cached interface addresses get.
const localRefreshInterval = 5 * time.Second

// localAddresses is the cached set of this machine's addresses. Connections
// from this machine, including those captured by the TUN inbound, carry one
// of them as their source (the TUN interface address when the route sends
// them through the TUN), or a loopback address. Only exact interface
// addresses count: the subnet of a LAN interface also holds gateway devices.
// A lookup never blocks: stale data is used while a refresh runs in the
// background.
type localAddresses struct {
	lookup     func() ([]net.Addr, error)
	now        func() time.Time
	snapshot   atomic.Pointer[localSnapshot]
	refreshing atomic.Bool
}

type localSnapshot struct {
	addrs map[netip.Addr]struct{}
	// tiny holds the subnets of point-to-point style interfaces (at most four
	// addresses, like a TUN's /30), whose peers are this machine's own stack.
	tiny []netip.Prefix
	at   time.Time
}

func newLocalAddresses() *localAddresses {
	local := &localAddresses{lookup: net.InterfaceAddrs, now: time.Now}
	local.refresh()
	return local
}

func (l *localAddresses) refresh() {
	addrs, err := l.lookup()
	snapshot := &localSnapshot{addrs: make(map[netip.Addr]struct{}, len(addrs)), at: l.now()}
	if err != nil {
		// Keep the previous addresses when enumeration fails.
		if previous := l.snapshot.Load(); previous != nil {
			snapshot.addrs = previous.addrs
			snapshot.tiny = previous.tiny
		}
	}
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		parsed, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		parsed = parsed.Unmap().WithZone("")
		snapshot.addrs[parsed] = struct{}{}
		if network, isNetwork := addr.(*net.IPNet); isNetwork {
			ones, bits := network.Mask.Size()
			prefixBits := ones - (bits - parsed.BitLen())
			if bits != 0 && bits-ones <= 2 && prefixBits > 0 {
				if prefix, err := parsed.Prefix(prefixBits); err == nil {
					snapshot.tiny = append(snapshot.tiny, prefix)
				}
			}
		}
	}
	l.snapshot.Store(snapshot)
}

func (l *localAddresses) contains(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	snapshot := l.snapshot.Load()
	if snapshot != nil {
		if _, loaded := snapshot.addrs[addr]; loaded {
			return true
		}
		for i := range snapshot.tiny {
			if snapshot.tiny[i].Contains(addr) {
				return true
			}
		}
	}
	if snapshot == nil || l.now().Sub(snapshot.at) >= localRefreshInterval {
		// A new interface (the TUN starting) shows up within the interval.
		if l.refreshing.CompareAndSwap(false, true) {
			go func() {
				defer l.refreshing.Store(false)
				l.refresh()
			}()
		}
	}
	return false
}

// upstreamConfig is the compiled `upstream` option.
type upstreamConfig struct {
	fingerprint string
	// mirrorHello builds the upstream ClientHello from the client's.
	mirrorHello bool
	// h2Profile is "chrome" or "" (net/http's client).
	h2Profile  string
	skipVerify *hostmatch.Matcher
	// roots verifies upstream certificates; nil uses the core's roots.
	roots *x509.CertPool
	// appended holds only the upstream.custom_roots certificates. It is checked first with
	// pure Go verification (see verifyUpstream).
	appended *x509.CertPool
}

// verifySkipped reports whether the upstream certificate of the host is not
// verified. An entry without a port covers port 443 only.
func (u *upstreamConfig) verifySkipped(serverName string, port uint16) bool {
	if u.skipVerify.Empty() {
		return false
	}
	addr, _ := netip.ParseAddr(serverName)
	if port == 0 {
		port = hostmatch.DefaultPort
	}
	return u.skipVerify.Match(serverName, addr, port)
}

func (e *Engine) compileUpstream(options option.MITMUpstreamOptions) (upstreamConfig, error) {
	var config upstreamConfig
	switch options.Fingerprint {
	case "", fingerprintChrome:
		config.fingerprint = fingerprintChrome
	case fingerprintNone, fingerprintSafari, fingerprintFirefox:
		config.fingerprint = options.Fingerprint
	default:
		return config, E.New("unknown upstream fingerprint: ", options.Fingerprint)
	}
	config.mirrorHello = options.MirrorClientHello
	switch options.H2Profile {
	case "", h2ProfileDefault:
	case h2ProfileChrome:
		config.h2Profile = h2ProfileChrome
	default:
		return config, E.New("unknown upstream h2 profile: ", options.H2Profile)
	}
	var err error
	config.skipVerify, err = hostmatch.New(options.SkipVerify, nil)
	if err != nil {
		return config, E.Cause(err, "upstream skip_verify")
	}
	if len(options.CustomRoots) > 0 {
		var pool *x509.CertPool
		if base := adapter.RootPoolFromContext(e.ctx); base != nil {
			pool = base.Clone()
		} else {
			pool, err = x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
		}
		appended := x509.NewCertPool()
		for _, path := range options.CustomRoots {
			content, err := filemanager.ReadFile(e.ctx, path)
			if err != nil {
				return config, E.Cause(err, "read custom root ", path)
			}
			if !appended.AppendCertsFromPEM(content) || !pool.AppendCertsFromPEM(content) {
				return config, E.New("custom root ", path, " holds no PEM certificate")
			}
		}
		config.roots = pool
		config.appended = appended
	}
	return config, nil
}

func compileQUIC(value string) (bool, error) {
	switch value {
	case "", quicBlock:
		return true, nil
	case quicAllow:
		return false, nil
	default:
		return false, E.New("unknown quic mode: ", value)
	}
}
