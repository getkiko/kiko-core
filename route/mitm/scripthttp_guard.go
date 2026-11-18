package mitm

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
)

// scriptAllowLocal switches the target restrictions of the script $httpClient off. Tests that
// serve their origin on loopback set it through SetScriptHTTPAllowLocal; the core never does.
var scriptAllowLocal atomic.Bool

// SetScriptHTTPAllowLocal lets the script $httpClient reach loopback, private and own
// addresses. For tests only.
func SetScriptHTTPAllowLocal(allow bool) {
	scriptAllowLocal.Store(allow)
}

// ScriptAddressRefused names why the script $httpClient must not connect to an address, or
// returns "": loopback, unspecified, link-local, multicast, private (RFC 1918, ULA) addresses,
// the addresses of this machine (which covers the core's own control ports, as the whole
// machine is off limits), also when an IPv6 address embeds one of those IPv4 addresses.
func (e *Engine) ScriptAddressRefused(addr netip.Addr) string {
	if scriptAllowLocal.Load() {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return "invalid address"
	}
	if addr.Is6() {
		raw := addr.As16()
		if embedded, ok := embeddedIPv4(raw); ok {
			if reason := e.ScriptAddressRefused(embedded); reason != "" {
				return reason
			}
		}
	}
	switch {
	case addr.IsLoopback():
		return "loopback address"
	case addr.IsUnspecified() || addr.Is4() && addr.As4()[0] == 0:
		return "unspecified address"
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast():
		return "link-local address"
	case addr.IsMulticast():
		return "multicast address"
	case addr.IsPrivate():
		return "private address"
	case addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "broadcast address"
	}
	if e.local != nil && e.local.contains(addr) {
		return "address of this machine"
	}
	return ""
}

// embeddedIPv4 returns the IPv4 address that a NAT64 (64:ff9b::/96), IPv4-compatible (::/96)
// or 6to4 (2002::/16) address carries.
func embeddedIPv4(raw [16]byte) (netip.Addr, bool) {
	zeros := true
	for _, b := range raw[:12] {
		if b != 0 {
			zeros = false
			break
		}
	}
	switch {
	case zeros:
		return netip.AddrFrom4([4]byte(raw[12:16])), true
	case raw[0] == 0x00 && raw[1] == 0x64 && raw[2] == 0xff && raw[3] == 0x9b && allZero(raw[4:12]):
		return netip.AddrFrom4([4]byte(raw[12:16])), true
	case raw[0] == 0x20 && raw[1] == 0x02:
		return netip.AddrFrom4([4]byte(raw[2:6])), true
	}
	return netip.Addr{}, false
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// scriptHostRefused returns the reason the script $httpClient must not connect to a host
// (as the URL gives it, without brackets), or "". Literal addresses go through
// ScriptAddressRefused; names are refused when they are localhost, a subdomain of it, or
// shaped like one of the legacy numeric IPv4 spellings (127.1, 2130706433, 0x7f.1, 0177.0.0.1)
// that a system resolver may accept. Other names are checked after the dial, see
// ConnectionManager.scriptAddressRefused.
func (e *Engine) scriptHostRefused(host string) string {
	if scriptAllowLocal.Load() {
		return ""
	}
	host = strings.ToLower(host)
	if host == "" {
		return "empty host"
	}
	if strings.ContainsAny(host, "%\x00 \t\r\n") {
		return "invalid host"
	}
	trimmed := strings.TrimRight(host, ".")
	if trimmed == "" {
		return "empty host"
	}
	if trimmed == "localhost" || strings.HasSuffix(trimmed, ".localhost") {
		return "localhost"
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return e.ScriptAddressRefused(addr)
	}
	if strings.Contains(trimmed, ":") {
		return "invalid host"
	}
	last := trimmed[strings.LastIndexByte(trimmed, '.')+1:]
	if numericLabel(last) {
		return "ambiguous numeric address"
	}
	return ""
}

// numericLabel reports whether a label is all decimal digits or 0x followed by hex digits:
// the spellings inet_aton accepts as an IPv4 part.
func numericLabel(label string) bool {
	if label == "" {
		return false
	}
	if len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
		for _, c := range label[2:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	for _, c := range label {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// scriptTargetRefused checks a "host:port" dial address.
func (e *Engine) scriptTargetRefused(address string) (host string, port uint16, reason string) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, "invalid address"
	}
	value, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || value == 0 {
		return "", 0, "invalid port"
	}
	return host, uint16(value), e.scriptHostRefused(host)
}
