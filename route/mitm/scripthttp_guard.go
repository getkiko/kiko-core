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
		if raw[0] == 0x00 && raw[1] == 0x64 && raw[2] == 0xff && raw[3] == 0x9b && raw[4] == 0x00 && raw[5] == 0x01 {
			// 64:ff9b:1::/48 is the local-use NAT64 prefix: it reaches the local network.
			return "private address"
		}
		for _, embedded := range embeddedIPv4s(raw) {
			if reason := e.ScriptAddressRefused(embedded); reason != "" {
				return reason
			}
		}
	}
	if addr.Is4() && specialIPv4(addr) {
		return "private address"
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

// embeddedIPv4s returns the IPv4 addresses that a NAT64 (64:ff9b::/96), IPv4-compatible
// (::/96), 6to4 (2002::/16), Teredo (2001::/32: server and client) or ISATAP address carries.
func embeddedIPv4s(raw [16]byte) []netip.Addr {
	zeros := true
	for _, b := range raw[:12] {
		if b != 0 {
			zeros = false
			break
		}
	}
	switch {
	case zeros:
		return []netip.Addr{netip.AddrFrom4([4]byte(raw[12:16]))}
	case raw[0] == 0x00 && raw[1] == 0x64 && raw[2] == 0xff && raw[3] == 0x9b && allZero(raw[4:12]):
		return []netip.Addr{netip.AddrFrom4([4]byte(raw[12:16]))}
	case raw[0] == 0x20 && raw[1] == 0x02:
		return []netip.Addr{netip.AddrFrom4([4]byte(raw[2:6]))}
	case raw[0] == 0x20 && raw[1] == 0x01 && raw[2] == 0 && raw[3] == 0:
		client := [4]byte{raw[12] ^ 0xff, raw[13] ^ 0xff, raw[14] ^ 0xff, raw[15] ^ 0xff}
		return []netip.Addr{netip.AddrFrom4([4]byte(raw[4:8])), netip.AddrFrom4(client)}
	case (raw[8] == 0x00 || raw[8] == 0x02) && raw[9] == 0x00 && raw[10] == 0x5e && raw[11] == 0xfe:
		return []netip.Addr{netip.AddrFrom4([4]byte(raw[12:16]))}
	}
	return nil
}

// specialIPv4 reports the IPv4 ranges that lead to internal networks and that IsPrivate
// does not cover: carrier-grade NAT (also the Tailscale range), the IETF protocol
// assignments and the reserved class E. The benchmarking range stays open: proxy tools
// hand out fake IP addresses from it.
func specialIPv4(addr netip.Addr) bool {
	b := addr.As4()
	switch {
	case b[0] == 100 && b[1]&0xc0 == 64:
		return true
	case b[0] == 192 && b[1] == 0 && b[2] == 0:
		return true
	case b[0] >= 240:
		return true
	}
	return false
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
	if trimmed == "localhost" || strings.HasSuffix(trimmed, ".localhost") || trimmed == "localhost.localdomain" {
		return "localhost"
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return e.ScriptAddressRefused(addr)
	}
	if strings.Contains(trimmed, ":") {
		return "invalid host"
	}
	if strings.HasSuffix(trimmed, ".local") || strings.HasSuffix(trimmed, ".localdomain") || strings.HasSuffix(trimmed, ".internal") || strings.HasSuffix(trimmed, ".lan") || strings.HasSuffix(trimmed, ".home.arpa") || !strings.Contains(trimmed, ".") {
		return "local name"
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
