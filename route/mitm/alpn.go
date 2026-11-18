package mitm

import (
	"slices"

	"github.com/sagernet/sing-box/common/mitm/h2"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	protocolHTTP1 = "http/1.1"
	protocolH2    = "h2"
)

// h2Supported reports whether this build can relay HTTP/2; a variable so tests
// can switch it.
var h2Supported = h2.Supported

// unknownOnly reports whether the client offers ALPN protocols but none the
// engine speaks. Such a client is served HTTP/1.1 without ALPN, as before h2.
func unknownOnly(clientProtocols []string) bool {
	return len(clientProtocols) > 0 &&
		!slices.Contains(clientProtocols, protocolH2) &&
		!slices.Contains(clientProtocols, protocolHTTP1)
}

// offerProtocols returns the protocols to offer upstream: the client's offer
// narrowed to what the engine speaks (h2 only when enabled), h2 first. A client
// without ALPN, or with only unknown protocols, speaks HTTP/1.1. The result is
// empty when nothing is shared (a client that wants h2 only while h2 is off).
func offerProtocols(clientProtocols []string, h2 bool) []string {
	if len(clientProtocols) == 0 || unknownOnly(clientProtocols) {
		return []string{protocolHTTP1}
	}
	var offer []string
	if h2 && slices.Contains(clientProtocols, protocolH2) {
		offer = append(offer, protocolH2)
	}
	if slices.Contains(clientProtocols, protocolHTTP1) {
		offer = append(offer, protocolHTTP1)
	}
	return offer
}

// checkNegotiated rejects a protocol the upstream picked that was not offered.
// An empty result is HTTP/1.1 and valid only when that was offered.
func checkNegotiated(offered []string, negotiated string) error {
	switch negotiated {
	case "":
		if !slices.Contains(offered, protocolHTTP1) {
			return E.New("upstream did not negotiate an application protocol")
		}
	case protocolH2, protocolHTTP1:
		if !slices.Contains(offered, negotiated) {
			return E.New("unexpected application protocol: ", negotiated)
		}
	default:
		return E.New("unexpected application protocol: ", negotiated)
	}
	return nil
}

// clientProtocol returns the ALPN value for the client side, given the
// client's offer and the protocol the upstream negotiated: exactly the
// upstream's protocol. An empty value means the client offered no ALPN and
// speaks HTTP/1.1 without it.
func clientProtocol(clientProtocols []string, upstreamProtocol string) (string, error) {
	if upstreamProtocol == "" {
		upstreamProtocol = protocolHTTP1
	}
	if len(clientProtocols) == 0 {
		if upstreamProtocol != protocolHTTP1 {
			return "", E.New("unexpected application protocol: ", upstreamProtocol)
		}
		return "", nil
	}
	if upstreamProtocol == protocolHTTP1 && unknownOnly(clientProtocols) {
		return "", nil
	}
	if !slices.Contains(clientProtocols, upstreamProtocol) {
		return "", E.New("client does not support ", upstreamProtocol, " negotiated by the upstream")
	}
	return upstreamProtocol, nil
}
