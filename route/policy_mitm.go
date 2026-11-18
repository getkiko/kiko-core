package route

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// Values of PolicyTestResult.MITM.
const (
	// PolicyMITMDecrypted: the connection would be decrypted.
	PolicyMITMDecrypted = "decrypted"
	// PolicyMITMPlain: the plaintext HTTP connection would go through the
	// rewrite engine.
	PolicyMITMPlain = "plain"
	// PolicyMITMSkippedPrefix is followed by the engine's reason
	// (authority_pending, a pinned host, a built-in exclusion, ...).
	PolicyMITMSkippedPrefix = "skipped:"
	// PolicyMITMBlockedQUIC: the QUIC connection would be rejected so that
	// the client falls back to TCP.
	PolicyMITMBlockedQUIC = "blocked-quic"
)

// testMITM evaluates the interception policy for a tested connection. The
// engine's Explain and MatchQUIC are read-only. The result is empty when the
// connection is not intercepted.
func (r *Router) testMITM(outboundTag string, metadata *adapter.InboundContext) string {
	if r.mitm == nil {
		return ""
	}
	probe := *metadata
	switch probe.Network {
	case N.NetworkUDP:
		if r.mitm.MatchQUIC(&probe) {
			return PolicyMITMBlockedQUIC
		}
		return ""
	case N.NetworkTCP:
	default:
		return ""
	}
	if probe.Protocol == "" && probe.Destination.Port == 443 {
		probe.Protocol = C.ProtocolTLS
	}
	if outboundTag == "" {
		if defaultOutbound := r.outbound.Default(); defaultOutbound != nil {
			outboundTag = defaultOutbound.Tag()
		}
	}
	if outbound, loaded := r.outbound.Outbound(outboundTag); loaded {
		if chain, err := resolveChain(outbound, N.NetworkTCP, &probe, true); err == nil {
			probe.OutboundChain = chain
		}
	}
	status, reason := r.mitm.Explain(&probe)
	switch status {
	case "decrypted":
		return PolicyMITMDecrypted
	case "plain":
		return PolicyMITMPlain
	case "skipped":
		return PolicyMITMSkippedPrefix + reason
	}
	return ""
}
