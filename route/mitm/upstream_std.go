//go:build !with_utls

package mitm

import (
	"context"
	"crypto/x509"
	"net"
)

// handshakeUpstream completes a TLS handshake offering the protocols,
// verified against the configured roots, and returns the negotiated one
// (empty without ALPN). Builds with uTLS apply upstream.fingerprint; this one
// always uses standard TLS.
func (e *Engine) handshakeUpstream(ctx context.Context, config *compiledConfig, conn net.Conn, serverName string, port uint16, protocols []string) (net.Conn, *x509.Certificate, string, error) {
	return e.handshakeStandard(ctx, config, conn, serverName, port, protocols)
}
