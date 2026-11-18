package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// upstreamRoots are the roots that verify upstream certificates: the
// upstream.custom_roots pool when configured, else the core's roots (nil means
// the system roots).
func (e *Engine) upstreamRoots(config *compiledConfig) *x509.CertPool {
	if config.upstream.roots != nil {
		return config.upstream.roots
	}
	return adapter.RootPoolFromContext(e.ctx)
}

// handshakeStandard completes an upstream handshake with crypto/tls offering
// the protocols, and returns the negotiated one (empty without ALPN). A host
// in upstream.skip_verify is not verified.
func (e *Engine) handshakeStandard(ctx context.Context, config *compiledConfig, conn net.Conn, serverName string, port uint16, protocols []string) (net.Conn, *x509.Certificate, string, error) {
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		RootCAs:            e.upstreamRoots(config),
		InsecureSkipVerify: config.upstream.verifySkipped(serverName, port) || config.upstream.appended != nil,
		Time:               e.timeFunc,
		NextProtos:         protocols,
		MinVersion:         tls.VersionTLS12,
	}
	if !config.upstream.verifySkipped(serverName, port) {
		tlsConfig.VerifyConnection = e.verifyConnection(config)
	}
	tlsConn := tls.Client(conn, tlsConfig)
	err := tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, "", E.New("missing peer certificate")
	}
	err = checkNegotiated(protocols, state.NegotiatedProtocol)
	if err != nil {
		return nil, nil, "", err
	}
	return tlsConn, state.PeerCertificates[0], state.NegotiatedProtocol, nil
}
