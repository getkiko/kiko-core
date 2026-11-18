//go:build with_utls

package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	E "github.com/sagernet/sing/common/exceptions"

	utls "github.com/metacubex/utls"
)

// clientHelloID maps upstream.fingerprint to a uTLS ClientHello; ok is false
// for `none`.
func clientHelloID(fingerprint string) (utls.ClientHelloID, bool) {
	switch fingerprint {
	case fingerprintSafari:
		return utls.HelloSafari_Auto, true
	case fingerprintFirefox:
		return utls.HelloFirefox_Auto, true
	case fingerprintNone:
		return utls.ClientHelloID{}, false
	default:
		return utls.HelloChrome_Auto, true
	}
}

// handshakeUpstream completes a TLS handshake with the configured
// fingerprint (standard TLS for `none`) whose ALPN offers the protocols,
// verified against the configured roots, and returns the negotiated one
// (empty without ALPN). A host in upstream.skip_verify is not verified.
func (e *Engine) handshakeUpstream(ctx context.Context, config *compiledConfig, conn net.Conn, serverName string, port uint16, protocols []string) (net.Conn, *x509.Certificate, string, error) {
	helloID, fingerprinted := clientHelloID(config.upstream.fingerprint)
	if !fingerprinted {
		return e.handshakeStandard(ctx, config, conn, serverName, port, protocols)
	}
	tlsConfig := &utls.Config{
		ServerName:         serverName,
		RootCAs:            e.upstreamRoots(config),
		InsecureSkipVerify: config.upstream.verifySkipped(serverName, port) || config.upstream.appended != nil,
		Time:               e.timeFunc,
		NextProtos:         protocols,
		MinVersion:         tls.VersionTLS12,
	}
	if !config.upstream.verifySkipped(serverName, port) && config.upstream.appended != nil {
		verify := e.verifyConnection(config)
		tlsConfig.VerifyConnection = func(state utls.ConnectionState) error {
			return verify(tls.ConnectionState{ServerName: state.ServerName, PeerCertificates: state.PeerCertificates})
		}
	}
	var tlsConn *utls.UConn
	if config.upstream.mirrorHello {
		tlsConn = e.mirroredClient(ctx, conn, tlsConfig, protocols)
	}
	if tlsConn == nil {
		tlsConn = utls.UClient(conn, tlsConfig, helloID)
		err := tlsConn.BuildHandshakeState()
		if err != nil {
			return nil, nil, "", err
		}
		for _, extension := range tlsConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = protocols
				err = tlsConn.BuildHandshakeState()
				if err != nil {
					return nil, nil, "", err
				}
				break
			}
		}
	}
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
