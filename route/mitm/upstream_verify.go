package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// verifyConnection returns the certificate check for a handshake that has
// InsecureSkipVerify set because upstream.custom_roots is configured, or nil
// when the standard verification applies.
//
// On macOS the system verifier leaks native memory every time it rejects a
// chain, and a chain that is trusted only through a custom root is rejected
// by the system before the appended root is tried. The chain is therefore
// checked against the custom roots alone first, in pure Go; only when that
// fails does the full pool (core or system roots plus the custom roots) decide.
func (e *Engine) verifyConnection(config *compiledConfig) func(tls.ConnectionState) error {
	appended := config.upstream.appended
	if appended == nil {
		return nil
	}
	full := e.upstreamRoots(config)
	return func(state tls.ConnectionState) error {
		return verifyUpstream(state.PeerCertificates, state.ServerName, e.now(), appended, full)
	}
}

// verifyUpstream verifies the chain for the server name (host name, validity
// period and server-auth extended key usage) against first, then against
// fallback.
func verifyUpstream(certs []*x509.Certificate, serverName string, now time.Time, first, fallback *x509.CertPool) error {
	if len(certs) == 0 {
		return E.New("missing peer certificate")
	}
	if serverName == "" {
		return E.New("missing server name")
	}
	options := x509.VerifyOptions{
		DNSName:       serverName,
		CurrentTime:   now,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, cert := range certs[1:] {
		options.Intermediates.AddCert(cert)
	}
	options.Roots = first
	_, err := certs[0].Verify(options)
	if err == nil {
		return nil
	}
	options.Roots = fallback
	_, err = certs[0].Verify(options)
	return err
}
