package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func verifyTestCert(t *testing.T, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           usages,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, pool
}

func TestVerifyUpstream(t *testing.T) {
	now := time.Now()
	server := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cert, appended := verifyTestCert(t, server, now.Add(-time.Hour), now.Add(time.Hour))
	chain := []*x509.Certificate{cert}
	empty := x509.NewCertPool()

	// Trusted through the appended root alone.
	require.NoError(t, verifyUpstream(chain, "example.com", now, appended, empty))
	// Name, validity period and usage are still enforced.
	require.Error(t, verifyUpstream(chain, "other.test", now, appended, empty))
	require.Error(t, verifyUpstream(chain, "", now, appended, empty))
	require.Error(t, verifyUpstream(chain, "example.com", now.Add(2*time.Hour), appended, empty))
	require.Error(t, verifyUpstream(chain, "example.com", now.Add(-2*time.Hour), appended, empty))
	require.Error(t, verifyUpstream(nil, "example.com", now, appended, empty))
	client, clientPool := verifyTestCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	require.Error(t, verifyUpstream([]*x509.Certificate{client}, "example.com", now, clientPool, empty))
	// A chain the appended roots do not cover falls back to the full pool.
	require.NoError(t, verifyUpstream(chain, "example.com", now, empty, appended))
	require.Error(t, verifyUpstream(chain, "example.com", now, empty, empty))
}
