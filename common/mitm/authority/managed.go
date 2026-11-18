package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// IntermediateValidity is the validity of an intermediate CA issued by IssueIntermediate.
const IntermediateValidity = 30 * 24 * time.Hour

// LoadIntermediate loads a pushed intermediate CA. chainPEM holds the intermediate first,
// then its issuers up to and including the self-signed root; keyPKCS8 is the PKCS#8 DER
// key of the intermediate. The intermediate must be a CA with certificate signing usage
// and path length 0, valid at now, verify to the root, and expire at notAfter (seconds);
// the root must match rootFingerprint. Leaves carry the chain without the root, which
// clients already trust. Errors never include key bytes.
func LoadIntermediate(chainPEM []byte, keyPKCS8 []byte, rootFingerprint string, notAfter time.Time, now time.Time) (*Authority, error) {
	var chain []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, E.New("intermediate chain: unexpected PEM block ", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, E.Cause(err, "intermediate chain: parse certificate")
		}
		chain = append(chain, cert)
	}
	if len(chain) < 2 {
		return nil, E.New("intermediate chain: expected the intermediate and its root")
	}
	intermediate, root := chain[0], chain[len(chain)-1]
	if !intermediate.BasicConstraintsValid || !intermediate.IsCA {
		return nil, E.New("intermediate chain: intermediate is not a CA")
	}
	if intermediate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, E.New("intermediate chain: intermediate lacks the certificate signing key usage")
	}
	if intermediate.MaxPathLen != 0 || !intermediate.MaxPathLenZero {
		return nil, E.New("intermediate chain: intermediate path length must be 0")
	}
	if !root.BasicConstraintsValid || !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, E.New("intermediate chain: last certificate is not a self-signed CA")
	}
	if fingerprint(root) != rootFingerprint {
		return nil, E.New("intermediate chain: root fingerprint mismatch")
	}
	if intermediate.NotAfter.Unix() != notAfter.Unix() {
		return nil, E.New("intermediate chain: expiry mismatch")
	}
	if now.Before(intermediate.NotBefore) || !now.Before(intermediate.NotAfter) {
		return nil, E.New("intermediate chain: intermediate is not valid now")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	issuers := x509.NewCertPool()
	for _, cert := range chain[1 : len(chain)-1] {
		issuers.AddCert(cert)
	}
	_, err := intermediate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: issuers,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, E.Cause(err, "intermediate chain: verify")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		// The parser error carries no key bytes, but stays out of the message regardless.
		return nil, E.New("intermediate key: invalid PKCS#8 private key")
	}
	key, isSigner := parsed.(crypto.Signer)
	if !isSigner {
		return nil, E.New("intermediate key: unsupported key type")
	}
	publicKey, isEqualer := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !isEqualer || !publicKey.Equal(intermediate.PublicKey) {
		return nil, E.New("intermediate key: private key does not match the intermediate")
	}
	served := make([][]byte, 0, len(chain)-1)
	for _, cert := range chain[:len(chain)-1] {
		served = append(served, cert.Raw)
	}
	return newAuthority(chain, served, key)
}

// IssueIntermediate signs an ECDSA P-256 intermediate CA (path length 0) with a root loaded
// from PEM, for tests and standalone use. It returns the chain (intermediate, root) as PEM
// and the intermediate key as PKCS#8 DER.
func IssueIntermediate(rootCertPEM, rootKeyPEM []byte, commonName string, validity time.Duration) (chainPEM []byte, keyPKCS8 []byte, err error) {
	root, err := Load(rootCertPEM, rootKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, E.Cause(err, "generate key")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(validity).Truncate(time.Second)
	if notAfter.After(root.NotAfter()) {
		notAfter = root.NotAfter()
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{commonName}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root.Certificate(), key.Public(), root.caKey)
	if err != nil {
		return nil, nil, E.Cause(err, "create certificate")
	}
	keyPKCS8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, E.Cause(err, "marshal key")
	}
	chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, cert := range root.chainDER {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})...)
	}
	return chainPEM, keyPKCS8, nil
}
