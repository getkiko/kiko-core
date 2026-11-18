// Package authority holds the certificate authority used for HTTPS decryption
// and issues short-lived leaf certificates for intercepted server names.
package authority

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sync/singleflight"
)

const (
	// CacheCapacity is the number of leaf certificates kept in memory.
	CacheCapacity = 1024
	// LeafValidity is the longest validity of an issued leaf.
	LeafValidity = 30 * 24 * time.Hour
	// LeafBackdate is how far before issuance a leaf becomes valid, to tolerate client clock skew.
	LeafBackdate = 24 * time.Hour
	// RenewBefore is the remaining validity below which a cached leaf is reissued.
	RenewBefore = time.Hour
)

// Authority signs leaf certificates with a loaded CA. It is safe for concurrent use.
type Authority struct {
	chain       []*x509.Certificate
	chainDER    [][]byte // sent after each leaf
	caKey       crypto.Signer
	leafKey     *ecdsa.PrivateKey
	fingerprint string
	rootPrint   string

	now   func() time.Time
	group singleflight.Group

	access  sync.Mutex
	entries map[string]*list.Element
	lru     list.List // front = most recently used; values are *cacheEntry
}

type cacheEntry struct {
	key  string
	cert *tls.Certificate
}

// LoadFile reads a PEM certificate chain and a PEM private key from disk. See Load.
func LoadFile(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, E.Cause(err, "read certificate authority")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, E.Cause(err, "read certificate authority key")
	}
	return Load(certPEM, keyPEM)
}

// Load parses a PEM certificate chain (first certificate = the signing CA, which must have
// IsCA and KeyUsageCertSign; following certificates are its issuers, sent after the leaf)
// and a PEM private key (PKCS#8, EC or PKCS#1), and checks the key matches the first certificate.
func Load(certPEM, keyPEM []byte) (*Authority, error) {
	var chain []*x509.Certificate
	var chainDER [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, E.Cause(err, "parse certificate authority")
		}
		chain = append(chain, cert)
		chainDER = append(chainDER, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, E.New("certificate authority: no certificate found")
	}
	ca := chain[0]
	if !ca.BasicConstraintsValid || !ca.IsCA {
		return nil, E.New("certificate authority: certificate is not a CA")
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, E.New("certificate authority: certificate lacks the certificate signing key usage")
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	publicKey, isEqualer := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !isEqualer || !publicKey.Equal(ca.PublicKey) {
		return nil, E.New("certificate authority: private key does not match the certificate")
	}
	return newAuthority(chain, chainDER, key)
}

func newAuthority(chain []*x509.Certificate, chainDER [][]byte, key crypto.Signer) (*Authority, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, E.Cause(err, "generate leaf key")
	}
	return &Authority{
		chain:       chain,
		chainDER:    chainDER,
		caKey:       key,
		leafKey:     leafKey,
		fingerprint: fingerprint(chain[0]),
		rootPrint:   fingerprint(chain[len(chain)-1]),
		now:         time.Now,
		entries:     make(map[string]*list.Element),
	}, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	rest := keyPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, E.New("certificate authority key: no private key found")
		}
		var (
			key any
			err error
		)
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "parse certificate authority key")
		}
		signer, isSigner := key.(crypto.Signer)
		if !isSigner {
			return nil, E.New("certificate authority key: unsupported key type")
		}
		return signer, nil
	}
}

// Generate creates a self-signed ECDSA P-256 root CA (path length 1) for tests and standalone use.
func Generate(commonName string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, E.Cause(err, "generate key")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{commonName}},
		NotBefore:             now.Add(-LeafBackdate),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, E.Cause(err, "create certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, E.Cause(err, "marshal key")
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, E.Cause(err, "generate serial number")
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

// Fingerprint returns the lowercase hex SHA-256 of the signing CA certificate DER.
func (a *Authority) Fingerprint() string {
	return a.fingerprint
}

// RootFingerprint returns the lowercase hex SHA-256 of the last certificate of the
// loaded chain; for a chain of one root it equals Fingerprint.
func (a *Authority) RootFingerprint() string {
	return a.rootPrint
}

// NotAfter returns the expiry of the signing CA.
func (a *Authority) NotAfter() time.Time {
	return a.chain[0].NotAfter
}

// Certificate returns the signing CA.
func (a *Authority) Certificate() *x509.Certificate {
	return a.chain[0]
}

// CacheLen returns the number of cached leaf certificates.
func (a *Authority) CacheLen() int {
	a.access.Lock()
	defer a.access.Unlock()
	return a.lru.Len()
}

// Leaf returns a leaf certificate for serverName. When upstream is not nil its DNS names and
// IP addresses are copied; serverName itself (an IP literal goes to the IP SANs) is always
// included. The common name is serverName. Validity runs from now-24h to min(now+30d, CA expiry).
// Leaves are cached by their SAN set; concurrent misses for the same set are collapsed, and an
// entry within one hour of expiry is reissued.
func (a *Authority) Leaf(serverName string, upstream *x509.Certificate) (*tls.Certificate, error) {
	serverName = strings.TrimSuffix(serverName, ".")
	if serverName == "" {
		return nil, E.New("issue leaf: empty server name")
	}
	dnsNames, ipAddresses := sanSet(serverName, upstream)
	key := cacheKey(dnsNames, ipAddresses)
	now := a.now()
	if cert := a.load(key, now); cert != nil {
		return cert, nil
	}
	value, err, _ := a.group.Do(key, func() (any, error) {
		now := a.now()
		if cert := a.load(key, now); cert != nil {
			return cert, nil
		}
		cert, err := a.issue(serverName, dnsNames, ipAddresses, now)
		if err != nil {
			return nil, err
		}
		a.store(key, cert)
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*tls.Certificate), nil
}

func sanSet(serverName string, upstream *x509.Certificate) ([]string, []net.IP) {
	var dnsNames []string
	var ipAddresses []net.IP
	if upstream != nil {
		for _, name := range upstream.DNSNames {
			dnsNames = append(dnsNames, strings.ToLower(name))
		}
		for _, ip := range upstream.IPAddresses {
			ipAddresses = append(ipAddresses, normalizeIP(ip))
		}
	}
	if addr, err := netip.ParseAddr(strings.Trim(serverName, "[]")); err == nil {
		ipAddresses = append(ipAddresses, normalizeIP(net.IP(addr.Unmap().AsSlice())))
	} else {
		dnsNames = append(dnsNames, strings.ToLower(serverName))
	}
	slices.Sort(dnsNames)
	dnsNames = slices.Compact(dnsNames)
	slices.SortFunc(ipAddresses, func(x, y net.IP) int { return bytes.Compare(x, y) })
	ipAddresses = slices.CompactFunc(ipAddresses, func(x, y net.IP) bool { return x.Equal(y) })
	return dnsNames, ipAddresses
}

func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func cacheKey(dnsNames []string, ipAddresses []net.IP) string {
	var builder strings.Builder
	for _, name := range dnsNames {
		builder.WriteString(name)
		builder.WriteByte(',')
	}
	builder.WriteByte('|')
	for _, ip := range ipAddresses {
		builder.WriteString(ip.String())
		builder.WriteByte(',')
	}
	return builder.String()
}

func (a *Authority) load(key string, now time.Time) *tls.Certificate {
	a.access.Lock()
	defer a.access.Unlock()
	element, loaded := a.entries[key]
	if !loaded {
		return nil
	}
	cert := element.Value.(*cacheEntry).cert
	notAfter := cert.Leaf.NotAfter
	// A leaf already clamped to the CA expiry cannot be improved by reissuing.
	if notAfter.Sub(now) < RenewBefore && notAfter.Before(a.chain[0].NotAfter) {
		a.lru.Remove(element)
		delete(a.entries, key)
		return nil
	}
	a.lru.MoveToFront(element)
	return cert
}

func (a *Authority) store(key string, cert *tls.Certificate) {
	a.access.Lock()
	defer a.access.Unlock()
	if element, loaded := a.entries[key]; loaded {
		element.Value.(*cacheEntry).cert = cert
		a.lru.MoveToFront(element)
		return
	}
	a.entries[key] = a.lru.PushFront(&cacheEntry{key: key, cert: cert})
	for a.lru.Len() > CacheCapacity {
		oldest := a.lru.Back()
		a.lru.Remove(oldest)
		delete(a.entries, oldest.Value.(*cacheEntry).key)
	}
}

func (a *Authority) issue(serverName string, dnsNames []string, ipAddresses []net.IP, now time.Time) (*tls.Certificate, error) {
	ca := a.chain[0]
	if !now.Before(ca.NotAfter) {
		return nil, E.New("issue leaf: certificate authority expired at ", ca.NotAfter.Format(time.RFC3339))
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore := now.Add(-LeafBackdate)
	if notBefore.Before(ca.NotBefore) {
		notBefore = ca.NotBefore
	}
	notAfter := now.Add(LeafValidity)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, a.leafKey.Public(), a.caKey)
	if err != nil {
		return nil, E.Cause(err, "issue leaf")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, E.Cause(err, "parse issued leaf")
	}
	certificate := make([][]byte, 0, 1+len(a.chainDER))
	certificate = append(certificate, der)
	certificate = append(certificate, a.chainDER...)
	return &tls.Certificate{
		Certificate: certificate,
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}, nil
}
