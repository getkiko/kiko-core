package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustGenerate(t testing.TB, validity time.Duration) *Authority {
	t.Helper()
	certPEM, keyPEM, err := Generate("Kiko Test CA", validity)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Load(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func verify(t *testing.T, a *Authority, cert *tls.Certificate, name string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(a.chain[len(a.chain)-1])
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parsed)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       name,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("verify %s: %v", name, err)
	}
}

func TestLeafDNSName(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	cert, err := a.Leaf("Example.COM.", nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("Leaf field not set")
	}
	if leaf.Subject.CommonName != "Example.COM" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" || len(leaf.IPAddresses) != 0 {
		t.Fatalf("SANs = %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.KeyUsage != x509.KeyUsageDigitalSignature || leaf.IsCA {
		t.Fatal("unexpected key usage")
	}
	if _, isECDSA := leaf.PublicKey.(*ecdsa.PublicKey); !isECDSA {
		t.Fatal("leaf key is not ECDSA")
	}
	now := time.Now()
	if d := now.Add(-LeafBackdate).Sub(leaf.NotBefore); d < -time.Minute || d > time.Minute {
		t.Fatalf("NotBefore = %v", leaf.NotBefore)
	}
	if d := now.Add(LeafValidity).Sub(leaf.NotAfter); d < -time.Minute || d > time.Minute {
		t.Fatalf("NotAfter = %v", leaf.NotAfter)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d", len(cert.Certificate))
	}
	verify(t, a, cert, "example.com")
}

func TestLeafIP(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	for _, name := range []string{"192.0.2.7", "2001:db8::1", "[2001:db8::2]"} {
		cert, err := a.Leaf(name, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.Leaf.DNSNames) != 0 || len(cert.Leaf.IPAddresses) != 1 {
			t.Fatalf("%s: SANs = %v %v", name, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		verify(t, a, cert, cert.Leaf.IPAddresses[0].String())
	}
}

func TestLeafUpstreamSANs(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	upstream := &x509.Certificate{
		DNSNames:    []string{"*.example.com", "example.com", "EXAMPLE.net"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1")},
	}
	cert, err := a.Leaf("api.example.org", upstream)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.example.com", "api.example.org", "example.com", "example.net"}
	if fmt.Sprint(cert.Leaf.DNSNames) != fmt.Sprint(want) {
		t.Fatalf("DNSNames = %v", cert.Leaf.DNSNames)
	}
	if len(cert.Leaf.IPAddresses) != 1 {
		t.Fatalf("IPAddresses = %v", cert.Leaf.IPAddresses)
	}
	verify(t, a, cert, "www.example.com")
	verify(t, a, cert, "api.example.org")
	verify(t, a, cert, "192.0.2.1")

	// Same SAN set, different order and server name already present: same cache entry.
	upstream2 := &x509.Certificate{DNSNames: []string{"example.net", "api.example.org", "example.com", "*.example.com"}, IPAddresses: upstream.IPAddresses}
	cert2, err := a.Leaf("example.com", upstream2)
	if err != nil {
		t.Fatal(err)
	}
	if cert2 != cert {
		t.Fatal("equal SAN sets should share a cache entry")
	}
}

func TestLeafClampedToCAExpiry(t *testing.T) {
	a := mustGenerate(t, 48*time.Hour)
	cert, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Leaf.NotAfter.Equal(a.NotAfter()) {
		t.Fatalf("leaf NotAfter %v, CA NotAfter %v", cert.Leaf.NotAfter, a.NotAfter())
	}
	verify(t, a, cert, "example.com")
}

func TestLeafExpiredCA(t *testing.T) {
	a := mustGenerate(t, time.Hour)
	a.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := a.Leaf("example.com", nil); err == nil {
		t.Fatal("expected error for expired CA")
	}
}

func TestLeafCacheHit(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	first, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Leaf("EXAMPLE.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("cache miss on second call")
	}
	if a.CacheLen() != 1 {
		t.Fatalf("CacheLen = %d", a.CacheLen())
	}
}

func TestLeafCacheEviction(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	for i := 0; i < CacheCapacity+10; i++ {
		if _, err := a.Leaf(fmt.Sprintf("h%d.example.com", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	if a.CacheLen() != CacheCapacity {
		t.Fatalf("CacheLen = %d", a.CacheLen())
	}
}

type countingSigner struct {
	*ecdsa.PrivateKey
	count atomic.Int32
}

func (s *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.count.Add(1)
	time.Sleep(20 * time.Millisecond)
	return s.PrivateKey.Sign(r, digest, opts)
}

func TestLeafConcurrentMissesCollapse(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	signer := &countingSigner{PrivateKey: a.caKey.(*ecdsa.PrivateKey)}
	a.caKey = signer
	var wg sync.WaitGroup
	results := make([]*tls.Certificate, 64)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cert, err := a.Leaf("example.com", nil)
			if err != nil {
				t.Error(err)
			}
			results[i] = cert
		}(i)
	}
	wg.Wait()
	if n := signer.count.Load(); n != 1 {
		t.Fatalf("signings = %d, want 1", n)
	}
	for _, cert := range results {
		if cert != results[0] {
			t.Fatal("concurrent callers got different certificates")
		}
	}
}

func TestLeafNearExpiryRegenerated(t *testing.T) {
	a := mustGenerate(t, 365*24*time.Hour)
	base := time.Now()
	a.now = func() time.Time { return base }
	first, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return base.Add(LeafValidity - 2*time.Hour) }
	if second, _ := a.Leaf("example.com", nil); second != first {
		t.Fatal("leaf with 2h left should be reused")
	}
	a.now = func() time.Time { return base.Add(LeafValidity - 30*time.Minute) }
	third, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("leaf within 1h of expiry should be reissued")
	}
	if !third.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatal("reissued leaf should expire later")
	}
	if a.CacheLen() != 1 {
		t.Fatalf("CacheLen = %d", a.CacheLen())
	}
}

func TestLoadRejectsMismatchedKey(t *testing.T) {
	certPEM, _, err := Generate("A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := Generate("B", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certPEM, otherKey); err == nil {
		t.Fatal("expected key mismatch error")
	}
}

func TestLoadRejectsNonCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if _, err := Load(certPEM, keyPEM); err == nil {
		t.Fatal("expected non-CA error")
	}
	// CA without the certificate signing key usage.
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageDigitalSignature
	der, _ = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, err := Load(certPEM, keyPEM); err == nil {
		t.Fatal("expected missing CertSign error")
	}
	if _, err := Load(nil, keyPEM); err == nil {
		t.Fatal("expected no certificate error")
	}
}

func TestRSAIntermediateCA(t *testing.T) {
	// RSA root, RSA intermediate (PKCS#1 key); the intermediate signs leaves and the root is sent after it.
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RSA Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "RSA Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, root, interKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(interKey)})
	a, err := Load(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if a.Certificate().Subject.CommonName != "RSA Intermediate" {
		t.Fatal("signing CA should be the first certificate")
	}
	if len(a.Fingerprint()) != 64 {
		t.Fatalf("fingerprint = %q", a.Fingerprint())
	}
	cert, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 3 {
		t.Fatalf("chain length = %d", len(cert.Certificate))
	}
	if cert.Leaf.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("signature algorithm = %v", cert.Leaf.SignatureAlgorithm)
	}
	verify(t, a, cert, "example.com")
}

func TestLoadFile(t *testing.T) {
	if _, err := LoadFile(t.TempDir()+"/missing.pem", t.TempDir()+"/missing.key"); err == nil {
		t.Fatal("expected error")
	}
}

func BenchmarkLeafHit(b *testing.B) {
	a := mustGenerate(b, 365*24*time.Hour)
	if _, err := a.Leaf("example.com", nil); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Leaf("example.com", nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeafMiss(b *testing.B) {
	a := mustGenerate(b, 365*24*time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Leaf(fmt.Sprintf("h%d.example.com", i), nil); err != nil {
			b.Fatal(err)
		}
	}
}
