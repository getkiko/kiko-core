package authority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCert(t *testing.T, commonName string, parent *testCert, mutate func(*x509.Certificate)) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(IntermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		template.MaxPathLen = 1
		template.NotAfter = now.Add(365 * 24 * time.Hour)
	} else {
		template.MaxPathLenZero = true
	}
	if mutate != nil {
		mutate(template)
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: cert, key: key}
}

func encodeChain(certs ...*testCert) []byte {
	var buffer bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.cert.Raw})
	}
	return buffer.Bytes()
}

func pkcs8(t *testing.T, cert *testCert) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(cert.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testFingerprint(cert *testCert) string {
	sum := sha256.Sum256(cert.cert.Raw)
	return hex.EncodeToString(sum[:])
}

type intermediateInput struct {
	chain       []byte
	key         []byte
	fingerprint string
	notAfter    time.Time
	now         time.Time
}

func TestLoadIntermediateValidation(t *testing.T) {
	root := newTestCert(t, "Root", nil, nil)
	good := newTestCert(t, "Intermediate", root, nil)
	valid := func() intermediateInput {
		return intermediateInput{encodeChain(good, root), pkcs8(t, good), testFingerprint(root), good.cert.NotAfter, time.Now()}
	}
	otherRoot := newTestCert(t, "Other Root", nil, nil)
	notCA := newTestCert(t, "Not CA", root, func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLenZero = false })
	noCertSign := newTestCert(t, "No CertSign", root, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature })
	pathLenOne := newTestCert(t, "Path Length 1", root, func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false })
	pathLenUnset := newTestCert(t, "Path Length Unset", root, func(c *x509.Certificate) { c.MaxPathLen = -1; c.MaxPathLenZero = false })
	notYetValid := newTestCert(t, "Future", root, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) })
	expired := newTestCert(t, "Expired", root, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-2 * time.Hour)
		c.NotAfter = time.Now().Add(-time.Hour).Truncate(time.Second)
	})
	foreign := newTestCert(t, "Foreign", otherRoot, nil)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(t, good)})
	ecDER, err := x509.MarshalECPrivateKey(good.key)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		name   string
		input  func() intermediateInput
		reason string
	}{
		{"good", valid, ""},
		{"empty chain", func() intermediateInput { i := valid(); i.chain = nil; return i }, "expected the intermediate"},
		{"intermediate only", func() intermediateInput { i := valid(); i.chain = encodeChain(good); return i }, "expected the intermediate"},
		{"private key block in chain", func() intermediateInput { i := valid(); i.chain = append(i.chain, keyPEM...); return i }, "unexpected PEM block"},
		{"not a CA", func() intermediateInput {
			return intermediateInput{encodeChain(notCA, root), pkcs8(t, notCA), testFingerprint(root), notCA.cert.NotAfter, time.Now()}
		}, "not a CA"},
		{"no certificate signing", func() intermediateInput {
			return intermediateInput{encodeChain(noCertSign, root), pkcs8(t, noCertSign), testFingerprint(root), noCertSign.cert.NotAfter, time.Now()}
		}, "certificate signing"},
		{"path length 1", func() intermediateInput {
			return intermediateInput{encodeChain(pathLenOne, root), pkcs8(t, pathLenOne), testFingerprint(root), pathLenOne.cert.NotAfter, time.Now()}
		}, "path length"},
		{"path length unset", func() intermediateInput {
			return intermediateInput{encodeChain(pathLenUnset, root), pkcs8(t, pathLenUnset), testFingerprint(root), pathLenUnset.cert.NotAfter, time.Now()}
		}, "path length"},
		{"last certificate not self-signed", func() intermediateInput {
			return intermediateInput{encodeChain(good, pathLenOne), pkcs8(t, good), testFingerprint(pathLenOne), good.cert.NotAfter, time.Now()}
		}, "self-signed"},
		{"chain to another root", func() intermediateInput {
			return intermediateInput{encodeChain(foreign, root), pkcs8(t, foreign), testFingerprint(root), foreign.cert.NotAfter, time.Now()}
		}, "verify"},
		{"root fingerprint mismatch", func() intermediateInput { i := valid(); i.fingerprint = testFingerprint(otherRoot); return i }, "fingerprint"},
		{"uppercase root fingerprint", func() intermediateInput { i := valid(); i.fingerprint = strings.ToUpper(i.fingerprint); return i }, "fingerprint"},
		{"expiry mismatch", func() intermediateInput { i := valid(); i.notAfter = i.notAfter.Add(time.Second); return i }, "expiry"},
		{"not yet valid", func() intermediateInput {
			return intermediateInput{encodeChain(notYetValid, root), pkcs8(t, notYetValid), testFingerprint(root), notYetValid.cert.NotAfter, time.Now()}
		}, "not valid now"},
		{"expired", func() intermediateInput {
			return intermediateInput{encodeChain(expired, root), pkcs8(t, expired), testFingerprint(root), expired.cert.NotAfter, time.Now()}
		}, "not valid now"},
		{"engine clock after expiry", func() intermediateInput { i := valid(); i.now = good.cert.NotAfter.Add(time.Second); return i }, "not valid now"},
		{"key mismatch", func() intermediateInput { i := valid(); i.key = pkcs8(t, root); return i }, "does not match"},
		{"key not PKCS#8", func() intermediateInput { i := valid(); i.key = ecDER; return i }, "PKCS#8"},
		{"key as PEM", func() intermediateInput { i := valid(); i.key = keyPEM; return i }, "PKCS#8"},
		{"empty key", func() intermediateInput { i := valid(); i.key = nil; return i }, "PKCS#8"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := testCase.input()
			a, err := LoadIntermediate(input.chain, input.key, input.fingerprint, input.notAfter, input.now)
			if testCase.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				if a.Fingerprint() != testFingerprint(good) || a.RootFingerprint() != testFingerprint(root) {
					t.Fatal("unexpected fingerprints")
				}
				if !a.NotAfter().Equal(good.cert.NotAfter) {
					t.Fatal("unexpected expiry")
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), testCase.reason) {
				t.Fatalf("error %q does not contain %q", err, testCase.reason)
			}
			if input.key != nil && bytes.Contains([]byte(err.Error()), input.key) {
				t.Fatal("error contains key bytes")
			}
		})
	}
}

func TestIntermediateLeafChain(t *testing.T) {
	root := newTestCert(t, "Root", nil, func(c *x509.Certificate) { c.MaxPathLen = 2 })
	middle := newTestCert(t, "Middle", root, func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false })
	intermediate := newTestCert(t, "Intermediate", middle, nil)
	a, err := LoadIntermediate(encodeChain(intermediate, middle, root), pkcs8(t, intermediate), testFingerprint(root), intermediate.cert.NotAfter, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The root stays out of the served chain.
	if len(cert.Certificate) != 3 || !bytes.Equal(cert.Certificate[1], intermediate.cert.Raw) || !bytes.Equal(cert.Certificate[2], middle.cert.Raw) {
		t.Fatalf("served chain length = %d", len(cert.Certificate))
	}
	if !cert.Leaf.NotAfter.After(time.Now()) || cert.Leaf.NotAfter.After(intermediate.cert.NotAfter) {
		t.Fatal("leaf outlives the intermediate")
	}
	verifyToRoot(t, cert.Certificate, root.cert, "example.com")
	if a.RootFingerprint() != testFingerprint(root) {
		t.Fatal("unexpected root fingerprint")
	}
}

func verifyToRoot(t *testing.T, chain [][]byte, root *x509.Certificate, name string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parsed)
	}
	leaf, err := x509.ParseCertificate(chain[0])
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
		t.Fatal(err)
	}
}

func TestIssueIntermediate(t *testing.T) {
	rootPEM, rootKeyPEM, err := Generate("Kiko Test Root", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, keyPKCS8, err := IssueIntermediate(rootPEM, rootKeyPEM, "Kiko Test Intermediate", IntermediateValidity)
	if err != nil {
		t.Fatal(err)
	}
	rootBlock, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root.Raw)
	interBlock, _ := pem.Decode(chainPEM)
	intermediate, err := x509.ParseCertificate(interBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	a, err := LoadIntermediate(chainPEM, keyPKCS8, hex.EncodeToString(sum[:]), intermediate.NotAfter, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := a.Leaf("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("served chain length = %d", len(cert.Certificate))
	}
	verifyToRoot(t, cert.Certificate, root, "example.com")
}

func TestFileRootFingerprint(t *testing.T) {
	a := mustGenerate(t, time.Hour)
	if a.RootFingerprint() != a.Fingerprint() {
		t.Fatal("a single root reports its own fingerprint")
	}
}
