package h2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testHost = "example.test"

var (
	certOnce sync.Once
	testCert tls.Certificate
)

func selfSigned(t testing.TB) tls.Certificate {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: testHost},
			DNSNames:     []string{testHost, "localhost"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		testCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return testCert
}

// origin is a TLS HTTP/2 test origin.
type origin struct {
	srv   *httptest.Server
	conns atomic.Int32
}

type connKey struct{}

func newOrigin(t testing.TB, h http.Handler) *origin {
	o := &origin{}
	o.srv = httptest.NewUnstartedServer(h)
	o.srv.EnableHTTP2 = true
	o.srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		o.conns.Add(1)
		return context.WithValue(ctx, connKey{}, c)
	}
	o.srv.StartTLS()
	t.Cleanup(func() {
		// Close blocks on open connections; drop them first.
		o.srv.CloseClientConnections()
		o.srv.Close()
	})
	return o
}

// killConn closes the connection the request arrived on.
func killConn(r *http.Request) {
	r.Context().Value(connKey{}).(net.Conn).Close()
}

func (o *origin) dial(ctx context.Context) (net.Conn, error) {
	return dialTLS(ctx, o.srv.Listener.Addr().String())
}

func dialTLS(ctx context.Context, addr string) (net.Conn, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}}
	return d.DialContext(ctx, "tcp", addr)
}

// proxyEnv runs Serve for every connection accepted on a TLS listener.
type proxyEnv struct {
	t        testing.TB
	addr     string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	sessions atomic.Int32
	done     chan error
	forward  atomic.Int32
	dials    atomic.Int32
}

type proxyConfig struct {
	dial     func(ctx context.Context) (net.Conn, error)
	noRedial bool
	// redial overrides the dial used for Redial.
	redial func(ctx context.Context) (net.Conn, error)
	mod    func(*Options)
}

func startProxy(t testing.TB, cfg proxyConfig) *proxyEnv {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &proxyEnv{t: t, addr: ln.Addr().String(), done: make(chan error, 256)}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	counted := func(f func(ctx context.Context) (net.Conn, error)) func(ctx context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) {
			e.dials.Add(1)
			return f(ctx)
		}
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				tc := c.(*tls.Conn)
				if err := tc.HandshakeContext(e.ctx); err != nil {
					c.Close()
					return
				}
				up, err := counted(cfg.dial)(e.ctx)
				if err != nil {
					c.Close()
					return
				}
				opts := Options{ServerName: testHost, OnRequest: func() { e.forward.Add(1) }}
				if !cfg.noRedial {
					opts.Redial = counted(cfg.dial)
					if cfg.redial != nil {
						opts.Redial = counted(cfg.redial)
					}
				}
				if cfg.mod != nil {
					cfg.mod(&opts)
				}
				e.sessions.Add(1)
				err = Serve(e.ctx, c, up, opts)
				select {
				case e.done <- err:
				default:
				}
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		e.cancel()
		e.wg.Wait()
	})
	return e
}

// client returns an HTTP client whose connections go to the proxy.
func (e *proxyEnv) client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, e.addr)
		},
	}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func (e *proxyEnv) url(path string) string { return "https://" + testHost + path }

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settleGoroutines waits until the goroutine count is back to base (plus a
// small allowance) and fails with a dump otherwise.
func settleGoroutines(t testing.TB, base int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > base+1 {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines leaked: %d > %d\n%s", runtime.NumGoroutine(), base, buf)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
