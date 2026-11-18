//go:build go1.26

package h2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

// clientConn opens one HTTP/2 client connection to the proxy with the given
// per-stream receive window.
func (e *proxyEnv) clientConn(window int) *http.ClientConn {
	e.t.Helper()
	nc, err := net.Dial("tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	tc := tls.Client(nc, &tls.Config{InsecureSkipVerify: true, ServerName: testHost, NextProtos: []string{"h2"}})
	if err := tc.Handshake(); err != nil {
		e.t.Fatal(err)
	}
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	t1 := &http.Transport{
		Protocols:   &protocols,
		DialContext: func(context.Context, string, string) (net.Conn, error) { return tc, nil },
		HTTP2:       &http.HTTP2Config{},
	}
	if window > 0 {
		t1.HTTP2.MaxReceiveBufferPerStream = window
	}
	cc, err := t1.NewClientConn(context.Background(), "http", "proxy.invalid:80")
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { cc.Close(); tc.Close() })
	return cc
}
