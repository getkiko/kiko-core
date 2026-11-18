//go:build go1.26

package h2

import (
	"context"
	"net"
	"net/http"
)

// Supported reports whether this build can relay HTTP/2 (Go 1.26 or later).
const Supported = true

// newClientConn starts an HTTP/2 client connection on nc, which is already
// TLS-handshaken with ALPN h2. net/http cannot take a foreign TLS conn, but it
// speaks prior-knowledge HTTP/2 on a plain one; the :scheme still comes from
// the request URL. x/net/http2.ClientConn is not used: its RoundTrip holds a
// mutex that its own state hook takes (a deadlock under load in x/net v0.57.0
// on Go 1.27).
func newClientConn(ctx context.Context, nc net.Conn) (clientConn, error) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	t1 := &http.Transport{
		Protocols:              &protocols,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nc, nil
		},
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     streamWindow,
			MaxReceiveBufferPerConnection: connWindow,
			SendPingTimeout:               upstreamPingAfter,
			PingTimeout:                   upstreamPingTimeout,
		},
	}
	return t1.NewClientConn(ctx, "http", "upstream.invalid:80")
}
