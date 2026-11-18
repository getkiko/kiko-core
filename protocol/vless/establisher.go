package vless

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newServerEstablisher(outboundDialer N.Dialer, server M.Socksaddr, transport adapter.V2RayClientTransport, tlsConfig tls.Config) dialer.ConnectionEstablisher {
	if transport != nil {
		return dialer.EstablishFunc(transport.DialContext)
	}
	if tlsConfig != nil {
		tlsDialer := tls.NewDialer(outboundDialer, tlsConfig)
		return dialer.EstablishFunc(func(ctx context.Context) (net.Conn, error) {
			return tlsDialer.DialTLSContext(ctx, server)
		})
	}
	return dialer.NewDialEstablisher(outboundDialer, N.NetworkTCP, server)
}
