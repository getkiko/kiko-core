package shadowtls

import (
	"context"
	"net"

	boxdialer "github.com/sagernet/sing-box/common/dialer"
	shadowtls "github.com/sagernet/sing-shadowtls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type connectionEstablisher struct {
	client *shadowtls.Client
	dialer N.Dialer
	server M.Socksaddr
}

func newConnectionEstablisher(client *shadowtls.Client, dialer N.Dialer, server M.Socksaddr) boxdialer.ConnectionEstablisher {
	return &connectionEstablisher{client: client, dialer: dialer, server: server}
}

func (e *connectionEstablisher) Establish(ctx context.Context) (net.Conn, error) {
	conn, err := e.dialer.DialContext(ctx, N.NetworkTCP, e.server)
	if err != nil {
		return nil, err
	}
	stlsConn, err := e.client.DialContextConn(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stlsConn, nil
}
