//go:build !with_utls

package mitm

import (
	"crypto/tls"
	"net"
)

func negotiatedProtocol(conn net.Conn) string {
	return conn.(*tls.Conn).ConnectionState().NegotiatedProtocol
}
