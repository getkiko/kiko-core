//go:build with_utls

package mitm

import (
	"net"

	utls "github.com/metacubex/utls"
)

func negotiatedProtocol(conn net.Conn) string {
	return conn.(*utls.UConn).ConnectionState().NegotiatedProtocol
}
