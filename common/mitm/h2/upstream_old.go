//go:build !go1.26

package h2

import (
	"context"
	"errors"
	"net"
)

// Supported reports whether this build can relay HTTP/2 (Go 1.26 or later).
const Supported = false

func newClientConn(context.Context, net.Conn) (clientConn, error) {
	return nil, errors.New("h2: requires Go 1.26 or later")
}
