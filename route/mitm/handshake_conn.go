package mitm

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
)

// handshakeConn is the client connection under the TLS server. While the server waits for the
// upstream handshake it does not read the client, so watch reads ahead to notice a close; the
// bytes read meanwhile (a TLS 1.3 client may already send ChangeCipherSpec) are handed to the
// server afterwards.
type handshakeConn struct {
	net.Conn
	pending []byte
}

func (c *handshakeConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		if len(c.pending) == 0 {
			c.pending = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

var aLongTimeAgo = time.Unix(1, 0)

// watch reads the client until the returned stop is called and calls cancel when the client
// fails or closes. stop returns that failure; the connection must not be read until then.
func (c *handshakeConn) watch(cancel context.CancelFunc) (stop func() error) {
	var (
		stopping atomic.Bool
		readErr  error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 512)
		for {
			n, err := c.Conn.Read(buffer)
			c.pending = append(c.pending, buffer[:n]...)
			if err != nil {
				if !stopping.Load() || !E.IsTimeout(err) {
					readErr = err
					cancel()
				}
				return
			}
		}
	}()
	return func() error {
		stopping.Store(true)
		if err := c.Conn.SetReadDeadline(aLongTimeAgo); err != nil {
			// The read cannot be interrupted: fail the handshake rather than wait for the client.
			c.Conn.Close()
			<-done
			return E.Cause(err, "interrupt client read")
		}
		<-done
		_ = c.Conn.SetReadDeadline(time.Time{})
		return readErr
	}
}

// withDeadlineReader puts conn behind a reader that reads ahead on its own goroutine unless it
// already is, so that interrupting a read never cuts into the protocol reader below (a stream
// cipher frame, an outbound transport without read deadlines).
func withDeadlineReader(conn net.Conn) net.Conn {
	if _, isReadAhead := conn.(*readAheadConn); isReadAhead {
		return conn
	}
	for current := any(conn); current != nil; {
		if _, isDeadline := current.(*deadline.Conn); isDeadline {
			return conn
		}
		upstream, hasUpstream := current.(common.WithUpstream)
		if !hasUpstream {
			break
		}
		current = upstream.Upstream()
	}
	return newReadAheadConn(conn)
}
