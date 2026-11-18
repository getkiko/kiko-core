package mitm

import (
	"context"
	"net"
	"sync"
)

type clientHelloKey struct{}

// clientHelloContext carries the client's ClientHello record (nil: none) to
// the upstream handshake.
func clientHelloContext(ctx context.Context, record []byte) context.Context {
	if record == nil {
		return ctx
	}
	return context.WithValue(ctx, clientHelloKey{}, record)
}

func clientHelloFrom(ctx context.Context) []byte {
	record, _ := ctx.Value(clientHelloKey{}).([]byte)
	return record
}

const (
	tlsRecordHeader    = 5
	tlsRecordHandshake = 0x16
)

// helloCapture is the client connection under the TLS server; it copies the
// first TLS record the client sends, the ClientHello when it fits one record.
type helloCapture struct {
	net.Conn

	mu     sync.Mutex
	buf    []byte
	done   bool
	usable bool
}

func (c *helloCapture) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.record(p[:n])
	}
	return n, err
}

func (c *helloCapture) record(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.buf = append(c.buf, p...)
	if c.buf[0] != tlsRecordHandshake {
		c.done = true
		c.buf = nil
		return
	}
	if len(c.buf) < tlsRecordHeader {
		return
	}
	total := tlsRecordHeader + (int(c.buf[3])<<8 | int(c.buf[4]))
	if len(c.buf) >= total {
		c.buf = c.buf[:total]
		c.done, c.usable = true, true
	}
}

// snapshot returns the captured record, nil when it is incomplete or absent. A
// nil receiver captures nothing.
func (c *helloCapture) snapshot() []byte {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.usable {
		return nil
	}
	return append([]byte(nil), c.buf...)
}

// helloExtensionIDs lists the extension types of a ClientHello record in
// order; ok is false for anything but a well-formed ClientHello.
func helloExtensionIDs(record []byte) (ids []uint16, ok bool) {
	// record header (5), handshake header (4), version (2), random (32)
	pos := tlsRecordHeader + 4 + 2 + 32
	skip := func(lengthBytes int) bool {
		if pos+lengthBytes > len(record) {
			return false
		}
		n := 0
		for i := 0; i < lengthBytes; i++ {
			n = n<<8 | int(record[pos+i])
		}
		pos += lengthBytes + n
		return pos <= len(record)
	}
	if len(record) < pos || record[0] != tlsRecordHandshake || record[tlsRecordHeader] != 1 {
		return nil, false
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return nil, false
	}
	if pos+2 > len(record) {
		return nil, true
	}
	end := pos + 2 + int(record[pos])<<8 + int(record[pos+1])
	pos += 2
	if end > len(record) {
		return nil, false
	}
	for pos+4 <= end {
		ids = append(ids, uint16(record[pos])<<8|uint16(record[pos+1]))
		pos += 4 + int(record[pos+2])<<8 + int(record[pos+3])
	}
	return ids, pos == end
}
