package mitm

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// readAheadSize holds two TLS records: larger reads below cost fewer hand-offs.
const readAheadSize = 32 << 10

// readAheadConn reads its connection on one goroutine, one buffer ahead of the reader. A read
// deadline ends only the waiting Read: the read below is never interrupted (a stream cipher
// frame, an outbound transport without read deadlines stay intact), and data or an error it
// returns later is delivered by the next Read. Reading ahead overlaps the read below with the
// processing of the previous buffer.
type readAheadConn struct {
	net.Conn
	results  chan readAheadResult
	closed   chan struct{}
	close    sync.Once
	deadline readDeadline

	access  sync.Mutex // guards current
	current readAheadResult
	ready   bool
}

type readAheadResult struct {
	buffer *buf.Buffer
	err    error
}

func newReadAheadConn(conn net.Conn) *readAheadConn {
	c := &readAheadConn{
		Conn:     conn,
		results:  make(chan readAheadResult, 1),
		closed:   make(chan struct{}),
		deadline: readDeadline{expired: make(chan struct{})},
	}
	go c.loop()
	return c
}

func (c *readAheadConn) loop() {
	for {
		buffer := buf.NewSize(readAheadSize)
		_, err := buffer.ReadOnceFrom(c.Conn)
		select {
		case c.results <- readAheadResult{buffer: buffer, err: err}:
		case <-c.closed:
			buffer.Release()
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *readAheadConn) Read(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	for {
		if !c.ready {
			select {
			case c.current = <-c.results:
			default:
				select {
				case c.current = <-c.results:
				case <-c.deadline.wait():
					return 0, os.ErrDeadlineExceeded
				case <-c.closed:
					return 0, net.ErrClosed
				}
			}
			c.ready = true
		}
		if buffer := c.current.buffer; buffer != nil {
			if !buffer.IsEmpty() {
				n, _ := buffer.Read(p)
				if !buffer.IsEmpty() {
					return n, nil
				}
				buffer.Release()
				c.current.buffer = nil
				// The error that came with the data follows on the next Read.
				c.ready = c.current.err != nil
				return n, nil
			}
			buffer.Release()
			c.current.buffer = nil
			c.ready = c.current.err != nil
			continue
		}
		// The error is final: the loop has stopped.
		return 0, c.current.err
	}
}

func (c *readAheadConn) SetReadDeadline(t time.Time) error {
	c.deadline.set(t)
	return nil
}

func (c *readAheadConn) SetDeadline(t time.Time) error {
	c.deadline.set(t)
	return c.Conn.SetWriteDeadline(t)
}

// NeedAdditionalReadDeadline tells sing's deadline helpers that read deadlines work.
func (c *readAheadConn) NeedAdditionalReadDeadline() bool {
	return false
}

func (c *readAheadConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// readDeadline is a resettable read deadline: wait returns a channel closed once it passed.
type readDeadline struct {
	access  sync.Mutex
	timer   *time.Timer
	expired chan struct{}
}

func (d *readDeadline) set(t time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		// The timer fired or is firing: wait for it to close expired.
		<-d.expired
	}
	d.timer = nil
	expired := isClosed(d.expired)
	if t.IsZero() {
		if expired {
			d.expired = make(chan struct{})
		}
		return
	}
	if duration := time.Until(t); duration > 0 {
		if expired {
			d.expired = make(chan struct{})
		}
		channel := d.expired
		d.timer = time.AfterFunc(duration, func() { close(channel) })
		return
	}
	if !expired {
		close(d.expired)
	}
}

func (d *readDeadline) wait() chan struct{} {
	d.access.Lock()
	defer d.access.Unlock()
	return d.expired
}

func isClosed(channel chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}
