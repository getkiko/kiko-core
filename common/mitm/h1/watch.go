package h1

import (
	"bufio"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/bufio/deadline"
)

// watcher detects that a peer went away while the relay is not reading from it: waiting for
// or streaming a response (client side), idle between exchanges (upstream side). It peeks, so
// no byte is consumed; a stop interrupts the peek with a past read deadline, as net/http does
// for its background reads.
type watcher struct {
	conn   net.Conn
	reader *bufio.Reader
	// dataEnds reports whether arriving data ends the watch quietly (a pipelined request)
	// instead of failing it (an unsolicited upstream message).
	dataEnds bool
	onFail   func()
	start    chan struct{}
	done     chan struct{}
	stopping atomic.Bool
	failed   atomic.Bool
	// active is set by whoever begins the watch and read by the Serve goroutine once it has
	// synchronized with that party.
	active bool
}

func (w *watcher) init(conn net.Conn, reader *bufio.Reader, dataEnds bool, onFail func()) {
	w.conn = conn
	w.reader = reader
	w.dataEnds = dataEnds
	w.onFail = onFail
	w.start = make(chan struct{}, 1)
	w.done = make(chan struct{}, 1)
	go w.run()
}

func (w *watcher) run() {
	for range w.start {
		_, err := w.reader.Peek(1)
		if !w.stopping.Load() && (err != nil || !w.dataEnds) {
			w.failed.Store(true)
			w.onFail()
		}
		w.done <- struct{}{}
	}
}

// begin starts watching; the reader must not be used by anyone else until end.
func (w *watcher) begin() {
	w.active = true
	w.start <- struct{}{}
}

// end stops a watch started by begin and returns once the reader is free again.
func (w *watcher) end() {
	if !w.active {
		return
	}
	w.stopping.Store(true)
	if w.conn.SetReadDeadline(aLongTimeAgo) != nil {
		// The peek cannot be interrupted: end the session rather than wait for the peer.
		w.onFail()
	}
	<-w.done
	_ = w.conn.SetReadDeadline(time.Time{})
	w.stopping.Store(false)
	w.active = false
}

// close ends the watcher goroutine after the connections were closed.
func (w *watcher) close() {
	if w.active {
		<-w.done
		w.active = false
	}
	close(w.start)
}

var aLongTimeAgo = time.Unix(1, 0)

// withReadDeadline returns conn, or conn behind sing's pipe-based deadline reader when its own
// read deadlines are missing or unsafe to interrupt.
func withReadDeadline(conn net.Conn) net.Conn {
	if deadline.NeedAdditionalReadDeadline(conn) || conn.SetReadDeadline(time.Time{}) != nil {
		return deadline.NewConn(conn)
	}
	return conn
}
