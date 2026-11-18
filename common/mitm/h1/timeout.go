package h1

import (
	"net"
	"sync"
	"time"
)

// headTimer bounds request head reads with one timer per session. Arming it only resets the
// timer; when it expires it interrupts the read with a past read deadline, the way the watchers
// stop their peeks. Arming per request thus costs no allocation and no deadline update, also on
// connections whose deadlines are emulated with timers (sing's deadline.Conn).
//
// The timer is armed only while the Serve goroutine reads a request head; the client watch,
// the request body copy and tunnels run while it is disarmed, so their use of the client's read
// deadline never overlaps with it.
type headTimer struct {
	conn  net.Conn
	timer *time.Timer
	mu    sync.Mutex
	armed bool
	until time.Time // the armed expiry; a late callback for an earlier expiry is ignored
	fired bool      // the read deadline was moved into the past and must be cleared
}

func (h *headTimer) init(conn net.Conn) {
	h.conn = conn
	h.timer = time.AfterFunc(time.Hour, h.fire)
	h.timer.Stop()
}

func (h *headTimer) fire() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.armed || time.Now().Before(h.until) {
		return
	}
	h.fired = true
	_ = h.conn.SetReadDeadline(aLongTimeAgo)
}

// arm makes a read that is still running after d fail with os.ErrDeadlineExceeded.
// A deadline left in the past by an earlier expiry is cleared first.
func (h *headTimer) arm(d time.Duration) {
	h.mu.Lock()
	if h.fired {
		h.fired = false
		_ = h.conn.SetReadDeadline(time.Time{})
	}
	h.armed = true
	h.until = time.Now().Add(d)
	h.mu.Unlock()
	h.timer.Reset(d)
}

// disarm stops the timer and restores the read deadline if the timer had fired.
func (h *headTimer) disarm() {
	h.timer.Stop()
	h.mu.Lock()
	h.armed = false
	fired := h.fired
	h.fired = false
	h.mu.Unlock()
	if fired {
		_ = h.conn.SetReadDeadline(time.Time{})
	}
}
