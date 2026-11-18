package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// pinningSilenceWindow is how soon after the client handshake completes a
// close without any request counts as a rejected certificate.
const pinningSilenceWindow = time.Second

// certificateAlerts are the TLS alerts a client sends when it rejects the
// presented certificate: bad_certificate (42), unsupported_certificate (43),
// certificate_unknown (46) and unknown_ca (48). crypto/tls reports a
// received alert as a *net.OpError with Op "remote error" whose Err prints
// "tls: <description>"; its type is not exported.
var certificateAlerts = []string{
	"tls: bad certificate",
	"tls: unsupported certificate",
	"tls: unknown certificate",
	"tls: unknown certificate authority",
}

// certificateAlert returns the description of a certificate-rejecting alert
// in the error chain, or "".
func certificateAlert(err error) string {
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil {
		return ""
	}
	message := opErr.Err.Error()
	for _, alert := range certificateAlerts {
		if strings.EqualFold(message, alert) {
			return message
		}
	}
	return ""
}

// pinningTracker watches one decrypted session for the signs of a client
// that does not trust the generated certificate.
type pinningTracker struct {
	engine    *Engine
	host      string
	key       pinKey
	duration  time.Duration
	startedAt time.Time
	// shared marks a client that cannot be told apart from other local
	// apps (no process, local source): failures are recorded but never
	// feed the skip table.
	shared bool
}

// fail records a client rejection and reports whether the pair was added to
// the skip table.
func (t *pinningTracker) fail(message string, now time.Time) bool {
	if t.shared {
		t.engine.skips.observe(t.host, message, now)
		return false
	}
	added := t.engine.skips.failPinning(t.host, t.key, message, now, t.duration)
	if added {
		kind := "source"
		if t.key.process != "" {
			kind = "process"
		}
		t.engine.logger.Info("mitm: ", t.host, " added to skip table for ", t.duration, " (", kind, ")")
	}
	return added
}

// handshakeFailed classifies a client-side handshake error. An alert that
// rejects the certificate always counts. After a TLS 1.3 server certificate
// was sent (certificateSent), any alert, a bad record MAC or a close while
// waiting for the client's Finished counts too: OpenSSL clients send the
// rejection alert under keys crypto/tls does not read it with, and it
// surfaces as "local error: tls: bad record MAC". Failures before the
// certificate was sent never count.
func (t *pinningTracker) handshakeFailed(err error, certificateSent bool) bool {
	if alert := certificateAlert(err); alert != "" {
		return t.fail("client rejected the certificate: "+alert, t.engine.now())
	}
	if !certificateSent {
		return false
	}
	if reason := tls13FinishedFailure(err); reason != "" {
		return t.fail("client rejected the certificate: "+reason, t.engine.now())
	}
	return false
}

// tls13FinishedFailure describes a handshake error that, once the TLS 1.3
// server flight is out, means the client refused it, or "".
func tls13FinishedFailure(err error) string {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ""
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "closed after the server flight"
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Err == nil {
		return ""
	}
	message := opErr.Err.Error()
	switch {
	case opErr.Op == "remote error" && strings.HasPrefix(message, "tls: "):
		return message
	case opErr.Op == "local error" && message == "tls: bad record MAC":
		return "alert not readable after the server flight (" + message + ")"
	}
	return ""
}

// requested records the first request of a session: the client trusts the
// certificate.
func (t *pinningTracker) requested() {
	t.engine.skips.succeed(t.host, t.key)
}

// endOrder numbers the first read failure or local close of each side of a
// session, so that the side that ended first can be told apart.
type endOrder struct {
	counter atomic.Int64
}

// endWatchConn records how a side of a session first ended: a read failure
// (the peer closed or reset), or a close from this side, which the connection
// reports as net.ErrClosed on its next read. Read timeouts do not count.
type endWatchConn struct {
	net.Conn
	order *endOrder
	// first is the order number of the first end, 0 while the side is open.
	first atomic.Int64
	// peer is set when the first end was caused by the remote side.
	peer atomic.Bool
}

func (c *endWatchConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		var netErr net.Error
		if !(errors.As(err, &netErr) && netErr.Timeout()) {
			c.ended(!errors.Is(err, net.ErrClosed))
		}
	}
	return n, err
}

// Upstream keeps the connection chain visible to withDeadlineReader.
func (c *endWatchConn) Upstream() any {
	return c.Conn
}

func (c *endWatchConn) Close() error {
	c.ended(false)
	return c.Conn.Close()
}

func (c *endWatchConn) ended(byPeer bool) {
	if c.first.Load() != 0 {
		return
	}
	if c.first.CompareAndSwap(0, c.order.counter.Add(1)) {
		c.peer.Store(byPeer)
	}
}

// clientEndedFirst reports whether the client side was the first to end the
// session by its own doing: the upstream and local closes do not count.
func clientEndedFirst(client, upstream *endWatchConn) bool {
	first := client.first.Load()
	if first == 0 || !client.peer.Load() {
		return false
	}
	other := upstream.first.Load()
	return other == 0 || first < other
}

// finished is called when a decrypted session ends. A session that served
// no request and ended within the silence window after the handshake counts
// as a rejection when the client ended it first, as does one the client
// ended with a certificate alert. A session ended by the core (engine
// shutdown, or a close from the user or router, seen as net.ErrClosed or a
// cancelled context) or by the upstream side first never counts.
func (t *pinningTracker) finished(requests int64, exempt bool, clientFirst bool, err error) {
	now := t.engine.now()
	if alert := certificateAlert(err); alert != "" && requests == 0 {
		t.fail("client rejected the certificate: "+alert, now)
		return
	}
	if requests != 0 || exempt || !clientFirst || errors.Is(err, net.ErrClosed) {
		return
	}
	if now.Sub(t.startedAt) <= pinningSilenceWindow {
		t.fail("client closed without a request", now)
	}
}
