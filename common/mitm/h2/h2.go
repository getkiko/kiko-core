// Package h2 relays one decrypted HTTP/2 connection: it serves the client side
// with an HTTP/2 server and forwards every stream as a request on the upstream
// connection.
package h2

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/script"

	"golang.org/x/net/http2"
)

// Options configures Serve.
type Options struct {
	// ServerName is the name the client connected to (the SNI). A request whose
	// :authority names another host is answered 421 Misdirected Request.
	ServerName string
	// OnRequest is called once for every request forwarded upstream (a retry on a
	// redialed connection does not count again).
	OnRequest func()
	Logger    logger.ContextLogger // may be nil
	// Redial opens a fresh upstream connection on which HTTP/2 has been
	// negotiated (dialed through the same outbound chain, TLS-handshaken, ALPN
	// h2). It is called when the upstream sent GOAWAY or closed. nil disables
	// redialing. The returned conn is owned and closed by h2.
	Redial func(ctx context.Context) (net.Conn, error)
	// IdleTimeout bounds how long the connection may carry no stream
	// (0: DefaultIdleTimeout, negative: unbounded).
	IdleTimeout time.Duration
	// Observer, when not nil, receives one Exchange per stream that passed the
	// head checks. A retry on a redialed connection belongs to the same
	// Exchange. Observation never changes what is forwarded. net/http keeps no
	// field order, so recorded fields are sorted by name.
	Observer flow.Observer
	// Connection describes the connection for Observer; it may be nil.
	Connection *flow.ConnectionInfo
	// Rewrite returns the current rewrite rule set; it is called once per
	// stream, so a changed set applies to the next stream of a running
	// connection. nil disables rewriting.
	Rewrite func() *rewrite.Set
	// Internal opens a fresh upstream connection to the origin of an internal rewrite (a
	// "header" URL rule that names another host): dialed through the same outbound,
	// TLS-handshaken for an https target with ALPN http/1.1. The relay speaks HTTP/1.1 on it
	// (kept per origin for the session, closed when the session ends) and owns the conns. nil
	// makes such a request fail with 502.
	Internal func(ctx context.Context, in *rewrite.Internal) (net.Conn, error)
	// Scripts runs the http-request and http-response scripts that match a stream, after the
	// rewrite rules. nil disables scripts.
	Scripts *script.Manager
	// UpstreamProfile selects how the upstream HTTP/2 client looks on the wire:
	// "" is net/http's own, ProfileChrome speaks like Chrome (SETTINGS, window
	// update, pseudo-header and header order).
	UpstreamProfile string
}

// DefaultIdleTimeout is the default Options.IdleTimeout.
const DefaultIdleTimeout = 2 * time.Minute

const (
	// streamWindow and connWindow bound what each side may have in flight
	// towards the proxy, so a slow peer backpressures the other one.
	streamWindow = 256 << 10
	connWindow   = 4 << 20
	// maxStreams is the concurrency the client may use.
	maxStreams = 100
	// maxHeaderBytes matches the h1 engine's header limit.
	maxHeaderBytes = 64 << 10
	maxFrameSize   = 64 << 10

	upstreamPingAfter   = 30 * time.Second
	upstreamPingTimeout = 15 * time.Second
	redialTimeout       = 30 * time.Second

	copyBufferSize = 32 << 10
)

var bufferPool = sync.Pool{New: func() any {
	b := make([]byte, copyBufferSize)
	return &b
}}

// session is the state of one relayed connection.
type session struct {
	ctx    context.Context
	opts   Options
	client net.Conn
	wg     sync.WaitGroup

	mu    sync.Mutex
	cur   *upConn
	conns map[*upConn]struct{}
	shut  bool

	redialMu sync.Mutex

	// ext holds the HTTP/1.1 transports of internal rewrites, per target origin.
	extMu sync.Mutex
	ext   map[string]*http.Transport
	// extClosed is set by shutdown (guarded by extMu).
	extClosed bool

	active atomic.Int32
	// gone reports that the upstream can no longer be reached; the client
	// connection is closed once its last stream finished, unless a later
	// acquire found a usable upstream again.
	gone atomic.Bool
}

// clientConn is the part of net/http.ClientConn the relay uses.
type clientConn interface {
	RoundTrip(*http.Request) (*http.Response, error)
	Err() error
	Close() error
}

// upConn is one upstream HTTP/2 connection. A replaced connection stays open
// until the streams still using it finished.
type upConn struct {
	cc      clientConn
	nc      net.Conn
	refs    int // guarded by session.mu
	retired bool
	bad     atomic.Bool
}

func (u *upConn) healthy() bool {
	if u.bad.Load() {
		return false
	}
	return u.cc.Err() == nil
}

// Serve relays the HTTP/2 connection client (a TLS server connection that
// negotiated h2) to upstream (a TLS client connection that negotiated h2). It
// blocks until the session ends and closes both connections.
func Serve(ctx context.Context, client net.Conn, upstream net.Conn, options Options) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s := &session{
		ctx:    ctx,
		opts:   options,
		client: client,
		conns:  make(map[*upConn]struct{}),
	}
	first, err := s.newUpConn(upstream)
	if err != nil {
		client.Close()
		upstream.Close()
		return E.Cause(err, "start upstream h2")
	}
	s.cur = first

	// A cancelled context ends the session: closing the client conn makes the
	// server return, closing the upstream conns fails the pending requests.
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		s.shutdown()
	})
	defer stop()

	idle := options.IdleTimeout
	switch {
	case idle == 0:
		idle = DefaultIdleTimeout
	case idle < 0:
		idle = 0
	}
	srv := &http2.Server{
		MaxConcurrentStreams:         maxStreams,
		MaxUploadBufferPerStream:     streamWindow,
		MaxUploadBufferPerConnection: connWindow,
		MaxReadFrameSize:             maxFrameSize,
		IdleTimeout:                  idle,
	}
	srv.ServeConn(client, &http2.ServeConnOpts{
		Context: ctx,
		Handler: s,
		BaseConfig: &http.Server{
			MaxHeaderBytes: maxHeaderBytes,
			ErrorLog:       log.New(logWriter{options.Logger}, "", 0),
			HTTP2: &http.HTTP2Config{
				MaxConcurrentStreams:          maxStreams,
				MaxReceiveBufferPerStream:     streamWindow,
				MaxReceiveBufferPerConnection: connWindow,
				MaxReadFrameSize:              maxFrameSize,
			},
		},
	})
	cancel()
	client.Close()
	s.shutdown()
	s.wg.Wait()
	s.debug("h2 session ended")
	return parent.Err()
}

func (s *session) debug(args ...any) {
	if s.opts.Logger != nil {
		s.opts.Logger.Debug(args...)
	}
}

// newUpConn starts an HTTP/2 client connection on nc and registers it.
func (s *session) newUpConn(nc net.Conn) (*upConn, error) {
	var (
		cc  clientConn
		err error
	)
	if s.opts.UpstreamProfile == ProfileChrome {
		cc, err = newChromeClientConn(s.ctx, nc)
	} else {
		cc, err = newClientConn(s.ctx, nc)
	}
	if err != nil {
		return nil, err
	}
	u := &upConn{cc: cc, nc: nc}
	s.mu.Lock()
	if s.shut {
		s.mu.Unlock()
		cc.Close()
		nc.Close()
		return nil, io.ErrClosedPipe
	}
	s.conns[u] = struct{}{}
	s.mu.Unlock()
	return u, nil
}

// shutdown closes every upstream connection.
func (s *session) shutdown() {
	s.mu.Lock()
	s.shut = true
	conns := s.conns
	s.conns = make(map[*upConn]struct{})
	s.mu.Unlock()
	for u := range conns {
		closeUp(u)
	}
	s.extMu.Lock()
	ext := s.ext
	s.extClosed = true
	s.ext = nil
	s.extMu.Unlock()
	for _, t := range ext {
		t.CloseIdleConnections()
	}
}

func closeUp(u *upConn) {
	u.cc.Close()
	u.nc.Close()
}

// acquire returns the upstream connection for a new request and counts the
// request on it. stale is a connection the caller found unusable; it is never
// returned and a fresh one is dialed in its place when Redial is set.
func (s *session) acquire(stale *upConn) (*upConn, error) {
	if u := s.pick(stale); u != nil {
		s.gone.Store(false)
		return u, nil
	}
	if s.opts.Redial == nil {
		s.gone.Store(true)
		return nil, errUpstreamGone
	}
	// One dial serves every stream that found the connection unusable.
	s.redialMu.Lock()
	defer s.redialMu.Unlock()
	if u := s.pick(stale); u != nil {
		s.gone.Store(false)
		return u, nil
	}
	dctx, cancel := context.WithTimeout(s.ctx, redialTimeout)
	nc, err := s.opts.Redial(dctx)
	cancel()
	if err != nil {
		s.gone.Store(true)
		s.debug("h2 upstream redial failed: ", err)
		return nil, E.Cause(err, "redial upstream")
	}
	u, err := s.newUpConn(nc)
	if err != nil {
		nc.Close()
		s.gone.Store(true)
		return nil, E.Cause(err, "start redialed upstream")
	}
	s.debug("h2 upstream redialed")
	// A later redial can succeed after an earlier one failed.
	s.gone.Store(false)
	s.mu.Lock()
	old := s.cur
	s.cur = u
	u.refs++
	var closeOld bool
	if old != nil {
		old.retired = true
		closeOld = old.refs == 0
		if closeOld {
			delete(s.conns, old)
		}
	}
	s.mu.Unlock()
	if closeOld {
		closeUp(old)
	}
	return u, nil
}

// pick takes a reference on the current connection when it is usable.
func (s *session) pick(stale *upConn) *upConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.cur
	if s.shut || u == nil || u == stale || !u.healthy() {
		return nil
	}
	u.refs++
	return u
}

// release drops a request's reference and closes a replaced connection that
// has drained.
func (s *session) release(u *upConn) {
	s.mu.Lock()
	u.refs--
	closeNow := u.retired && u.refs == 0
	if closeNow {
		delete(s.conns, u)
	}
	s.mu.Unlock()
	if closeNow {
		closeUp(u)
	}
}

// markBad stops new requests from using u.
func (s *session) markBad(u *upConn) {
	u.bad.Store(true)
}

type logWriter struct{ logger logger.ContextLogger }

func (w logWriter) Write(p []byte) (int, error) {
	if w.logger != nil {
		w.logger.Debug("h2 server: ", string(p))
	}
	return len(p), nil
}
