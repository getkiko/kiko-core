// Package h1 relays HTTP/1.1 between a decrypted client connection and a decrypted upstream
// connection, one exchange at a time.
package h1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/httpx"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/common/mitm/scripthook"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/common/buf"
	sbufio "github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// Options configures Serve.
type Options struct {
	// OnRequest is called once for every request head forwarded upstream (once per request,
	// also when the head is resent on a redialed connection).
	OnRequest func()
	Logger    logger.ContextLogger // may be nil
	// Redial opens a fresh upstream connection that is ready for HTTP/1.1 (dialed through the same
	// outbound chain, TLS-handshaken, ALPN http/1.1). nil disables redialing. h1 closes the
	// connection it replaces. The returned conn is owned and closed by h1.
	Redial func(ctx context.Context) (net.Conn, error)
	// IdleTimeout bounds how long the client may stay silent between requests
	// (0: DefaultIdleTimeout, negative: unbounded).
	IdleTimeout time.Duration
	// HeaderTimeout bounds reading one request head once its first byte arrived
	// (0: DefaultHeaderTimeout, negative: unbounded).
	HeaderTimeout time.Duration
	// Observer, when not nil, receives one Exchange per request that passed the head checks:
	// the request and response heads as received (wire order, before hop-by-hop removal),
	// both bodies as they are forwarded, interim responses, trailers, protocol switches and
	// timing points. A resent head (Redial) belongs to the same Exchange and only updates its
	// timing. Observation never changes what is forwarded. After a 101 or a CONNECT tunnel
	// no further bytes are reported.
	Observer flow.Observer
	// Connection describes the connection for Observer; it may be nil.
	Connection *flow.ConnectionInfo
	// Rewrite returns the current rewrite rule set; it is called once per request, so a changed
	// set applies to the next request of a running connection. nil disables rewriting.
	Rewrite func() *rewrite.Set
	// Scheme is the URL scheme rules and records see: "https" (default) or "http".
	Scheme string
	// Internal opens a fresh upstream connection to the origin of an internal rewrite (a "header"
	// URL rule that names another host): dialed through the same outbound, TLS-handshaken for an
	// https target with ALPN http/1.1. It is used for that one request, whose answer then ends the
	// connection; the regular upstream stays as it was. h1 owns the returned conn. nil makes such
	// a request fail with 502.
	Internal func(ctx context.Context, in *rewrite.Internal) (net.Conn, error)
	// Scripts runs the http-request and http-response scripts that match a request, after the
	// rewrite rules. nil disables scripts.
	Scripts *script.Manager
}

const (
	// DefaultIdleTimeout is the default Options.IdleTimeout.
	DefaultIdleTimeout = 2 * time.Minute
	// DefaultHeaderTimeout is the default Options.HeaderTimeout.
	DefaultHeaderTimeout = 30 * time.Second
)

const (
	ioBufferSize   = 4096
	copyBufferSize = 32 * 1024
)

var (
	errUnsolicitedSwitch = E.New("upstream switched protocols without an upgrade request")
	errUnofferedSwitch   = E.New("upstream switched to a protocol the client did not offer")
	errCodingsHTTP10     = E.New("transfer codings in a response to an HTTP/1.0 client")
	errClose             = errors.New("close after exchange")
)

const (
	badRequest          = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	uriTooLong          = "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	headerTooLarge      = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	notImplemented      = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	badGateway          = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	versionNotSupported = "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)

// errorReply is the response answering a request rejected with err.
func errorReply(err error) string {
	switch httpx.RequestErrorStatus(err) {
	case 414:
		return uriTooLong
	case 431:
		return headerTooLarge
	case 501:
		return notImplemented
	case 505:
		return versionNotSupported
	default:
		return badRequest
	}
}

// flushWriter flushes after every write so streamed bodies are not held back.
type flushWriter struct {
	w *bufio.Writer
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, f.w.Flush()
}

type session struct {
	ctx     context.Context
	options Options
	client  net.Conn
	// upstream is replaced by redial on the Serve goroutine under upstreamMu; other goroutines
	// reach it only through closeUpstream and closeBoth.
	upstream   net.Conn
	upstreamMu sync.Mutex
	closed     bool

	idleTimeout   time.Duration
	headerTimeout time.Duration
	timed         bool // either timeout is set and headTimer is initialized
	headTimer     headTimer

	clientR   *bufio.Reader
	clientW   *bufio.Writer
	upstreamR *bufio.Reader
	upstreamW *bufio.Writer

	clientHead   httpx.HeadReader
	upstreamHead httpx.HeadReader
	req          httpx.Request
	resp         httpx.Response

	clientFlush   flushWriter
	upstreamFlush flushWriter

	// Response body copy, on the Serve goroutine.
	copyBuffer   []byte
	limited      io.LimitedReader
	chunkedR     httpx.ChunkedReader
	responsePipe bodyPipe
	requestPipe  bodyPipe

	// Request body copy, on its own goroutine while the response is read.
	bodyBuffer   []byte
	bodyFraming  httpx.Framing
	bodyLimited  io.LimitedReader
	bodyChunkedR httpx.ChunkedReader
	bodyDone     chan error
	bodyRunning  bool

	// clientWatch runs while the client is not read (waiting for and streaming a response),
	// upstreamWatch while the upstream is idle between exchanges.
	clientWatch   watcher
	upstreamWatch watcher
	// exchanges counts completed exchanges on the session, upstreamExchanges those on the
	// current upstream connection: on a reused upstream connection an upstream that closes
	// before answering is retried (Redial) or ends the client connection instead of answering
	// 502.
	exchanges         int
	upstreamExchanges int
	// upstreamDead is set when the idle upstream went away and must be redialed before the
	// next request (Redial only).
	upstreamDead bool
	// parked is the regular upstream while a request is served by an internal rewrite's own
	// connection (guarded by upstreamMu).
	parked *parkedUpstream
	// reserved is the buffering budget taken by the current exchange.
	reserved int64
	// internalScheme is the scheme of the current request after an internal rewrite.
	internalScheme string
	// planSet is the rule set the current request was matched against.
	planSet *rewrite.Set
	// sx follows the scripts of the current request (nil without matching scripts).
	sx *scripthook.Exchange
	// respReplay, when set, replaces the response body source of copyResponseBody.
	respReplay io.Reader

	// Observation of the current exchange (nil without Options.Observer).
	obs      flow.Exchange
	reqBody  flow.Body
	respBody flow.Body
	scratch  []flow.Header

	// localServed is set when the exchange was answered by a rewrite rule without the upstream;
	// abortErr is what the observer is told when a rule dropped the connection.
	localServed bool
	abortErr    error
}

var ioPool = sync.Pool{New: func() any {
	return &ioBuffers{
		clientR:   bufio.NewReaderSize(nil, ioBufferSize),
		clientW:   bufio.NewWriterSize(nil, ioBufferSize),
		upstreamR: bufio.NewReaderSize(nil, ioBufferSize),
		upstreamW: bufio.NewWriterSize(nil, ioBufferSize),
	}
}}

type ioBuffers struct {
	clientR   *bufio.Reader
	clientW   *bufio.Writer
	upstreamR *bufio.Reader
	upstreamW *bufio.Writer
}

func timeout(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	if value < 0 {
		return 0
	}
	return value
}

// Serve relays HTTP/1.1 between the decrypted client connection and the decrypted upstream
// connection until either side ends or ctx is done, then closes both. Returns nil when the
// client closed cleanly between messages, stayed idle past IdleTimeout, or the exchange ended
// by Connection: close; otherwise the error.
//
// Exchanges are strictly serial: the next request is read only after the previous response
// completed. Bodies are re-framed (Content-Length kept, chunked decoded and re-encoded with its
// permitted trailer fields) and hop-by-hop fields removed. Interim 1xx responses are forwarded
// as they arrive; a 101 answer to an upgrade request turns the connection into a byte tunnel,
// as does a 2xx answer to CONNECT. With Options.Redial an upstream that closed while idle is
// replaced before the next request, and an idempotent request without content is resent once
// when a reused upstream connection fails before answering.
func Serve(ctx context.Context, client net.Conn, upstream net.Conn, options Options) error {
	// The watchers interrupt their peeks with read deadlines.
	client = withReadDeadline(client)
	upstream = withReadDeadline(upstream)
	buffers := ioPool.Get().(*ioBuffers)
	buffers.clientR.Reset(client)
	buffers.clientW.Reset(client)
	buffers.upstreamR.Reset(upstream)
	buffers.upstreamW.Reset(upstream)
	s := &session{
		ctx:           ctx,
		options:       options,
		client:        client,
		upstream:      upstream,
		idleTimeout:   timeout(options.IdleTimeout, DefaultIdleTimeout),
		headerTimeout: timeout(options.HeaderTimeout, DefaultHeaderTimeout),
		clientR:       buffers.clientR,
		clientW:       buffers.clientW,
		upstreamR:     buffers.upstreamR,
		upstreamW:     buffers.upstreamW,
		copyBuffer:    buf.Get(copyBufferSize),
		bodyDone:      make(chan error, 1),
	}
	s.clientHead = httpx.HeadReader{Reader: s.clientR, Limits: httpx.DefaultLimits}
	s.upstreamHead = httpx.HeadReader{Reader: s.upstreamR, Limits: httpx.DefaultLimits}
	s.clientFlush.w = s.clientW
	s.upstreamFlush.w = s.upstreamW

	closeBoth := s.closeBoth
	s.clientWatch.init(client, s.clientR, true, closeBoth)
	if s.idleTimeout > 0 || s.headerTimeout > 0 {
		s.timed = true
		s.headTimer.init(client)
	}
	if options.Redial != nil {
		// An idle upstream that went away is replaced; the client connection stays.
		s.upstreamWatch.init(upstream, s.upstreamR, false, s.closeUpstream)
	} else {
		s.upstreamWatch.init(upstream, s.upstreamR, false, closeBoth)
	}
	stop := context.AfterFunc(ctx, closeBoth)
	err := s.loop()
	stop()
	if s.timed {
		s.headTimer.timer.Stop()
	}
	peerGone := s.clientWatch.failed.Load() || s.upstreamWatch.failed.Load()
	closeBoth()
	if s.bodyRunning {
		<-s.bodyDone
	}
	s.clientWatch.close()
	s.upstreamWatch.close()
	s.responsePipe.close()
	s.requestPipe.close()
	buf.Put(s.copyBuffer)
	if s.bodyBuffer != nil {
		buf.Put(s.bodyBuffer)
	}
	buffers.clientR.Reset(nil)
	buffers.clientW.Reset(nil)
	buffers.upstreamR.Reset(nil)
	buffers.upstreamW.Reset(nil)
	ioPool.Put(buffers)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err == errClose || peerGone {
		// A peer that went away between or during exchanges ends the session normally.
		return nil
	}
	return err
}

// closeBoth closes the client and the current upstream connection; safe from any goroutine.
func (s *session) closeBoth() {
	s.upstreamMu.Lock()
	s.closed = true
	upstream := s.upstream
	parked := s.parked
	s.upstreamMu.Unlock()
	s.client.Close()
	upstream.Close()
	if parked != nil {
		parked.conn.Close()
	}
}

// closeUpstream closes the current upstream connection; safe from any goroutine.
func (s *session) closeUpstream() {
	s.upstreamMu.Lock()
	upstream := s.upstream
	s.upstreamMu.Unlock()
	upstream.Close()
}

func (s *session) isClosed() bool {
	s.upstreamMu.Lock()
	defer s.upstreamMu.Unlock()
	return s.closed
}

// redial replaces the upstream connection with a fresh one from Options.Redial. It runs on the
// Serve goroutine while neither the upstream watch nor the request body copy uses the upstream.
func (s *session) redial() error {
	if s.isClosed() {
		return net.ErrClosed
	}
	conn, err := s.options.Redial(s.ctx)
	if err != nil {
		return E.Cause(err, "redial upstream")
	}
	if conn == nil {
		return E.New("redial upstream: no connection")
	}
	conn = withReadDeadline(conn)
	s.upstreamMu.Lock()
	if s.closed {
		s.upstreamMu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	previous := s.upstream
	s.upstream = conn
	s.upstreamMu.Unlock()
	previous.Close()
	s.upstreamR.Reset(conn)
	s.upstreamW.Reset(conn)
	s.upstreamWatch.conn = conn
	s.upstreamWatch.failed.Store(false)
	s.upstreamExchanges = 0
	s.upstreamDead = false
	s.debug("redialed upstream")
	return nil
}

func (s *session) debug(args ...any) {
	if s.options.Logger != nil {
		s.options.Logger.DebugContext(s.ctx, args...)
	}
}

func (s *session) reply(raw string) {
	s.clientW.WriteString(raw)
	s.clientW.Flush()
}

const (
	rejectLinger     = 500 * time.Millisecond
	rejectDrainLimit = 256 << 10
)

// rejectRequest answers a rejected request, ends the client direction and drains what the
// client still sends for a moment before the connection closes: unread data would make the
// close a TCP reset, which can destroy the reply before the client reads it (as net/http's
// closeWriteAndWait avoids).
func (s *session) rejectRequest(raw string) {
	s.reply(raw)
	_ = N.CloseWrite(s.client)
	_ = s.client.SetReadDeadline(time.Now().Add(rejectLinger))
	_, _ = io.CopyN(io.Discard, s.clientR, rejectDrainLimit)
}

func isTimeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// readRequestHead reads the next request head under the idle and header timeouts: the client
// may stay silent for idleTimeout before the first byte, then has headerTimeout for the head.
// A silent client is reported as io.EOF. The timer is disarmed before returning, so bodies,
// the client watch and tunnels run without it.
func (s *session) readRequestHead() error {
	if !s.timed {
		return s.clientHead.ReadRequest(&s.req)
	}
	if s.clientR.Buffered() == 0 {
		if s.idleTimeout > 0 {
			s.headTimer.arm(s.idleTimeout)
		}
		if _, err := s.clientR.Peek(1); err != nil {
			s.headTimer.disarm()
			if isTimeout(err) {
				s.debug("client idle timeout")
				return io.EOF
			}
			return err
		}
	}
	if s.headerTimeout > 0 {
		s.headTimer.arm(s.headerTimeout)
	} else {
		s.headTimer.disarm()
	}
	err := s.clientHead.ReadRequest(&s.req)
	s.headTimer.disarm()
	return err
}

func (s *session) loop() error {
	for {
		if s.upstreamExchanges > 0 && !s.upstreamDead {
			s.upstreamWatch.begin()
		}
		err := s.readRequestHead()
		s.upstreamWatch.end()
		if s.options.Redial != nil && s.upstreamWatch.failed.Load() {
			// The idle upstream closed or sent unsolicited data: replace it on the next request.
			s.upstreamWatch.failed.Store(false)
			s.upstreamDead = true
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if isTimeout(err) {
				// A head that stalls past HeaderTimeout ends the connection without a reply.
				return E.Cause(err, "read request")
			}
			if err != io.ErrUnexpectedEOF && !E.IsClosedOrCanceled(err) {
				s.debug("malformed request: ", err)
				s.rejectRequest(errorReply(err))
			}
			return E.Cause(err, "read request")
		}
		err = s.exchange()
		if err != nil {
			return err
		}
		s.exchanges++
		// A locally answered exchange leaves the upstream idle but equally exposed to idle
		// closes: it is watched and treated as reused from then on.
		s.localServed = false
		s.upstreamExchanges++
	}
}

// idempotent reports whether a request may be sent again (RFC 9110 section 9.2.2), by method or
// by an idempotency key field.
func idempotent(req *httpx.Request) bool {
	switch req.Method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	}
	return req.Header.Has("Idempotency-Key") || req.Header.Has("X-Idempotency-Key")
}

func (s *session) writeRequestHead() error {
	httpx.WriteRequestHead(s.upstreamW, &s.req)
	return s.upstreamW.Flush()
}

// exchange relays one request and reports it to the observer.
func (s *session) exchange() error {
	err := s.exchangeObserved()
	rewrite.ReleaseHold(&s.reserved)
	if s.parked != nil && err == nil {
		s.leaveInternal()
	}
	return err
}

func (s *session) exchangeObserved() error {
	if s.options.Observer == nil {
		return s.relay()
	}
	s.obs, s.reqBody, s.respBody = nil, nil, nil
	s.abortErr = nil
	err := s.relay()
	if s.obs != nil {
		observed := err
		if observed == errClose {
			observed = nil
			if s.abortErr != nil {
				observed = s.abortErr
			}
		}
		s.respBody.Done()
		s.obs.Finish(observed)
		s.obs, s.reqBody, s.respBody = nil, nil, nil
	}
	return err
}

// observeRequest starts the Exchange for the request in s.req.
func (s *session) observeRequest() {
	req := &s.req
	s.obs = s.options.Observer.NewExchange(s.options.Connection)
	s.reqBody = s.obs.RequestBody()
	s.respBody = s.obs.ResponseBody()
	s.obs.RequestHead(flow.RequestHead{
		Method:    req.Method,
		Scheme:    s.scheme(),
		Authority: req.Header.Get("Host"),
		Path:      req.Target,
		Proto:     "http/1.1",
		Headers:   s.flowHeaders(req.Header),
	})
}

// flowHeaders converts header into the reused scratch slice; the observer copies what it keeps.
func (s *session) flowHeaders(header httpx.Header) []flow.Header {
	out := s.scratch[:0]
	for i := range header {
		out = append(out, flow.Header{Name: header[i].Name, Value: header[i].Value})
	}
	s.scratch = out
	return out
}

func trailerHeaders(header httpx.Header) []flow.Header {
	out := make([]flow.Header, 0, len(header))
	for i := range header {
		out = append(out, flow.Header{Name: header[i].Name, Value: header[i].Value})
	}
	return out
}

func (s *session) observeResponseReader(r io.Reader) io.Reader {
	if s.respBody == nil {
		return r
	}
	return s.respBody.Reader(r)
}

// markRequestSent notes that the request head was written upstream (again, after a redial).
func (s *session) markRequestSent() {
	if s.obs != nil {
		s.obs.Mark(flow.PointRequestHeaders, time.Now())
	}
}

func (s *session) relay() error {
	req := &s.req
	err := httpx.CheckHost(req)
	var framing httpx.Framing
	if err == nil {
		framing, err = httpx.RequestFraming(req)
	}
	if err != nil {
		s.debug("malformed request: ", err)
		s.rejectRequest(errorReply(err))
		return E.Cause(err, "read request")
	}
	s.internalScheme = ""
	originScheme := s.scheme()
	originAuthority := req.Header.Get("Host")
	plan := s.rewritePlan()
	var requestHits []flow.RewriteHit
	var external *rewrite.Internal
	if in := plan.Internal(); in != nil {
		// Internal rewrite: the request goes to another origin and path; the rules of the new
		// URL (never the URL rules again) decide the rest.
		host, port := splitAuthority(req.Header.Get("Host"), s.scheme())
		if !in.SameOrigin(s.scheme(), host, port) {
			external = in
		}
		req.Header.Set("Host", in.Authority)
		req.Target = in.Target
		s.internalScheme = in.Scheme
		plan = s.planSet.PlanAfterInternal(in)
		requestHits = append(requestHits, in.Hit)
	}
	if plan.HasRequestEdits() {
		var hits []flow.RewriteHit
		req.Header, hits = applyHeaders(plan, false, req.Header)
		requestHits = append(requestHits, hits...)
	}
	var sx *scripthook.Exchange
	if plan.Local() == nil && s.options.Scripts != nil && req.Method != "CONNECT" && len(req.Target) > 0 && req.Target[0] == '/' {
		sx = scripthook.Begin(s.ctx, s.options.Scripts, s.rewriteSet(), s.scheme(), req.Header.Get("Host"), req.Target, req.Method)
	}
	s.sx = sx
	var heldReq *rewrite.Held
	var requestStart time.Time
	upgradeRequest := req.Header.HasToken("Connection", "upgrade")
	hasBody := framing.Kind != httpx.BodyNone
	wantBody := plan.HasBodyRules(rewrite.ScopeRequest) || sx.WantsBody(script.PhaseRequest, hasBody && !upgradeRequest)
	if wantBody {
		requestStart = time.Now()
	}
	if wantBody && hasBody && !upgradeRequest {
		heldReq, err = s.collectRequest(plan, s.planSet, &framing, !req.ProtoAtLeast(1, 1), sx)
		if err != nil {
			if err != io.ErrUnexpectedEOF && !E.IsClosedOrCanceled(err) {
				s.rejectRequest(badRequest)
			}
			return E.Cause(err, "read request body")
		}
		if heldReq != nil {
			if heldReq.Changed {
				dropDigests(&req.Header, heldReq.Hits, s.bodyChunkedR.Trailer())
				editedLength(&req.Header, len(heldReq.Data))
				framing = httpx.Framing{Kind: httpx.BodyLength, Length: int64(len(heldReq.Data))}
			}
			requestHits = append(requestHits, heldReq.Hits...)
		}
	}
	var scriptLocal *rewrite.LocalResponse
	if sx.HasResponse() {
		sx.SetRequestHeaders(toFlowHeaders(req.Header))
	}
	if sx.HasRequest() {
		out := sx.RunRequest(&scripthook.Message{
			Headers:  toFlowHeaders(req.Header),
			Held:     heldReq,
			Encoding: joinValues(req.Header, "Content-Encoding"),
			HasBody:  heldReq != nil,
			Limit:    max(s.planSet.MaxBodySize(), sx.MaxBody(script.PhaseRequest)),
		}, req.Target)
		if out.HeadersChanged {
			req.Header = fromFlowHeaders(out.Headers)
		}
		if out.Internal != nil {
			in := out.Internal
			req.Header.Set("Host", in.Authority)
			req.Target = in.Target
			s.internalScheme = in.Scheme
			external = nil
			if originHost, originPort := splitAuthority(originAuthority, originScheme); !in.SameOrigin(originScheme, originHost, originPort) {
				external = in
			}
		}
		if out.BodyChanged && heldReq != nil {
			heldReq.Data, heldReq.Changed = out.Body, true
			dropDigests(&req.Header, out.Hits, s.bodyChunkedR.Trailer())
			editedLength(&req.Header, len(out.Body))
			framing = httpx.Framing{Kind: httpx.BodyLength, Length: int64(len(out.Body))}
		}
		requestHits = append(requestHits, out.Hits...)
		scriptLocal = out.Local
	}
	if s.options.Observer != nil {
		s.observeRequest()
		if !requestStart.IsZero() {
			// Buffering the body must not push the start of the exchange back.
			s.obs.Mark(flow.PointStart, requestStart)
		}
		if len(requestHits) > 0 {
			s.obs.Rewritten(requestHits)
		}
	}
	http10 := !req.ProtoAtLeast(1, 1)
	closeAfter := http10 || req.Header.HasToken("Connection", "close")
	if req.Header.HasToken("Upgrade", "h2c") {
		req.Header.Del("Upgrade")
		req.Header.Del("HTTP2-Settings")
	}
	// RFC 9110 section 7.8: Upgrade in an HTTP/1.0 request is ignored (and so removed).
	upgrade := !http10 && req.Header.HasToken("Connection", "upgrade") && req.Header.Has("Upgrade")
	expectContinue := false
	if req.Header.Has("Expect") {
		if http10 {
			// RFC 9110 section 10.1.1: 100-continue is not meant for HTTP/1.0.
			req.Header.Del("Expect")
		} else {
			expectContinue = req.Header.HasToken("Expect", "100-continue")
		}
	}
	method := req.Method

	header := httpx.RemoveHopByHop(req.Header, upgrade)
	switch framing.Kind {
	case httpx.BodyChunked:
		header = append(header, httpx.Field{Name: "Transfer-Encoding", Value: "chunked"})
	case httpx.BodyLength:
		header = setContentLength(header, framing.Length)
	case httpx.BodyNone:
		if header.Has("Content-Length") {
			header = setContentLength(header, 0)
		}
	}
	req.Header = header

	if local := plan.Local(); local != nil {
		return s.serveLocal(local, framing.Kind != httpx.BodyNone, http10, closeAfter)
	}
	if scriptLocal != nil {
		return s.serveLocal(scriptLocal, framing.Kind != httpx.BodyNone, http10, closeAfter)
	}
	if external != nil {
		if err = s.enterInternal(external); err != nil {
			s.debug("internal rewrite: ", err)
			s.reply(badGateway)
			return E.Cause(err, "internal rewrite")
		}
	}
	if s.upstreamExchanges > 0 && s.upstreamR.Buffered() > 0 {
		// Bytes the upstream sent beyond its last response answer no request and must not be
		// taken for the answer to this one (response queue poisoning). The upstream watch
		// catches such bytes while idle; this catches those that came with the response or
		// raced with a pipelined request.
		s.debug("unsolicited upstream data")
		if s.options.Redial == nil {
			return errClose
		}
		s.closeUpstream()
		s.upstreamDead = true
	}
	if s.upstreamDead {
		// Nothing was sent yet, so any request may go to a fresh connection.
		if err = s.redial(); err != nil {
			if s.exchanges > 0 {
				// A reused connection that closes is retried by the client on a new one; a 502
				// would be shown to the user.
				s.debug(err)
				return errClose
			}
			if !s.isClosed() {
				s.reply(badGateway)
			}
			return err
		}
	}
	retry := s.options.Redial != nil && framing.Kind == httpx.BodyNone && idempotent(req)
	redialed := false
	reused := s.upstreamExchanges > 0
	if err = s.writeRequestHead(); err != nil {
		if !reused {
			s.reply(badGateway)
			return E.Cause(err, "write request")
		}
		if !retry {
			// The upstream closed the idle connection: close the client's as well, so that
			// it retries on a new one.
			return errClose
		}
		if s.redial() != nil {
			return errClose
		}
		redialed, reused = true, false
		if err = s.writeRequestHead(); err != nil {
			s.reply(badGateway)
			return E.Cause(err, "write request")
		}
	}
	if s.options.OnRequest != nil {
		s.options.OnRequest()
	}
	s.markRequestSent()
	if framing.Kind != httpx.BodyNone && heldReq != nil && heldReq.Complete {
		if err = s.writeHeldRequest(heldReq, framing); err != nil {
			s.reply(badGateway)
			return E.Cause(err, "write request body")
		}
		s.clientWatch.begin()
	} else if framing.Kind != httpx.BodyNone {
		if s.bodyBuffer == nil {
			s.bodyBuffer = buf.Get(copyBufferSize)
		}
		s.bodyFraming = framing
		s.bodyRunning = true
		var replay io.Reader
		if heldReq != nil {
			replay = heldReq.Replay
		}
		go s.copyRequestBody(s.obs, s.reqBody, replay)
	} else {
		s.clientWatch.begin()
	}

	continued := false
	interim := false
	for {
		err = s.upstreamHead.ReadResponse(&s.resp)
		if err != nil {
			if reused && !interim && !s.upstreamHead.Partial() && (err == io.EOF || E.IsClosedOrCanceled(err)) {
				// The reused connection closed before answering: likely an idle close racing
				// with the request.
				if retry && !redialed && s.redial() == nil {
					redialed, reused = true, false
					if err = s.writeRequestHead(); err == nil {
						s.markRequestSent()
						continue
					}
					s.reply(badGateway)
					return E.Cause(err, "write request")
				}
				return errClose
			}
			s.reply(badGateway)
			return E.Cause(err, "read response")
		}
		interim = true
		code := s.resp.StatusCode
		if code >= 200 {
			break
		}
		if s.obs != nil {
			if code == 101 {
				if upgrade {
					s.obs.Upgrade(code, s.flowHeaders(s.resp.Header))
				}
			} else {
				s.obs.Informational(code, s.flowHeaders(s.resp.Header))
			}
		}
		if code == 101 {
			if !upgrade {
				s.reply(badGateway)
				return errUnsolicitedSwitch
			}
			if !httpx.UpgradeAccepted(req.Header, s.resp.Header) {
				s.reply(badGateway)
				return errUnofferedSwitch
			}
			s.resp.Header = httpx.RemoveHopByHop(s.resp.Header, true)
			s.resp.Header.Del("Content-Length")
			httpx.WriteResponseHead(s.clientW, &s.resp)
			if err = s.clientW.Flush(); err != nil {
				return E.Cause(err, "write response")
			}
			if err = s.waitBody(); err != nil {
				return err
			}
			s.clientWatch.end()
			return s.tunnel()
		}
		if http10 {
			// HTTP/1.0 clients do not understand interim responses.
			continue
		}
		if code == 100 {
			continued = true
		}
		s.resp.Header = httpx.RemoveHopByHop(s.resp.Header, false)
		// A 1xx response has no content and no Content-Length (RFC 9110 section 8.6).
		s.resp.Header.Del("Content-Length")
		httpx.WriteResponseHead(s.clientW, &s.resp)
		if err = s.clientW.Flush(); err != nil {
			return E.Cause(err, "write response")
		}
	}

	resp := &s.resp
	var responseHits []flow.RewriteHit
	var headAt time.Time
	var heldSpent bool
	var heldResp *rewrite.Held
	tunnel := method == "CONNECT" && resp.StatusCode < 300
	buffering := (plan.HasBodyRules(rewrite.ScopeResponse) || sx.WantsBody(script.PhaseResponse, true)) && !tunnel
	if buffering {
		headAt = time.Now()
	}
	if plan.HasResponseEdits() && !tunnel {
		resp.Header, responseHits = applyHeaders(plan, true, resp.Header)
	}
	if buffering {
		heldResp, heldSpent, err = s.collectResponse(plan, s.planSet, method, sx)
		if err != nil {
			s.debug("read response body: ", err)
			s.reply(badGateway)
			return E.Cause(err, "read response body")
		}
	}
	var scriptHits []flow.RewriteHit
	if sx.HasResponse() && !tunnel {
		out := sx.RunResponse(&scripthook.Message{
			Headers:  toFlowHeaders(resp.Header),
			Status:   resp.StatusCode,
			Held:     heldResp,
			Encoding: joinValues(resp.Header, "Content-Encoding"),
			HasBody:  heldResp != nil,
			Limit:    max(s.planSet.MaxBodySize(), sx.MaxBody(script.PhaseResponse)),
			Head:     method == "HEAD",
		})
		scriptHits = out.Hits
		if out.Local != nil {
			// The script dropped the connection.
			if heldResp != nil {
				responseHits = append(responseHits, heldResp.Hits...)
			}
			if s.obs != nil {
				s.obs.Rewritten(append(append(responseHits, scriptHits...), out.Local.Hit))
			}
			s.abortErr = errRewriteAbort
			return errClose
		}
		if out.HeadersChanged {
			resp.Header = fromFlowHeaders(out.Headers)
		}
		if out.Status != 0 {
			resp.StatusCode = out.Status
			resp.Reason = http.StatusText(out.Status)
		}
		if out.BodyChanged && heldResp != nil {
			heldResp.Data, heldResp.Changed = out.Body, true
		}
	}
	if heldResp != nil {
		if heldResp.Changed {
			dropDigests(&resp.Header, firstNonEmpty(heldResp.Hits, scriptHits), s.chunkedR.Trailer())
			editedLength(&resp.Header, len(heldResp.Data))
		}
		responseHits = append(responseHits, heldResp.Hits...)
	}
	responseHits = append(responseHits, scriptHits...)
	if s.obs != nil {
		now := time.Now()
		if buffering {
			now = headAt
		}
		s.obs.Mark(flow.PointFirstByte, now)
		s.obs.Mark(flow.PointResponseHeaders, now)
		if method == "CONNECT" && resp.StatusCode < 300 {
			s.obs.Upgrade(resp.StatusCode, s.flowHeaders(resp.Header))
		} else {
			s.obs.ResponseHead(resp.StatusCode, s.flowHeaders(resp.Header))
		}
		if len(responseHits) > 0 {
			s.obs.Rewritten(responseHits)
		}
	}
	responseFraming, err := httpx.ResponseFraming(method, resp)
	if err != nil {
		s.debug("malformed response: ", err)
		s.reply(badGateway)
		return E.Cause(err, "read response")
	}
	if method == "CONNECT" && resp.StatusCode < 300 {
		// A 2xx answer to CONNECT turns the connection into a tunnel right after the header
		// block (RFC 9112 section 6.3), whatever its framing fields say.
		header = httpx.RemoveHopByHop(resp.Header, false)
		header.Del("Content-Length")
		header.Del("Transfer-Encoding")
		resp.Header = header
		httpx.WriteResponseHead(s.clientW, resp)
		if err = s.clientW.Flush(); err != nil {
			return E.Cause(err, "write response")
		}
		if err = s.waitBody(); err != nil {
			return err
		}
		s.clientWatch.end()
		return s.tunnel()
	}
	if !resp.ProtoAtLeast(1, 1) || resp.Header.HasToken("Connection", "close") || responseFraming.Kind == httpx.BodyClose {
		closeAfter = true
	}
	if heldSpent {
		closeAfter = true
	}
	if http10 && responseFraming.Codings != "" {
		// An HTTP/1.0 client cannot decode transfer codings.
		s.reply(badGateway)
		return errCodingsHTTP10
	}
	transferEncoded := resp.Header.Has("Transfer-Encoding")
	header = filterAltSvc(httpx.RemoveHopByHop(resp.Header, false))
	chunkedOut := false
	switch responseFraming.Kind {
	case httpx.BodyChunked:
		header.Del("Content-Length")
		if http10 {
			// Deliver the decoded body delimited by close; its trailer fields are dropped, and
			// so is their announcement.
			header.Del("Trailer")
			closeAfter = true
		} else {
			codings := "chunked"
			if responseFraming.Codings != "" {
				codings = responseFraming.Codings + ", chunked"
			}
			header = append(header, httpx.Field{Name: "Transfer-Encoding", Value: codings})
			chunkedOut = true
		}
	case httpx.BodyLength:
		header = setContentLength(header, responseFraming.Length)
	case httpx.BodyClose:
		if responseFraming.Codings != "" {
			// Faulty or non-chunked transfer codings: the bytes are forwarded as they are,
			// still declared by their Transfer-Encoding, until the upstream closes
			// (RFC 9112 sections 6.1 and 6.3).
			header.Del("Content-Length")
			header = append(header, httpx.Field{Name: "Transfer-Encoding", Value: responseFraming.Codings})
		}
	case httpx.BodyNone:
		if httpx.ResponseHasBody(method, resp.StatusCode) {
			if header.Has("Content-Length") {
				header = setContentLength(header, 0)
			}
		} else if transferEncoded || resp.StatusCode == 204 {
			// Beside Transfer-Encoding, Content-Length is overridden (RFC 9112 section 6.3) and
			// was not validated; it leaves with the hop-by-hop Transfer-Encoding. A 204 must
			// not carry it (RFC 9110 section 8.6).
			header.Del("Content-Length")
		} else if header.Has("Content-Length") {
			// HEAD and 304: the length of the representation, validated by ResponseFraming,
			// forwarded as one canonical value.
			if length, err := httpx.ContentLength(header); err == nil {
				header = setContentLength(header, length)
			} else {
				header.Del("Content-Length")
			}
		}
	}
	if closeAfter {
		header = append(header, httpx.Field{Name: "Connection", Value: "close"})
	}
	resp.Header = header
	httpx.WriteResponseHead(s.clientW, resp)
	if responseFraming.Kind == httpx.BodyNone {
		err = s.clientW.Flush()
	} else if heldResp != nil && heldResp.Complete {
		err = s.writeHeldResponse(heldResp, responseFraming, chunkedOut)
	} else {
		if heldResp != nil {
			s.respReplay = heldResp.Replay
		}
		err = s.copyResponseBody(responseFraming, chunkedOut)
	}
	if err != nil {
		return err
	}

	if s.bodyRunning {
		if closeAfter || expectContinue && !continued {
			// The request body may never be sent; end the connection instead of waiting.
			select {
			case err = <-s.bodyDone:
				s.bodyRunning = false
			default:
				return errClose
			}
		} else {
			err = s.waitBody()
		}
		if err != nil {
			return err
		}
	}
	if closeAfter {
		return errClose
	}
	s.clientWatch.end()
	return nil
}

// filterAltSvc drops the HTTP/3 alternatives from Alt-Svc so that the client stays on the
// decrypted TCP connection; a field left empty is removed.
func filterAltSvc(header httpx.Header) httpx.Header {
	n := 0
	for i := range header {
		field := header[i]
		if strings.EqualFold(field.Name, "Alt-Svc") {
			value, changed := httpx.FilterAltSvc(field.Value)
			if changed {
				if value == "" {
					continue
				}
				field.Value = value
			}
		}
		header[n] = field
		n++
	}
	clear(header[n:])
	return header[:n]
}

// setContentLength makes header carry exactly one Content-Length field holding the framed
// length in canonical form. A header that already does is returned unchanged without allocating.
func setContentLength(header httpx.Header, length int64) httpx.Header {
	if header.Count("Content-Length") != 1 || !canonicalLength(header.Get("Content-Length")) {
		header.Set("Content-Length", strconv.FormatInt(length, 10))
	}
	return header
}

// canonicalLength reports whether a validated Content-Length value is a single decimal without
// leading zeros.
func canonicalLength(value string) bool {
	return value == "0" || value != "" && value[0] != '0' && strings.IndexByte(value, ',') < 0
}

func (s *session) waitBody() error {
	if !s.bodyRunning {
		return nil
	}
	err := <-s.bodyDone
	s.bodyRunning = false
	return err
}

// copyRequestBody runs on its own goroutine, which may outlive the exchange; it gets the
// observation handles by value.
func (s *session) copyRequestBody(obs flow.Exchange, reqBody flow.Body, replay io.Reader) {
	observe := func(r io.Reader) io.Reader {
		if reqBody == nil {
			return r
		}
		return reqBody.Reader(r)
	}
	framing := s.bodyFraming
	var err error
	switch {
	case framing.Kind == httpx.BodyLength && framing.Length <= pipeThreshold:
		if replay == nil {
			s.bodyLimited = io.LimitedReader{R: s.clientR, N: framing.Length}
			replay = &s.bodyLimited
		}
		var n int64
		n, err = io.CopyBuffer(&s.upstreamFlush, observe(replay), s.bodyBuffer)
		if err == nil && n < framing.Length {
			err = io.ErrUnexpectedEOF
		}
	case framing.Kind == httpx.BodyLength:
		var n int64
		if replay == nil {
			replay = s.clientR
		}
		n, err = s.requestPipe.copy(s.upstream, observe(replay), framing.Length, false)
		if err == nil && n < framing.Length {
			err = io.ErrUnexpectedEOF
		}
	case framing.Kind == httpx.BodyChunked:
		if replay == nil {
			s.bodyChunkedR.Reset(s.clientR)
			replay = &s.bodyChunkedR
		}
		_, err = s.requestPipe.copy(s.upstream, observe(replay), -1, true)
		if err == nil {
			if obs != nil && len(s.bodyChunkedR.Trailer()) > 0 {
				obs.Trailers(flow.Request, trailerHeaders(s.bodyChunkedR.Trailer()))
			}
			err = writeLastChunk(s.upstreamW, &s.bodyChunkedR)
		}
	}
	if reqBody != nil {
		reqBody.Done()
	}
	if err != nil {
		err = E.Cause(err, "copy request body")
		// Unblock the response read on the Serve goroutine.
		s.closeUpstream()
	} else {
		// The client is not read again until the response completed.
		s.clientWatch.begin()
	}
	s.bodyDone <- err
}

// copyResponseBody forwards the response body. A fixed-length body up to pipeThreshold is
// copied here, written together with the head; longer, chunked and close-delimited bodies go
// through the response pipe after the head was flushed, so that a streamed response shows its
// head before its first data and large bodies are written in large pieces.
func (s *session) copyResponseBody(framing httpx.Framing, chunkedOut bool) error {
	var err error
	replay := s.respReplay
	s.respReplay = nil
	if framing.Kind == httpx.BodyLength && framing.Length <= pipeThreshold {
		if replay == nil {
			s.limited = io.LimitedReader{R: s.upstreamR, N: framing.Length}
			replay = &s.limited
		}
		var n int64
		n, err = io.CopyBuffer(&s.clientFlush, s.observeResponseReader(replay), s.copyBuffer)
		if err == nil && n < framing.Length {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			err = s.clientW.Flush()
		}
	} else if err = s.clientW.Flush(); err == nil {
		switch framing.Kind {
		case httpx.BodyLength:
			var n int64
			if replay == nil {
				replay = s.upstreamR
			}
			n, err = s.responsePipe.copy(s.client, s.observeResponseReader(replay), framing.Length, false)
			if err == nil && n < framing.Length {
				err = io.ErrUnexpectedEOF
			}
		case httpx.BodyChunked:
			// Re-encoded, or decoded for an HTTP/1.0 client without its trailer section.
			if replay == nil {
				s.chunkedR.Reset(s.upstreamR)
				replay = &s.chunkedR
			}
			_, err = s.responsePipe.copy(s.client, s.observeResponseReader(replay), -1, chunkedOut)
			if err == nil && s.obs != nil && len(s.chunkedR.Trailer()) > 0 {
				s.obs.Trailers(flow.Response, trailerHeaders(s.chunkedR.Trailer()))
			}
			if err == nil && chunkedOut {
				err = writeLastChunk(s.clientW, &s.chunkedR)
			}
		default:
			if replay == nil {
				replay = s.upstreamR
			}
			_, err = s.responsePipe.copy(s.client, s.observeResponseReader(replay), -1, false)
		}
	}
	if s.respBody != nil {
		s.respBody.Done()
	}
	if err != nil {
		return E.Cause(err, "copy response body")
	}
	return nil
}

// tunnel forwards bytes in both directions after a protocol switch, starting with whatever
// either reader already buffered.
func (s *session) tunnel() error {
	if n := s.clientR.Buffered(); n > 0 {
		pending, _ := s.clientR.Peek(n)
		if _, err := s.upstream.Write(pending); err != nil {
			return E.Cause(err, "write upgraded")
		}
	}
	if n := s.upstreamR.Buffered(); n > 0 {
		pending, _ := s.upstreamR.Peek(n)
		if _, err := s.client.Write(pending); err != nil {
			return E.Cause(err, "write upgraded")
		}
	}
	err := sbufio.CopyConn(s.ctx, s.client, s.upstream)
	if err == nil || E.IsClosedOrCanceled(err) {
		return errClose
	}
	return err
}

// chunkHeaderRoom is the space reserved before the data for the hexadecimal size and CRLF.
const chunkHeaderRoom = 18

// writeLastChunk ends a chunked body with the last chunk and the permitted fields of the
// source's trailer section.
func writeLastChunk(w *bufio.Writer, source *httpx.ChunkedReader) error {
	trailer := httpx.FilterTrailer(source.Trailer())
	if len(trailer) == 0 {
		w.WriteString(lastChunk)
	} else {
		w.WriteString("0\r\n")
		httpx.WriteHeader(w, trailer)
	}
	return w.Flush()
}

const (
	hexDigits = "0123456789abcdef"
	lastChunk = "0\r\n\r\n"
)
