package h2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/mitm/httpx"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ProfileChrome selects the upstream HTTP/2 client that speaks like Chrome on
// the wire: the connection preface (SETTINGS, connection WINDOW_UPDATE), the
// pseudo-header order and the request header order of Chrome. The default
// client (net/http's) differs in all of them, which fingerprinting services
// (the Akamai HTTP/2 fingerprint) tell apart from a Chrome TLS handshake.
const ProfileChrome = "chrome"

const (
	// What Chrome announces; the stream window is its INITIAL_WINDOW_SIZE and
	// the connection window grows by chromeConnIncrement right after the
	// SETTINGS frame (65535 + 15663105 = 15 MiB).
	chromeHeaderTableSize   = 65536
	chromeStreamWindow      = 6291456
	chromeMaxHeaderList     = 262144
	chromeConnIncrement     = 15663105
	chromeCreditThreshold   = 64 << 10
	chromeDefaultFrameSize  = 16384
	chromeDefaultStreams    = 100
	chromeDefaultSendWindow = 65535
	chromeWriteChunk        = 32 << 10
	chromePriorityWeight    = 255 // wire value, weight 256
	// chromeBufferCap is the most received-but-unread data the connection keeps:
	// the reader stops reading the socket above it (TCP backpressure) until
	// consumers catch up. The windows announced to the server are Chrome's
	// (6 MiB per stream, 15 MiB per connection) and cannot be smaller; this
	// cap bounds the memory a slow client can pin behind a connection.
	chromeBufferCap = 8 << 20
)

// chromeSettings is the SETTINGS frame of Chrome, in its order.
var chromeSettings = []http2.Setting{
	{ID: http2.SettingHeaderTableSize, Val: chromeHeaderTableSize},
	{ID: http2.SettingEnablePush, Val: 0},
	{ID: http2.SettingInitialWindowSize, Val: chromeStreamWindow},
	{ID: http2.SettingMaxHeaderListSize, Val: chromeMaxHeaderList},
}

// errChromeNotUsable starts the errors of a connection that takes no request
// (the relay retries such a request on a new connection).
const errChromeNotUsable = "client conn not usable"

var (
	errChromeClosedBody  = errors.New("http2: response body closed")
	errChromeStreamDone  = errors.New("http2: stream done")
	errChromeConnClosed  = errors.New("http2: client conn is closed")
	errChromeGracefulEnd = errors.New("http2: Transport received Server's graceful shutdown GOAWAY")
)

// chromeConn is a minimal HTTP/2 client connection (frame layer from
// x/net/http2) with Chrome's wire behavior. Requests are relayed one stream
// each; the receive windows are Chrome's, so up to chromeStreamWindow bytes of
// a stream (chromeConnIncrement+65535 of the connection) may be buffered here
// while a consumer is slow.
type chromeConn struct {
	nc          net.Conn
	pingAfter   time.Duration
	pingTimeout time.Duration

	// wmu serializes frame writes and the HPACK encoder.
	wmu  sync.Mutex
	fr   *http2.Framer
	henc *hpack.Encoder
	hbuf bytes.Buffer

	// ctl holds frames the reader goroutine wants written; a dedicated
	// goroutine writes them so that the reader never blocks on the socket.
	ctlMu    sync.Mutex
	ctl      []func(*http2.Framer) error
	ctlWake  chan struct{}
	ctlLimit int
	lastRead time.Time // guarded by mu

	mu             sync.Mutex
	cond           *sync.Cond
	streams        map[uint32]*chromeStream
	nextID         uint32
	err            error // set once the connection takes no new request
	closed         bool
	sendWindow     int64
	peerInitial    int64
	peerMaxFrame   uint32
	peerMaxStreams uint32
	recvWindow     int64 // what the server may still send on the connection
	pendingConn    int64 // consumed bytes not yet returned to the server
	buffered       int64 // received bytes no consumer read yet
	paused         bool  // the reader waits for consumers
	done           chan struct{}
}

type chromeResult struct {
	resp *http.Response
	err  error
}

type chromeStream struct {
	cc  *chromeConn
	id  uint32
	req *http.Request

	// guarded by cc.mu
	sendWindow  int64
	recvWindow  int64
	pendingRecv int64
	localDone   bool
	remoteDone  bool
	finished    bool // removed from the stream table
	hasBody     bool
	gotHead     bool
	buf         [][]byte
	readErr     error
	resp        *http.Response
	trailer     http.Header
	dataLen     int64

	head     chan chromeResult
	readable chan struct{}
	stopCtx  func() bool
}

// newChromeClientConn starts the connection on nc (TLS already negotiated
// h2): it writes the preface, SETTINGS and WINDOW_UPDATE like Chrome and
// starts the reader.
func newChromeClientConn(ctx context.Context, nc net.Conn) (clientConn, error) {
	cc := &chromeConn{
		nc:             nc,
		pingAfter:      upstreamPingAfter,
		pingTimeout:    upstreamPingTimeout,
		streams:        make(map[uint32]*chromeStream),
		nextID:         1,
		sendWindow:     chromeDefaultSendWindow,
		peerInitial:    chromeDefaultSendWindow,
		peerMaxFrame:   chromeDefaultFrameSize,
		peerMaxStreams: chromeDefaultStreams,
		recvWindow:     chromeDefaultSendWindow + chromeConnIncrement,
		ctlWake:        make(chan struct{}, 1),
		ctlLimit:       chromeCtlLimit,
		done:           make(chan struct{}),
		lastRead:       time.Now(),
	}
	cc.cond = sync.NewCond(&cc.mu)
	cc.fr = http2.NewFramer(deadlineWriter{nc, chromeWriteTimeout}, bufio.NewReaderSize(nc, 64<<10))
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(chromeHeaderTableSize, nil)
	cc.fr.MaxHeaderListSize = chromeMaxHeaderList
	cc.fr.SetMaxReadFrameSize(chromeDefaultFrameSize)
	cc.henc = hpack.NewEncoder(&cc.hbuf)

	if _, err := io.WriteString(nc, http2.ClientPreface); err != nil {
		return nil, err
	}
	if err := cc.fr.WriteSettings(chromeSettings...); err != nil {
		return nil, err
	}
	if err := cc.fr.WriteWindowUpdate(0, chromeConnIncrement); err != nil {
		return nil, err
	}
	go cc.readLoop()
	go cc.controlLoop()
	go cc.keepAlive()
	return cc, nil
}

func (cc *chromeConn) Err() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.err
}

func (cc *chromeConn) Close() error {
	cc.shutdown(errChromeConnClosed)
	return nil
}

// shutdown ends the connection: every stream fails with a connection-lost
// error and the socket closes.
func (cc *chromeConn) shutdown(cause error) {
	cc.mu.Lock()
	if cc.closed {
		cc.mu.Unlock()
		return
	}
	cc.closed = true
	if cc.err == nil {
		cc.err = cause
	}
	streams := cc.streams
	cc.streams = make(map[uint32]*chromeStream)
	var failure error
	if errors.Is(cause, errChromeConnClosed) {
		failure = cause
	} else {
		failure = fmt.Errorf("http2: client connection lost: %w", cause)
	}
	for _, st := range streams {
		st.failLocked(failure)
	}
	close(cc.done)
	cc.cond.Broadcast()
	cc.mu.Unlock()
	cc.nc.Close()
}

// finishLocked marks the stream finished (cc.mu held); a request body still
// being sent is released.
func (st *chromeStream) finishLocked() {
	if st.finished {
		return
	}
	st.finished = true
	if st.stopCtx != nil {
		st.stopCtx()
	}
	if st.hasBody {
		go closeBody(st.req)
	}
}

// failLocked ends the stream with err (cc.mu held).
func (st *chromeStream) failLocked(err error) {
	if st.finished {
		return
	}
	st.finishLocked()
	st.localDone, st.remoteDone = true, true
	if !st.gotHead {
		st.gotHead = true
		st.head <- chromeResult{err: err}
	}
	if st.readErr == nil {
		st.readErr = err
	}
	st.wake()
}

// dropBufferLocked discards buffered data and returns its connection credit.
func (st *chromeStream) dropBufferLocked() {
	var n int64
	for _, chunk := range st.buf {
		n += int64(len(chunk))
	}
	st.buf = nil
	if n > 0 {
		st.cc.bufferedLocked(-n)
		st.cc.creditConnLocked(n)
	}
}

func (st *chromeStream) wake() {
	select {
	case st.readable <- struct{}{}:
	default:
	}
}

// creditConnLocked counts consumed connection bytes and queues a
// WINDOW_UPDATE once enough accumulated.
func (cc *chromeConn) creditConnLocked(n int64) {
	cc.pendingConn += n
	if cc.pendingConn >= chromeCreditThreshold && !cc.closed {
		inc := cc.pendingConn
		cc.pendingConn = 0
		cc.recvWindow += inc
		cc.queue(func(fr *http2.Framer) error { return fr.WriteWindowUpdate(0, uint32(inc)) })
	}
}

// chromeCtlLimit caps the queued control writes (PING and SETTINGS ACKs,
// WINDOW_UPDATE, RST_STREAM). A peer that floods them without reading our
// answers would otherwise grow the queue without bound.
var chromeCtlLimit = 10000

// chromeWriteTimeout bounds one socket write, so a peer that stops reading
// cannot hold the writers forever.
// chromeStallLimit bounds the wait of a request on a peer that allows no
// concurrent streams.
var chromeStallLimit = 30 * time.Second

var chromeWriteTimeout = 30 * time.Second

// deadlineWriter arms the write deadline before every write.
type deadlineWriter struct {
	nc      net.Conn
	timeout time.Duration
}

func (w deadlineWriter) Write(p []byte) (int, error) {
	w.nc.SetWriteDeadline(time.Now().Add(w.timeout))
	return w.nc.Write(p)
}

// queue hands a write to the control goroutine. It may run under cc.mu.
func (cc *chromeConn) queue(write func(*http2.Framer) error) {
	cc.ctlMu.Lock()
	if len(cc.ctl) >= cc.ctlLimit {
		cc.ctlMu.Unlock()
		go cc.shutdown(errors.New("http2: control write queue overflow"))
		return
	}
	cc.ctl = append(cc.ctl, write)
	cc.ctlMu.Unlock()
	select {
	case cc.ctlWake <- struct{}{}:
	default:
	}
}

func (cc *chromeConn) controlLoop() {
	for {
		select {
		case <-cc.done:
			return
		case <-cc.ctlWake:
		}
		for {
			cc.ctlMu.Lock()
			if len(cc.ctl) == 0 {
				cc.ctlMu.Unlock()
				break
			}
			write := cc.ctl[0]
			cc.ctl[0] = nil
			cc.ctl = cc.ctl[1:]
			cc.ctlMu.Unlock()
			cc.wmu.Lock()
			err := write(cc.fr)
			cc.wmu.Unlock()
			if err != nil {
				cc.shutdown(err)
				return
			}
		}
	}
}

// keepAlive pings a connection that went quiet and closes one that does not
// answer.
func (cc *chromeConn) keepAlive() {
	if cc.pingAfter <= 0 {
		return
	}
	timer := time.NewTimer(cc.pingAfter)
	defer timer.Stop()
	for {
		select {
		case <-cc.done:
			return
		case <-timer.C:
		}
		cc.mu.Lock()
		idle := time.Since(cc.lastRead)
		if cc.paused {
			idle = 0
		}
		cc.mu.Unlock()
		if idle < cc.pingAfter {
			timer.Reset(cc.pingAfter - idle)
			continue
		}
		sent := time.Now()
		cc.queue(func(fr *http2.Framer) error { return fr.WritePing(false, [8]byte{}) })
		select {
		case <-cc.done:
			return
		case <-time.After(cc.pingTimeout):
		}
		cc.mu.Lock()
		quiet := cc.lastRead.Before(sent) && !cc.paused
		cc.mu.Unlock()
		if quiet {
			cc.shutdown(errors.New("ping timeout"))
			return
		}
		timer.Reset(cc.pingAfter)
	}
}

// bufferedLocked accounts received data; consumers waking a paused reader.
func (cc *chromeConn) bufferedLocked(delta int64) {
	cc.buffered += delta
	if delta < 0 && cc.paused && cc.buffered < chromeBufferCap {
		cc.cond.Broadcast()
	}
}

// waitBuffer blocks the reader while too much unread data is buffered.
func (cc *chromeConn) waitBuffer() {
	cc.mu.Lock()
	for cc.buffered >= chromeBufferCap && !cc.closed {
		cc.paused = true
		cc.cond.Wait()
	}
	if cc.paused {
		cc.paused = false
		cc.lastRead = time.Now()
	}
	cc.mu.Unlock()
}

func (cc *chromeConn) readLoop() {
	for {
		cc.waitBuffer()
		frame, err := cc.fr.ReadFrame()
		if err != nil {
			var streamErr http2.StreamError
			if errors.As(err, &streamErr) {
				cc.resetStream(streamErr.StreamID, streamErr.Code, streamErr)
				continue
			}
			cc.shutdown(err)
			return
		}
		cc.mu.Lock()
		cc.lastRead = time.Now()
		cc.mu.Unlock()
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			err = cc.onSettings(f)
		case *http2.MetaHeadersFrame:
			err = cc.onHeaders(f)
		case *http2.DataFrame:
			err = cc.onData(f)
		case *http2.WindowUpdateFrame:
			cc.onWindowUpdate(f)
		case *http2.RSTStreamFrame:
			cc.onReset(f)
		case *http2.GoAwayFrame:
			cc.onGoAway(f)
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				cc.queue(func(fr *http2.Framer) error { return fr.WritePing(true, data) })
			}
		case *http2.PushPromiseFrame:
			err = errors.New("unexpected PUSH_PROMISE")
		}
		if err != nil {
			cc.shutdown(err)
			return
		}
	}
}

// resetStream fails one stream and tells the server.
func (cc *chromeConn) resetStream(id uint32, code http2.ErrCode, cause error) {
	cc.mu.Lock()
	st := cc.streams[id]
	if st != nil {
		cc.removeLocked(st)
		st.failLocked(cause)
	}
	cc.mu.Unlock()
	cc.queue(func(fr *http2.Framer) error { return fr.WriteRSTStream(id, code) })
}

func (cc *chromeConn) removeLocked(st *chromeStream) {
	if cc.streams[st.id] == st {
		delete(cc.streams, st.id)
		cc.cond.Broadcast()
		if cc.err != nil && len(cc.streams) == 0 && !cc.closed {
			// A connection that got GOAWAY ends with its last stream.
			go cc.shutdown(cc.err)
		}
	}
}

func (cc *chromeConn) onSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	var table *uint32
	cc.mu.Lock()
	err := f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingHeaderTableSize:
			v := s.Val
			table = &v
		case http2.SettingMaxConcurrentStreams:
			cc.peerMaxStreams = s.Val
		case http2.SettingMaxFrameSize:
			if s.Val < chromeDefaultFrameSize || s.Val > 1<<24-1 {
				return errors.New("invalid SETTINGS_MAX_FRAME_SIZE")
			}
			cc.peerMaxFrame = s.Val
		case http2.SettingInitialWindowSize:
			if s.Val > 1<<31-1 {
				return errors.New("invalid SETTINGS_INITIAL_WINDOW_SIZE")
			}
			delta := int64(s.Val) - cc.peerInitial
			cc.peerInitial = int64(s.Val)
			for _, st := range cc.streams {
				st.sendWindow += delta
			}
		}
		return nil
	})
	cc.cond.Broadcast()
	cc.mu.Unlock()
	if err != nil {
		return err
	}
	cc.queue(func(fr *http2.Framer) error {
		if table != nil {
			size := *table
			if size > chromeHeaderTableSize {
				size = chromeHeaderTableSize
			}
			cc.henc.SetMaxDynamicTableSize(size)
		}
		return fr.WriteSettingsAck()
	})
	return nil
}

func (cc *chromeConn) onWindowUpdate(f *http2.WindowUpdateFrame) {
	cc.mu.Lock()
	if f.StreamID == 0 {
		cc.sendWindow += int64(f.Increment)
	} else if st := cc.streams[f.StreamID]; st != nil {
		st.sendWindow += int64(f.Increment)
	}
	cc.cond.Broadcast()
	cc.mu.Unlock()
}

func (cc *chromeConn) onReset(f *http2.RSTStreamFrame) {
	cc.mu.Lock()
	if st := cc.streams[f.StreamID]; st != nil {
		cc.removeLocked(st)
		st.failLocked(http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode})
	}
	cc.mu.Unlock()
}

func (cc *chromeConn) onGoAway(f *http2.GoAwayFrame) {
	cc.mu.Lock()
	if cc.err == nil {
		cc.err = fmt.Errorf("%s: server sent GOAWAY (%v)", errChromeNotUsable, f.ErrCode)
	}
	var cause error = errChromeGracefulEnd
	if f.ErrCode != http2.ErrCodeNo {
		cause = fmt.Errorf("%s: server sent GOAWAY and closed the connection (%v)", errChromeNotUsable, f.ErrCode)
	}
	for id, st := range cc.streams {
		if id > f.LastStreamID {
			cc.removeLocked(st)
			st.failLocked(cause)
		}
	}
	idle := len(cc.streams) == 0
	cc.cond.Broadcast()
	cc.mu.Unlock()
	if idle {
		cc.shutdown(cc.Err())
	}
}

// errChromeLength reports a response body that disagrees with its
// Content-Length.
var errChromeLength = errors.New("http2: response body length differs from Content-Length")

// lengthBad reports whether got body bytes contradict the declared length. A
// short body is only a mismatch once the stream has ended.
func lengthBad(req *http.Request, resp *http.Response, got int64, ended bool) bool {
	if resp == nil || resp.ContentLength < 0 {
		return false
	}
	if req.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return false
	}
	return got > resp.ContentLength || (ended && got != resp.ContentLength)
}

// failLengthLocked resets a stream whose body length is wrong.
func (cc *chromeConn) failLengthLocked(st *chromeStream) {
	cc.removeLocked(st)
	st.failLocked(errChromeLength)
	id := st.id
	cc.queue(func(fr *http2.Framer) error { return fr.WriteRSTStream(id, http2.ErrCodeProtocol) })
}

// streamEndedLocked handles the end of a stream's response.
func (cc *chromeConn) streamEndedLocked(st *chromeStream) {
	st.remoteDone = true
	if st.readErr == nil {
		st.readErr = io.EOF
	}
	st.wake()
	local := st.localDone
	st.finishLocked()
	cc.removeLocked(st)
	if !local {
		// The server answered before the request body ended: stop sending it.
		id := st.id
		cc.queue(func(fr *http2.Framer) error { return fr.WriteRSTStream(id, http2.ErrCodeNo) })
	}
}

func (cc *chromeConn) onHeaders(f *http2.MetaHeadersFrame) error {
	cc.mu.Lock()
	st := cc.streams[f.StreamID]
	cc.mu.Unlock()
	if st == nil {
		return nil
	}
	if f.Truncated {
		cc.resetStream(f.StreamID, http2.ErrCodeProtocol, errors.New("http2: response headers too large"))
		return nil
	}
	cc.mu.Lock()
	gotHead := st.gotHead
	cc.mu.Unlock()
	if gotHead {
		// Trailers.
		if !f.StreamEnded() {
			cc.resetStream(f.StreamID, http2.ErrCodeProtocol, errors.New("http2: trailers without END_STREAM"))
			return nil
		}
		trailer := make(http.Header)
		for _, field := range f.RegularFields() {
			if !httpx.TrailerAllowed(field.Name) {
				continue
			}
			key := textproto.CanonicalMIMEHeaderKey(field.Name)
			trailer[key] = append(trailer[key], field.Value)
		}
		cc.mu.Lock()
		if !st.finished && lengthBad(st.req, st.resp, st.dataLen, true) {
			cc.failLengthLocked(st)
		} else if !st.finished {
			st.trailer = trailer
			if st.resp != nil && len(trailer) > 0 {
				st.resp.Trailer = trailer
			}
			cc.streamEndedLocked(st)
		}
		cc.mu.Unlock()
		return nil
	}
	status := f.PseudoValue("status")
	code, err := strconv.Atoi(status)
	if err != nil || code < 100 || code > 999 {
		cc.resetStream(f.StreamID, http2.ErrCodeProtocol, fmt.Errorf("http2: invalid :status %q", status))
		return nil
	}
	header := make(http.Header)
	for _, field := range f.RegularFields() {
		key := textproto.CanonicalMIMEHeaderKey(field.Name)
		if hopByHop(key) {
			continue
		}
		header[key] = append(header[key], field.Value)
	}
	if code == http.StatusSwitchingProtocols {
		// RFC 9113 section 8.6: HTTP/2 has no protocol switch.
		cc.resetStream(f.StreamID, http2.ErrCodeProtocol, errors.New("http2: unexpected 101 Switching Protocols"))
		return nil
	}
	if code >= 100 && code <= 199 {
		if trace := httptrace.ContextClientTrace(st.req.Context()); trace != nil && trace.Got1xxResponse != nil {
			if err := trace.Got1xxResponse(code, textproto.MIMEHeader(header)); err != nil {
				cc.resetStream(f.StreamID, http2.ErrCodeCancel, err)
			}
		}
		return nil
	}
	resp := &http.Response{
		Status:        status + " " + http.StatusText(code),
		StatusCode:    code,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		Header:        header,
		ContentLength: -1,
		Request:       st.req,
	}
	if length := header.Get("Content-Length"); length != "" {
		if n, err := strconv.ParseInt(length, 10, 64); err == nil && n >= 0 {
			resp.ContentLength = n
		}
	}
	cc.mu.Lock()
	if st.finished {
		cc.mu.Unlock()
		return nil
	}
	if f.StreamEnded() && lengthBad(st.req, resp, 0, true) {
		cc.failLengthLocked(st)
		cc.mu.Unlock()
		return nil
	}
	st.gotHead = true
	st.resp = resp
	if f.StreamEnded() {
		resp.Body = http.NoBody
		cc.streamEndedLocked(st)
	} else {
		resp.Body = &chromeBody{st: st}
	}
	st.head <- chromeResult{resp: resp}
	cc.mu.Unlock()
	return nil
}

func (cc *chromeConn) onData(f *http2.DataFrame) error {
	length := int64(f.Length)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.recvWindow -= length
	if cc.recvWindow < 0 {
		return errors.New("flow control: server exceeded the connection window")
	}
	st := cc.streams[f.StreamID]
	data := f.Data()
	if st == nil || st.finished || st.remoteDone {
		cc.creditConnLocked(length)
		return nil
	}
	if !st.gotHead {
		cc.mu.Unlock()
		cc.resetStream(f.StreamID, http2.ErrCodeProtocol, errors.New("http2: DATA before response headers"))
		cc.mu.Lock()
		cc.creditConnLocked(length)
		return nil
	}
	st.recvWindow -= length
	if st.recvWindow < 0 {
		cc.removeLocked(st)
		st.failLocked(http2.StreamError{StreamID: st.id, Code: http2.ErrCodeFlowControl})
		cc.creditConnLocked(length)
		id := st.id
		cc.queue(func(fr *http2.Framer) error { return fr.WriteRSTStream(id, http2.ErrCodeFlowControl) })
		return nil
	}
	st.dataLen += int64(len(data))
	if lengthBad(st.req, st.resp, st.dataLen, f.StreamEnded()) {
		cc.creditConnLocked(length)
		cc.failLengthLocked(st)
		return nil
	}
	if padding := length - int64(len(data)); padding > 0 {
		cc.creditConnLocked(padding)
		st.pendingRecv += padding
	}
	if len(data) > 0 {
		st.buf = append(st.buf, append([]byte(nil), data...))
		cc.bufferedLocked(int64(len(data)))
		st.wake()
	}
	if f.StreamEnded() {
		cc.streamEndedLocked(st)
	} else {
		cc.creditStreamLocked(st)
	}
	return nil
}

// creditStreamLocked queues a stream WINDOW_UPDATE once enough was consumed.
func (cc *chromeConn) creditStreamLocked(st *chromeStream) {
	if st.pendingRecv < chromeCreditThreshold || st.finished || st.remoteDone {
		return
	}
	inc := st.pendingRecv
	st.pendingRecv = 0
	st.recvWindow += inc
	id := st.id
	cc.queue(func(fr *http2.Framer) error { return fr.WriteWindowUpdate(id, uint32(inc)) })
}

// chromeBody is a response body.
type chromeBody struct {
	st *chromeStream
}

func (b *chromeBody) Read(p []byte) (int, error) {
	st := b.st
	cc := st.cc
	if len(p) == 0 {
		return 0, nil
	}
	for {
		cc.mu.Lock()
		if len(st.buf) > 0 {
			n := copy(p, st.buf[0])
			st.buf[0] = st.buf[0][n:]
			if len(st.buf[0]) == 0 {
				st.buf[0] = nil
				st.buf = st.buf[1:]
			}
			cc.bufferedLocked(-int64(n))
			st.pendingRecv += int64(n)
			cc.creditStreamLocked(st)
			cc.creditConnLocked(int64(n))
			if len(st.buf) > 0 {
				st.wake()
			}
			cc.mu.Unlock()
			return n, nil
		}
		err := st.readErr
		cc.mu.Unlock()
		if err != nil {
			return 0, err
		}
		select {
		case <-st.readable:
		case <-cc.done:
		}
	}
}

func (b *chromeBody) Close() error {
	st := b.st
	cc := st.cc
	cc.mu.Lock()
	finished := st.finished
	ended := st.remoteDone
	st.dropBufferLocked()
	st.readErr = errChromeClosedBody
	st.wake()
	cc.mu.Unlock()
	if !finished && !ended {
		st.cancel(errChromeClosedBody)
	}
	return nil
}

// cancel ends the stream locally and resets it.
func (st *chromeStream) cancel(cause error) {
	cc := st.cc
	cc.mu.Lock()
	if st.finished {
		cc.mu.Unlock()
		return
	}
	cc.removeLocked(st)
	st.failLocked(cause)
	st.dropBufferLocked()
	cc.mu.Unlock()
	id := st.id
	cc.queue(func(fr *http2.Framer) error { return fr.WriteRSTStream(id, http2.ErrCodeCancel) })
}

// RoundTrip sends req on a new stream and returns the response head.
func (cc *chromeConn) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	fields, err := chromeRequestFields(req)
	if err != nil {
		closeBody(req)
		return nil, err
	}
	// The relay sets ContentLength 0 for a request the client ended with its
	// headers; net/http would send an empty DATA frame for the body it still
	// carries, Chrome ends the stream on the HEADERS frame.
	hasBody := req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
	st := &chromeStream{
		cc:       cc,
		req:      req,
		head:     make(chan chromeResult, 1),
		readable: make(chan struct{}, 1),
	}
	st.hasBody = hasBody
	stopWake := context.AfterFunc(ctx, func() {
		cc.mu.Lock()
		cc.cond.Broadcast()
		cc.mu.Unlock()
	})
	var maxFrame uint32
	waitStart := time.Now()
	stopStall := time.AfterFunc(chromeStallLimit, func() {
		cc.mu.Lock()
		cc.cond.Broadcast()
		cc.mu.Unlock()
	})
	defer stopStall.Stop()
	for {
		cc.mu.Lock()
		stalled := false
		for !cc.closed && cc.err == nil && uint32(len(cc.streams)) >= cc.peerMaxStreams && ctx.Err() == nil {
			// A peer that allows no stream at all never frees a slot.
			if cc.peerMaxStreams == 0 && time.Since(waitStart) >= chromeStallLimit {
				stalled = true
				break
			}
			cc.cond.Wait()
		}
		if stalled {
			cc.mu.Unlock()
			stopWake()
			closeBody(req)
			return nil, fmt.Errorf("%s: peer allows no concurrent streams", errChromeNotUsable)
		}
		if ctx.Err() != nil || cc.closed || cc.err != nil || cc.nextID > 1<<31-1 {
			cause := cc.err
			cc.mu.Unlock()
			stopWake()
			closeBody(req)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if cause == nil {
				cause = errors.New("stream ids exhausted")
			}
			return nil, fmt.Errorf("%s: %w", errChromeNotUsable, cause)
		}
		cc.mu.Unlock()
		// Stream ids must reach the wire in order: take the write lock, then
		// the id.
		cc.wmu.Lock()
		cc.mu.Lock()
		if uint32(len(cc.streams)) < cc.peerMaxStreams && !cc.closed && cc.err == nil {
			break
		}
		cc.mu.Unlock()
		cc.wmu.Unlock()
	}
	stopWake()
	st.id = cc.nextID
	cc.nextID += 2
	st.sendWindow = cc.peerInitial
	st.recvWindow = chromeStreamWindow
	st.localDone = !hasBody
	cc.streams[st.id] = st
	maxFrame = cc.peerMaxFrame
	cc.mu.Unlock()
	err = cc.writeHeadersLocked(st.id, fields, !hasBody, true, maxFrame)
	cc.wmu.Unlock()
	if err != nil {
		cc.shutdown(err)
		closeBody(req)
		return nil, fmt.Errorf("http2: client connection lost: %w", err)
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}
	if hasBody {
		go st.writeBody()
	} else if req.Body != nil {
		closeBody(req)
	}
	if !hasBody && trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	cc.mu.Lock()
	if !st.finished {
		st.stopCtx = context.AfterFunc(ctx, func() { st.cancel(ctx.Err()) })
	}
	cc.mu.Unlock()
	select {
	case result := <-st.head:
		return result.resp, result.err
	case <-ctx.Done():
		st.cancel(ctx.Err())
		return nil, ctx.Err()
	}
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

// writeHeadersLocked encodes and writes a header block (cc.wmu held).
func (cc *chromeConn) writeHeadersLocked(id uint32, fields []hpack.HeaderField, endStream bool, priority bool, maxFrame uint32) error {
	cc.hbuf.Reset()
	for _, field := range fields {
		if err := cc.henc.WriteField(field); err != nil {
			return err
		}
	}
	block := cc.hbuf.Bytes()
	first := true
	for {
		chunk := block
		if uint32(len(chunk)) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		block = block[len(chunk):]
		end := len(block) == 0
		var err error
		if first {
			param := http2.HeadersFrameParam{StreamID: id, BlockFragment: chunk, EndStream: endStream, EndHeaders: end}
			if priority {
				// Chrome's request HEADERS frames carry a priority: exclusive, weight
				// 256 on stream 0. It sends other weights and dependencies for lower
				// priority resources, which a relay cannot know.
				param.Priority = http2.PriorityParam{Exclusive: true, Weight: chromePriorityWeight}
			}
			err = cc.fr.WriteHeaders(param)
			first = false
		} else {
			err = cc.fr.WriteContinuation(id, end, chunk)
		}
		if err != nil {
			return err
		}
		if end {
			return nil
		}
	}
}

// writeBody streams the request body (and trailers) on the stream.
func (st *chromeStream) writeBody() {
	cc := st.cc
	req := st.req
	defer req.Body.Close()
	buf := make([]byte, chromeWriteChunk)
	for {
		n, err := req.Body.Read(buf)
		if n > 0 {
			if sendErr := st.sendData(buf[:n]); sendErr != nil {
				return
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			st.cancel(err)
			return
		}
	}
	var fields []hpack.HeaderField
	if keys := allowedTrailerKeys(req.Trailer); len(keys) > 0 {
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range req.Trailer[k] {
				fields = append(fields, hpack.HeaderField{Name: strings.ToLower(k), Value: v})
			}
		}
	}
	cc.mu.Lock()
	if st.finished || st.localDone {
		cc.mu.Unlock()
		return
	}
	st.localDone = true
	maxFrame := cc.peerMaxFrame
	cc.mu.Unlock()
	cc.wmu.Lock()
	var err error
	if len(fields) > 0 {
		err = cc.writeHeadersLocked(st.id, fields, true, false, maxFrame)
	} else {
		err = cc.fr.WriteData(st.id, true, nil)
	}
	cc.wmu.Unlock()
	if err != nil {
		cc.shutdown(err)
		return
	}
	cc.mu.Lock()
	if st.remoteDone && !st.finished {
		st.finished = true
		cc.removeLocked(st)
	}
	cc.mu.Unlock()
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
}

// sendData writes p as DATA frames within the flow-control windows.
func (st *chromeStream) sendData(p []byte) error {
	cc := st.cc
	ctx := st.req.Context()
	for len(p) > 0 {
		cc.mu.Lock()
		stop := context.AfterFunc(ctx, func() {
			cc.mu.Lock()
			cc.cond.Broadcast()
			cc.mu.Unlock()
		})
		for !st.finished && !cc.closed && ctx.Err() == nil && (st.sendWindow <= 0 || cc.sendWindow <= 0) {
			cc.cond.Wait()
		}
		stop()
		if st.finished || cc.closed || ctx.Err() != nil {
			cc.mu.Unlock()
			return errChromeStreamDone
		}
		n := int64(len(p))
		if n > st.sendWindow {
			n = st.sendWindow
		}
		if n > cc.sendWindow {
			n = cc.sendWindow
		}
		if n > int64(cc.peerMaxFrame) {
			n = int64(cc.peerMaxFrame)
		}
		st.sendWindow -= n
		cc.sendWindow -= n
		cc.mu.Unlock()
		cc.wmu.Lock()
		err := cc.fr.WriteData(st.id, false, p[:n])
		cc.wmu.Unlock()
		if err != nil {
			cc.shutdown(err)
			return err
		}
		p = p[n:]
	}
	return nil
}
