package h2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/httpx"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/common/mitm/scripthook"
	"github.com/sagernet/sing-box/script"
	E "github.com/sagernet/sing/common/exceptions"
)

// goneGrace is a variable so tests can widen it.
var goneGrace = 300 * time.Millisecond

var errUpstreamGone = E.New("upstream h2 connection is gone")

// ServeHTTP relays one client stream. Panics end the stream, not the process.
func (s *session) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Registering under the mutex orders it against shutdown: Serve's wg.Wait
	// only starts after shut is set, so a handler that gets here later leaves
	// without touching the callbacks.
	s.mu.Lock()
	if s.shut {
		s.mu.Unlock()
		reply(w, http.StatusServiceUnavailable)
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	s.active.Add(1)
	g := &hookGuard{}
	defer func() {
		rec := recover()
		g.finish()
		if s.active.Add(-1) == 0 && s.gone.Load() {
			// Nothing is left to serve on a connection whose upstream is lost.
			// The grace period lets the last reply (the 502) reach the client.
			time.AfterFunc(goneGrace, func() {
				if s.active.Load() == 0 && s.gone.Load() {
					s.debug("h2 closing the client connection: upstream lost")
					s.client.Close()
				}
			})
		}
		s.wg.Done()
		if rec != nil {
			if rec != http.ErrAbortHandler {
				s.debug("h2 handler panic: ", rec)
			}
			panic(http.ErrAbortHandler)
		}
	}()
	s.relay(w, r, g)
}

func (s *session) relay(w http.ResponseWriter, r *http.Request, g *hookGuard) {
	authority := r.Host
	if authority == "" {
		reply(w, http.StatusBadRequest)
		return
	}
	if !sameHost(authority, s.opts.ServerName) {
		reply(w, http.StatusMisdirectedRequest)
		return
	}
	if r.Method == http.MethodConnect {
		reply(w, http.StatusMethodNotAllowed)
		return
	}
	target, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		reply(w, http.StatusBadRequest)
		return
	}
	target.Scheme = "https"
	target.Host = authority

	clientAuthority := authority
	plan, set := s.rewritePlan(r)
	var requestHits []flow.RewriteHit
	var external *rewrite.Internal
	if in := plan.Internal(); in != nil {
		// Internal rewrite: another origin and path, invisible to the client; the rules of the
		// new URL (never the URL rules again) decide the rest.
		if !in.SameOrigin("https", hostOnly(authority), authorityPort(authority, 443)) {
			external = in
			r.Header = withoutCredentials(r.Header)
		}
		newTarget, err := url.ParseRequestURI(in.Target)
		if err != nil {
			reply(w, http.StatusBadGateway)
			return
		}
		authority = in.Authority
		target = newTarget
		target.Scheme = in.Scheme
		target.Host = authority
		r.Host = authority
		r.RequestURI = in.Target
		plan = set.PlanAfterInternal(in)
		requestHits = append(requestHits, in.Hit)
	}
	header := r.Header
	if plan.HasRequestEdits() {
		var hits []flow.RewriteHit
		header, hits = applyHeader(plan, false, header)
		requestHits = append(requestHits, hits...)
	}
	var sx *scripthook.Exchange
	if plan.Local() == nil && s.opts.Scripts != nil {
		sx = scripthook.Begin(r.Context(), s.opts.Scripts, s.rewriteSet(), "https", authority, r.RequestURI, r.Method)
	}
	// Buffering for body rules happens before the stream is observed: the recorded head
	// carries the corrected length.
	var reserved int64
	defer rewrite.ReleaseHold(&reserved)
	var requestStart time.Time
	hasBody := r.Body != nil && r.Body != http.NoBody
	if plan.HasBodyRules(rewrite.ScopeRequest) || sx.WantsBody(script.PhaseRequest, hasBody) {
		requestStart = time.Now()
	}
	var requestSource io.Reader = r.Body
	contentLength := r.ContentLength
	var held *rewrite.Held
	if hasBody && (plan.HasBodyRules(rewrite.ScopeRequest) || sx.WantsBody(script.PhaseRequest, true)) {
		contentType := header.Get("Content-Type")
		var err error
		held, err = plan.HoldFor(rewrite.ScopeRequest, contentType, strings.Join(header.Values("Content-Encoding"), ", "), r.Body,
			r.ContentLength, rewrite.StreamingMessage(rewrite.ScopeRequest, r.Method, 0, contentType, false),
			max(set.MaxBodySize(), sx.MaxBody(script.PhaseRequest)), set.MaxBodySize(), &reserved, nil, sx.WantsBody(script.PhaseRequest, true))
		if err != nil {
			s.debug("h2 request body: ", err)
			reply(w, http.StatusBadRequest)
			return
		}
		if held != nil {
			if held.Changed {
				header = cloneHeader(header)
				dropDigests(header, held.Hits)
				header.Set("Content-Length", strconv.Itoa(len(held.Data)))
				contentLength = int64(len(held.Data))
			}
			if held.Complete {
				requestSource = bytes.NewReader(held.Data)
			} else if held.Replay != nil {
				requestSource = held.Replay
			}
			requestHits = append(requestHits, held.Hits...)
		}
	}
	var scriptLocal *rewrite.LocalResponse
	if sx.HasResponse() {
		sx.SetRequestHeaders(scriptHeaders(header))
	}
	if sx.HasRequest() {
		out := sx.RunRequest(&scripthook.Message{
			Headers:  scriptHeaders(header),
			Held:     held,
			Encoding: strings.Join(header.Values("Content-Encoding"), ", "),
			HasBody:  held != nil,
			Limit:    max(set.MaxBodySize(), sx.MaxBody(script.PhaseRequest)),
		}, r.RequestURI)
		if out.HeadersChanged {
			header = headerFromFlow(out.Headers)
		}
		if out.Internal != nil {
			in := out.Internal
			newTarget, err := url.ParseRequestURI(in.Target)
			if err != nil {
				reply(w, http.StatusBadGateway)
				return
			}
			authority = in.Authority
			target = newTarget
			target.Scheme = in.Scheme
			target.Host = authority
			r.Host = authority
			r.RequestURI = in.Target
			external = nil
			if !in.SameOrigin("https", hostOnly(clientAuthority), authorityPort(clientAuthority, 443)) {
				external = in
				header = withoutCredentials(header)
			}
		}
		if out.BodyChanged && held != nil {
			header = cloneHeader(header)
			dropDigests(header, out.Hits)
			header.Set("Content-Length", strconv.Itoa(len(out.Body)))
			contentLength = int64(len(out.Body))
			requestSource = bytes.NewReader(out.Body)
		}
		requestHits = append(requestHits, out.Hits...)
		scriptLocal = out.Local
	}
	var ob *observed
	var failure error
	if s.opts.Observer != nil {
		ob = s.observe(r, header, target.Scheme)
		if !requestStart.IsZero() {
			ob.ex.Mark(flow.PointStart, requestStart)
		}
		defer func() {
			ob.finish(failure)
		}()
		ob.rewritten(requestHits)
	}
	if local := plan.Local(); local != nil {
		s.serveLocal(w, r, local, ob, &failure)
		return
	}
	if scriptLocal != nil {
		s.serveLocal(w, r, scriptLocal, ob, &failure)
		return
	}
	body := newRequestBody(r, requestSource, ob)
	build := func() *http.Request {
		out := (&http.Request{
			Method:        r.Method,
			URL:           target,
			Host:          authority,
			Header:        requestHeader(header),
			Body:          http.NoBody,
			ContentLength: contentLength,
		}).WithContext(r.Context())
		if body != nil {
			out.Body = body.attempt()
			if len(r.Trailer) > 0 {
				out.Trailer = r.Trailer
			}
		} else {
			out.ContentLength = 0
		}
		return out
	}

	if s.opts.OnRequest != nil {
		s.opts.OnRequest()
	}

	if external != nil {
		failure = s.relayInternal(w, r, g, external, build, ob, plan, set, sx, &reserved, header.Get("Range") != "")
		return
	}
	var stale *upConn
	for attempt := 0; ; attempt++ {
		u, err := s.acquire(stale)
		if err != nil {
			s.debug("h2 no upstream: ", err)
			failure = err
			reply(w, http.StatusBadGateway)
			return
		}
		out := build()
		out = out.WithContext(s.traceContext(out.Context(), w, g, ob))
		resp, err := u.cc.RoundTrip(out)
		if err != nil {
			s.release(u)
			// Stop the attempt's body first, so that what was consumed is final.
			out.Body.Close()
			if r.Context().Err() != nil {
				failure = r.Context().Err()
				return
			}
			if unusable(err) {
				s.markBad(u)
			}
			if attempt == 0 && s.opts.Redial != nil && retryable(err, r.Method, body) {
				s.debug("h2 retrying on a new upstream connection: ", err)
				stale = u
				continue
			}
			failure = err
			if unusable(err) && s.opts.Redial == nil {
				s.gone.Store(true)
			}
			s.debug("h2 upstream request failed: ", err)
			reply(w, http.StatusBadGateway)
			return
		}
		func() {
			defer s.release(u)
			rewrite.ReleaseHold(&reserved)
			failure = s.respond(w, r, resp, ob, plan, set, sx, header.Get("Range") != "")
		}()
		if ob != nil && failure == nil {
			if trailer, ok := body.finished(r); ok {
				ob.trailers(flow.Request, trailer)
			}
		}
		return
	}
}

// respond relays the upstream response; it closes resp.Body. It returns why
// the response did not reach the client completely, nil on success.
func (s *session) respond(w http.ResponseWriter, r *http.Request, resp *http.Response, ob *observed, plan *rewrite.Plan, set *rewrite.Set, sx *scripthook.Exchange, ranged bool) error {
	defer resp.Body.Close()
	h := w.Header()
	header := resp.Header
	var responseHits []flow.RewriteHit
	if plan.HasResponseEdits() {
		header, responseHits = applyHeader(plan, true, header)
	}
	headAt := time.Now()
	var reserved int64
	defer rewrite.ReleaseHold(&reserved)
	var bodySource io.Reader = resp.Body
	var heldData []byte
	holdComplete := false
	status := resp.StatusCode
	hasBody := resp.Body != http.NoBody && resp.ContentLength != 0
	var held *rewrite.Held
	if hasBody && (plan.HasBodyRules(rewrite.ScopeResponse) || sx.WantsBody(script.PhaseResponse, true)) {
		contentType := header.Get("Content-Type")
		var err error
		held, err = plan.HoldFor(rewrite.ScopeResponse, contentType, strings.Join(header.Values("Content-Encoding"), ", "), resp.Body,
			resp.ContentLength, rewrite.StreamingMessage(rewrite.ScopeResponse, r.Method, resp.StatusCode, contentType, ranged),
			max(set.MaxBodySize(), sx.MaxBody(script.PhaseResponse)), set.MaxBodySize(), &reserved, nil, sx.WantsBody(script.PhaseResponse, true))
		if err != nil {
			if r.Context().Err() != nil {
				return r.Context().Err()
			}
			s.debug("h2 upstream body failed: ", err)
			ob.finish(err)
			panic(http.ErrAbortHandler)
		}
	}
	var scriptHits []flow.RewriteHit
	if sx.HasResponse() {
		out := sx.RunResponse(&scripthook.Message{
			Headers:  scriptHeaders(header),
			Status:   status,
			Held:     held,
			Encoding: strings.Join(header.Values("Content-Encoding"), ", "),
			HasBody:  held != nil,
			Limit:    max(set.MaxBodySize(), sx.MaxBody(script.PhaseResponse)),
			Head:     r.Method == http.MethodHead,
		})
		scriptHits = out.Hits
		if out.Local != nil {
			// The script reset the stream.
			if held != nil {
				responseHits = append(responseHits, held.Hits...)
			}
			ob.rewritten(append(append(responseHits, scriptHits...), out.Local.Hit))
			ob.finish(errRewriteAbort)
			panic(http.ErrAbortHandler)
		}
		if out.HeadersChanged {
			header = headerFromFlow(out.Headers)
		}
		if out.Status != 0 {
			status = out.Status
		}
		if out.BodyChanged && held != nil {
			held.Data, held.Changed = out.Body, true
		}
	}
	if held != nil {
		if held.Changed {
			header = cloneHeader(header)
			if len(held.Hits) > 0 {
				dropDigests(header, held.Hits)
			} else {
				dropDigests(header, scriptHits)
			}
			header.Set("Content-Length", strconv.Itoa(len(held.Data)))
		}
		if held.Complete {
			heldData, holdComplete = held.Data, true
		} else if held.Replay != nil {
			bodySource = held.Replay
		}
		responseHits = append(responseHits, held.Hits...)
	}
	responseHits = append(responseHits, scriptHits...)
	copyResponseHeader(h, header)
	// The server fills these in when absent; the relay must not invent them.
	if _, ok := h["Date"]; !ok {
		h["Date"] = nil
	}
	if _, ok := h["Content-Type"]; !ok {
		h["Content-Type"] = nil
	}
	ob.markAt(flow.PointFirstByte, headAt)
	ob.markAt(flow.PointResponseHeaders, headAt)
	ob.responseHead(status, header)
	ob.rewritten(responseHits)
	w.WriteHeader(status)

	rc := http.NewResponseController(w)
	// A response known to be empty keeps its headers back so that they travel
	// in one HEADERS frame with END_STREAM (gRPC trailers-only replies).
	empty := resp.Body == http.NoBody || resp.ContentLength == 0
	if !empty {
		if err := rc.Flush(); err != nil {
			return err
		}
	}
	bufp := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufp)
	buf := *bufp
	var source io.Reader = bodySource
	if holdComplete {
		source = bytes.NewReader(heldData)
		empty = len(heldData) == 0
	}
	if ob != nil {
		source = ob.resp.Reader(source)
	}
	for !empty {
		n, err := source.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if werr := rc.Flush(); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			if r.Context().Err() != nil {
				return r.Context().Err()
			}
			s.debug("h2 upstream body failed: ", err)
			ob.finish(err)
			panic(http.ErrAbortHandler)
		}
	}
	ob.trailers(flow.Response, resp.Trailer)
	for k, vv := range resp.Trailer {
		if hopByHop(k) || !httpx.TrailerAllowed(k) {
			continue
		}
		h[http.TrailerPrefix+k] = vv
	}
	return nil
}

// traceContext relays 1xx responses (103 Early Hints) to the client.
func (s *session) traceContext(ctx context.Context, w http.ResponseWriter, g *hookGuard, ob *observed) context.Context {
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) (err error) {
			if code == http.StatusSwitchingProtocols {
				return nil
			}
			// This runs on the transport's goroutine, possibly after the handler
			// returned: the writer is off limits by then.
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.done {
				return nil
			}
			ob.informational(code, http.Header(header))
			defer func() {
				if recover() != nil {
					err = nil
				}
			}()
			h := w.Header()
			saved := h.Clone()
			for k := range h {
				delete(h, k)
			}
			copyResponseHeader(h, http.Header(header))
			w.WriteHeader(code)
			for k := range h {
				delete(h, k)
			}
			for k, vv := range saved {
				h[k] = vv
			}
			return nil
		},
	}
	if ob != nil {
		trace.WroteHeaders = func() { ob.mark(flow.PointRequestHeaders) }
		trace.WroteRequest = func(httptrace.WroteRequestInfo) { ob.mark(flow.PointRequestBody) }
	}
	return httptrace.WithClientTrace(ctx, trace)
}

func reply(w http.ResponseWriter, code int) {
	h := w.Header()
	h["Date"] = nil
	h["Content-Type"] = nil
	w.WriteHeader(code)
}

// hookGuard fences callbacks that run on the transport's goroutines from the
// handler's end.
type hookGuard struct {
	mu   sync.Mutex
	done bool
}

func (g *hookGuard) finish() {
	g.mu.Lock()
	g.done = true
	g.mu.Unlock()
}

var errBodyClosed = errors.New("h2: request body detached")

// requestBody is the client request body shared by the attempts to send it
// upstream. Reads from the client run on a helper goroutine, so that closing
// an attempt's view releases a transport goroutine blocked in Read (a refused
// stream with an idle body would otherwise never return). Bytes already read
// from the client but not delivered stay buffered for the next attempt.
type requestBody struct {
	src  io.Reader
	read atomic.Int64 // bytes delivered to an attempt

	mu  sync.Mutex
	buf []byte // unread part of store
	err error
	// store is the one read buffer; a fetch starts only once buf is drained,
	// so no slice handed out by Read aliases a later fetch.
	store []byte
	wait  chan struct{} // non-nil while a client read is in flight
}

func newRequestBody(r *http.Request, source io.Reader, ob *observed) *requestBody {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	src := source
	if ob != nil {
		// The client body is read once whatever the number of attempts, so
		// the observer sees every byte once.
		src = ob.req.Reader(source)
	}
	return &requestBody{src: src}
}

// finished returns the client's trailers once the body was read to its end.
func (b *requestBody) finished(r *http.Request) (http.Header, bool) {
	if b == nil || len(r.Trailer) == 0 {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != io.EOF || b.wait != nil {
		return nil, false
	}
	return r.Trailer, true
}

func (b *requestBody) fetch(done chan struct{}) {
	n, err := b.src.Read(b.store)
	b.mu.Lock()
	b.buf = b.store[:n]
	b.err = err
	b.wait = nil
	b.mu.Unlock()
	close(done)
}

// attempt returns the body of one upstream request.
func (b *requestBody) attempt() *attemptBody {
	return &attemptBody{b: b, closed: make(chan struct{})}
}

// attemptBody is one attempt's view of a requestBody.
type attemptBody struct {
	b      *requestBody
	closed chan struct{}
	shut   bool // guarded by b.mu
}

func (a *attemptBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b := a.b
	for {
		b.mu.Lock()
		if a.shut {
			b.mu.Unlock()
			return 0, errBodyClosed
		}
		if len(b.buf) > 0 {
			n := copy(p, b.buf)
			b.buf = b.buf[n:]
			b.read.Add(int64(n))
			b.mu.Unlock()
			return n, nil
		}
		if b.err != nil {
			err := b.err
			b.mu.Unlock()
			return 0, err
		}
		if b.wait == nil {
			if b.store == nil {
				b.store = make([]byte, copyBufferSize)
			}
			b.wait = make(chan struct{})
			go b.fetch(b.wait)
		}
		wait := b.wait
		b.mu.Unlock()
		select {
		case <-wait:
		case <-a.closed:
			return 0, errBodyClosed
		}
	}
}

// Close detaches the attempt: a pending or later Read fails. The client body is
// left open; the server closes it when the handler returns.
func (a *attemptBody) Close() error {
	a.b.mu.Lock()
	if !a.shut {
		a.shut = true
		close(a.closed)
	}
	a.b.mu.Unlock()
	return nil
}

// retryable reports whether a request that failed with err may be sent again on
// a fresh upstream connection without the origin processing it twice.
func retryable(err error, method string, body *requestBody) bool {
	if body != nil && body.read.Load() > 0 {
		return false
	}
	if notSent(err) {
		return true
	}
	if !connLost(err) {
		return false
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

// notSent matches the errors with which the HTTP/2 transport reports that the
// stream was never processed by the origin (the cases it retries itself).
func notSent(err error) bool {
	msg := err.Error()
	for _, s := range notSentErrors {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// connLost matches errors of a connection that went away; the request may or
// may not have reached the origin.
func connLost(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	for _, s := range connLostErrors {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// unusable matches the errors after which the connection takes no new request.
func unusable(err error) bool {
	if notSent(err) && !strings.Contains(err.Error(), "REFUSED_STREAM") {
		return true
	}
	return connLost(err)
}

var (
	notSentErrors = []string{
		"client conn not usable",
		"graceful shutdown GOAWAY",
		"client conn could not be established",
		"REFUSED_STREAM",
	}
	connLostErrors = []string{
		"client conn is closed",
		"client connection lost",
		"client connection force closed",
		"server sent GOAWAY",
		"connection reset",
		"broken pipe",
		"use of closed network connection",
	}
)

// hopByHop lists the fields that describe a single HTTP connection and must
// not be relayed over HTTP/2. Trailer is regenerated from the trailers.
func hopByHop(k string) bool {
	switch textproto.CanonicalMIMEHeaderKey(k) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Upgrade",
		"Transfer-Encoding", "Trailer", "Te", "Host":
		return true
	}
	return false
}

// connectionTokens returns the fields named by the Connection field.
func connectionTokens(h http.Header) map[string]bool {
	var m map[string]bool
	for _, v := range h["Connection"] {
		for _, t := range strings.Split(v, ",") {
			t = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			if m == nil {
				m = make(map[string]bool)
			}
			m[t] = true
		}
	}
	return m
}

func requestHeader(src http.Header) http.Header {
	dst := make(http.Header, len(src)+1)
	named := connectionTokens(src)
	for k, vv := range src {
		if hopByHop(k) || named[k] {
			continue
		}
		dst[k] = append([]string(nil), vv...)
	}
	// TE survives only as "trailers" (gRPC requires it).
	for _, v := range src["Te"] {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "trailers") {
				dst["Te"] = []string{"trailers"}
			}
		}
	}
	// An empty User-Agent keeps the transport from adding its own.
	if _, ok := dst["User-Agent"]; !ok {
		dst["User-Agent"] = []string{""}
	}
	return dst
}

func copyResponseHeader(dst, src http.Header) {
	named := connectionTokens(src)
	for k, vv := range src {
		if hopByHop(k) || named[k] {
			continue
		}
		if k == "Alt-Svc" {
			var kept []string
			for _, v := range vv {
				if f, _ := httpx.FilterAltSvc(v); f != "" {
					kept = append(kept, f)
				}
			}
			if len(kept) > 0 {
				dst[k] = kept
			}
			continue
		}
		dst[k] = append([]string(nil), vv...)
	}
}

// sameHost compares the host part of an :authority with the server name: port
// stripped, case-insensitive, IP literals compared as addresses.
func sameHost(authority, serverName string) bool {
	a, b := hostOnly(authority), hostOnly(serverName)
	if a == b {
		return true
	}
	ia, errA := netip.ParseAddr(a)
	ib, errB := netip.ParseAddr(b)
	return errA == nil && errB == nil && ia.Unmap() == ib.Unmap()
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

// withoutCredentials returns a copy of header without the headers that
// authenticate the client to its origin. An internal rewrite to another origin
// must not hand them to it.
func withoutCredentials(header http.Header) http.Header {
	header = header.Clone()
	for _, name := range httpx.CredentialHeaders {
		header.Del(name)
	}
	return header
}
