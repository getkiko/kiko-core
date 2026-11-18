package capture

import (
	"errors"
	"io"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/flow"
)

// exchange implements flow.Exchange for one record.
type exchange struct {
	m         *Manager
	e         *entry
	req, resp bodyRec
}

func cloneHeaders(headers []flow.Header) []flow.Header {
	if len(headers) == 0 {
		return nil
	}
	return append([]flow.Header(nil), headers...)
}

func headerValue(headers []flow.Header, name string) string {
	for i := range headers {
		if strings.EqualFold(headers[i].Name, name) {
			return headers[i].Value
		}
	}
	return ""
}

func (x *exchange) RequestHead(head flow.RequestHead) {
	headers := cloneHeaders(head.Headers)
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	e := x.e
	if e.evicted {
		return
	}
	r := &e.rec
	r.Method = head.Method
	r.Scheme = head.Scheme
	r.Authority = head.Authority
	r.Host = hostOf(head.Authority)
	r.Path = head.Path
	r.URL = head.Scheme + "://" + head.Authority + head.Path
	r.Proto = head.Proto
	r.RequestHeaders = headers
	r.RequestEncoding = headerValue(headers, "Content-Encoding")
	x.m.addSizeLocked(e, int64(len(r.Method)+len(r.Scheme)+len(r.Authority)+len(r.Host)+len(r.Path)+len(r.URL)+len(r.Proto)+len(r.RequestEncoding))+headersSize(headers))
	x.m.touchLocked(e)
}

func (x *exchange) RequestBody() flow.Body  { return &x.req }
func (x *exchange) ResponseBody() flow.Body { return &x.resp }

func (x *exchange) Informational(code int, headers []flow.Header) {
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	if x.e.evicted || len(x.e.rec.Interim) >= 16 {
		return
	}
	x.e.rec.Interim = append(x.e.rec.Interim, code)
	x.m.addSizeLocked(x.e, 8)
	x.m.touchLocked(x.e)
}

func (x *exchange) ResponseHead(status int, headers []flow.Header) {
	headers = cloneHeaders(headers)
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	e := x.e
	if e.evicted {
		return
	}
	e.rec.Status = status
	e.rec.ResponseHeaders = headers
	e.rec.ResponseEncoding = headerValue(headers, "Content-Encoding")
	x.m.addSizeLocked(e, int64(len(e.rec.ResponseEncoding))+headersSize(headers))
	if e.rec.Timing.ResponseHeaders.IsZero() {
		e.rec.Timing.ResponseHeaders = time.Now()
	}
	x.m.touchLocked(e)
}

func (x *exchange) Trailers(side flow.Side, headers []flow.Header) {
	headers = cloneHeaders(headers)
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	e := x.e
	if e.evicted {
		return
	}
	if side == flow.Response {
		e.rec.ResponseTrailers = headers
	} else {
		e.rec.RequestTrailers = headers
	}
	x.m.addSizeLocked(e, headersSize(headers))
	x.m.touchLocked(e)
}

func (x *exchange) Mark(point flow.Point, at time.Time) {
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	if x.e.evicted {
		return
	}
	t := &x.e.rec.Timing
	switch point {
	case flow.PointStart:
		t.Start = at
	case flow.PointRequestHeaders:
		t.RequestHeaders = at
	case flow.PointRequestBody:
		t.RequestBody = at
	case flow.PointFirstByte:
		t.FirstByte = at
	case flow.PointResponseHeaders:
		t.ResponseHeaders = at
	case flow.PointResponseBody:
		t.ResponseBody = at
	case flow.PointEnd:
		t.End = at
	}
}

func (x *exchange) SetDurations(dns, connect, tls time.Duration) {
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	t := &x.e.rec.Timing
	t.DNS, t.Connect, t.TLS = dns, connect, tls
}

func (x *exchange) Upgrade(status int, headers []flow.Header) {
	headers = cloneHeaders(headers)
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	e := x.e
	if e.evicted {
		return
	}
	e.rec.Status = status
	e.rec.ResponseHeaders = headers
	x.m.addSizeLocked(e, headersSize(headers))
	e.rec.State = StateUpgraded
	if e.rec.Timing.ResponseHeaders.IsZero() {
		e.rec.Timing.ResponseHeaders = time.Now()
	}
	x.m.touchLocked(e)
	x.m.markFinishedLocked(e)
	x.m.enforceLocked()
}

func (x *exchange) Rewritten(hits []flow.RewriteHit) {
	if len(hits) == 0 {
		return
	}
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	if x.e.evicted {
		return
	}
	x.e.rec.Rewritten = true
	x.e.rec.Rewrites = append(x.e.rec.Rewrites[:len(x.e.rec.Rewrites):len(x.e.rec.Rewrites)], hits...)
	x.m.addSizeLocked(x.e, hitsSize(hits))
	x.m.enforceLocked()
	x.m.touchLocked(x.e)
}

func (x *exchange) Finish(err error) {
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	e := x.e
	if e.evicted {
		return
	}
	now := time.Now()
	x.req.finishLocked(now, false)
	x.resp.finishLocked(now, false)
	if e.rec.Timing.End.IsZero() {
		e.rec.Timing.End = now
	}
	if err != nil {
		e.rec.Error = err.Error()
		x.m.addSizeLocked(e, int64(len(e.rec.Error)))
	}
	switch {
	case e.rec.State == StateUpgraded:
	case err != nil && !errors.Is(err, io.EOF):
		e.rec.State = StateFailed
	default:
		e.rec.State = StateComplete
	}
	x.m.touchLocked(e)
	x.m.markFinishedLocked(e)
	x.m.enforceLocked()
}

// bodyRec observes one body and stores its leading bytes in the entry.
type bodyRec struct {
	x    *exchange
	side flow.Side
	tee  body.Tee
	done bool
}

func (b *bodyRec) store() *bodyStore {
	if b.side == flow.Response {
		return &b.x.e.resp
	}
	return &b.x.e.req
}

// WriteBody implements body.Sink; the manager lock is held.
func (b *bodyRec) WriteBody(p []byte) bool {
	m, e := b.x.m, b.x.e
	if e.evicted {
		return false
	}
	store := b.store()
	for len(p) > 0 {
		if spare := store.spare(); spare > 0 {
			n := min(spare, len(p))
			store.fill(p[:n])
			p = p[n:]
			continue
		}
		size := store.nextChunk(len(p))
		if m.bytes+int64(size) > m.opts.MaxMemory {
			// Only finished records can make room.
			for m.bytes+int64(size) > m.opts.MaxMemory && m.evictOldestFinishedLocked() {
			}
			if e.evicted {
				// Making room evicted this record itself.
				return false
			}
			if m.bytes+int64(size) > m.opts.MaxMemory {
				if !e.rec.BodyDropped {
					e.rec.BodyDropped = true
					m.bodyDropped++
					m.touchLocked(e)
				}
				return false
			}
		}
		store.addChunk(size)
		m.addSizeLocked(e, int64(size))
	}
	return true
}

func (b *bodyRec) Write(p []byte) {
	if len(p) == 0 {
		return
	}
	b.x.m.mu.Lock()
	b.tee.Write(p)
	b.x.m.mu.Unlock()
}

func (b *bodyRec) Reader(r io.Reader) io.Reader { return &lockedReader{r: r, b: b} }
func (b *bodyRec) Writer(w io.Writer) io.Writer { return &lockedWriter{w: w, b: b} }

func (b *bodyRec) Done() {
	b.x.m.mu.Lock()
	defer b.x.m.mu.Unlock()
	if b.x.e.evicted || b.done {
		return
	}
	b.finishLocked(time.Now(), true)
}

// finishLocked folds the counters into the record.
func (b *bodyRec) finishLocked(now time.Time, touch bool) {
	if b.done {
		return
	}
	b.done = true
	e, m := b.x.e, b.x.m
	store := b.store()
	if freed := store.shrink(); freed > 0 {
		m.addSizeLocked(e, -freed)
	}
	r := &e.rec
	if b.side == flow.Response {
		r.ResponseBytes = b.tee.Total()
		r.ResponseBodyStored = store.stored
		r.ResponseBodyTruncated = b.tee.Truncated()
		if r.Timing.ResponseBody.IsZero() {
			r.Timing.ResponseBody = now
		}
	} else {
		r.RequestBytes = b.tee.Total()
		r.RequestBodyStored = store.stored
		r.RequestBodyTruncated = b.tee.Truncated()
		if r.Timing.RequestBody.IsZero() {
			r.Timing.RequestBody = now
		}
	}
	if touch {
		m.touchLocked(e)
	}
}

type lockedReader struct {
	r io.Reader
	b *bodyRec
}

func (r *lockedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.b.Write(p[:n])
	}
	if err != nil {
		r.b.Done()
	}
	return n, err
}

type lockedWriter struct {
	w io.Writer
	b *bodyRec
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.b.Write(p[:n])
	}
	return n, err
}
