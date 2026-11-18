package h1

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/httpx"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/common/mitm/scripthook"
	"github.com/sagernet/sing-box/script"
	E "github.com/sagernet/sing/common/exceptions"
)

const continueReply = "HTTP/1.1 100 Continue\r\n\r\n"

// joinValues returns the values of the fields named name, comma separated.
func joinValues(header httpx.Header, name string) string {
	var out string
	for i := range header {
		if strings.EqualFold(header[i].Name, name) {
			if out != "" {
				out += ", "
			}
			out += header[i].Value
		}
	}
	return out
}

// dropDigests removes the fields that no longer describe an edited body (integrity digests,
// and the Trailer announcement: the edited body is sent with a length, so its trailer section
// is dropped) and notes it in the first edit record.
func dropDigests(header *httpx.Header, hits []flow.RewriteHit, trailer httpx.Header) {
	note := func(change flow.RewriteChange) {
		if len(hits) > 0 {
			hits[0].Changes = append(hits[0].Changes, change)
		}
	}
	for _, name := range []string{"Digest", "Content-Digest", "Repr-Digest", "Content-MD5"} {
		if header.Has(name) {
			note(flow.RewriteChange{Op: rewrite.OpDelete, Name: name, Before: header.Get(name), HadBefore: true})
			header.Del(name)
		}
	}
	if header.Has("Trailer") || len(trailer) > 0 {
		var names []string
		for i := range trailer {
			names = append(names, trailer[i].Name)
		}
		note(flow.RewriteChange{Op: "trailer-dropped", Name: "Trailer", Before: header.Get("Trailer"), HadBefore: header.Has("Trailer"), After: strings.Join(names, ", "), HasAfter: len(names) > 0})
		header.Del("Trailer")
	}
}

// collectRequest buffers the request body for body rules before the head is forwarded. It
// returns nil when the rules do not select the request. An error means the request body could
// not be read; the caller answers and ends the connection.
func (s *session) collectRequest(plan *rewrite.Plan, set *rewrite.Set, framing *httpx.Framing, http10 bool, sx *scripthook.Exchange) (*rewrite.Held, error) {
	req := &s.req
	var src io.Reader
	length := int64(-1)
	if framing.Kind == httpx.BodyLength {
		s.bodyLimited = io.LimitedReader{R: s.clientR, N: framing.Length}
		src = &s.bodyLimited
		length = framing.Length
	} else {
		s.bodyChunkedR.Reset(s.clientR)
		src = &s.bodyChunkedR
	}
	contentType := req.Header.Get("Content-Type")
	return plan.HoldFor(rewrite.ScopeRequest, contentType, joinValues(req.Header, "Content-Encoding"), src, length,
		rewrite.StreamingMessage(rewrite.ScopeRequest, req.Method, 0, contentType, false), max(set.MaxBodySize(), sx.MaxBody(script.PhaseRequest)), set.MaxBodySize(), &s.reserved,
		func() {
			if !http10 && req.Header.HasToken("Expect", "100-continue") {
				// The client waits for permission to send the body. The expectation is answered
				// here and not forwarded: the body follows the head at once.
				s.reply(continueReply)
				req.Header.Del("Expect")
			}
		}, sx.WantsBody(script.PhaseRequest, true))
}

// collectResponse buffers the response body for body rules before the head is forwarded. spent
// reports a body delimited by close.
func (s *session) collectResponse(plan *rewrite.Plan, set *rewrite.Set, method string, sx *scripthook.Exchange) (held *rewrite.Held, spent bool, err error) {
	resp := &s.resp
	contentType := resp.Header.Get("Content-Type")
	want := sx.WantsBody(script.PhaseResponse, true)
	if !want && !plan.NeedsBody(rewrite.ScopeResponse, contentType) {
		return nil, false, nil
	}
	if rewrite.StreamingMessage(rewrite.ScopeResponse, method, resp.StatusCode, contentType, s.req.Header.Has("Range")) {
		held, err = plan.HoldFor(rewrite.ScopeResponse, contentType, "", nil, -1, true, 0, 0, &s.reserved, nil, want)
		return held, false, err
	}
	framing, ferr := httpx.ResponseFraming(method, resp)
	if ferr != nil || framing.Kind == httpx.BodyNone {
		// Malformed responses are reported by the caller.
		return nil, false, nil
	}
	if framing.Codings != "" {
		return &rewrite.Held{Hits: plan.SkipHits(rewrite.ScopeResponse, contentType, rewrite.SkipEncoding), Reason: rewrite.SkipEncoding}, false, nil
	}
	length := int64(-1)
	var src io.Reader
	switch framing.Kind {
	case httpx.BodyLength:
		if framing.Length == 0 {
			return nil, false, nil
		}
		length = framing.Length
		s.limited = io.LimitedReader{R: s.upstreamR, N: framing.Length}
		src = &s.limited
	case httpx.BodyChunked:
		s.chunkedR.Reset(s.upstreamR)
		src = &s.chunkedR
	default:
		src = s.upstreamR
	}
	held, err = plan.HoldFor(rewrite.ScopeResponse, contentType, joinValues(resp.Header, "Content-Encoding"), src, length, false, max(set.MaxBodySize(), sx.MaxBody(script.PhaseResponse)), set.MaxBodySize(), &s.reserved, nil, want)
	return held, framing.Kind == httpx.BodyClose, err
}

// editedLength rewrites the framing fields of a message whose body was replaced.
func editedLength(header *httpx.Header, length int) {
	header.Del("Transfer-Encoding")
	header.Set("Content-Length", strconv.Itoa(length))
}

// writeChunked writes data as a chunked body followed by the last chunk (with the permitted
// trailer fields of source).
func writeChunked(w *bufio.Writer, data []byte, source *httpx.ChunkedReader) error {
	if len(data) > 0 {
		w.WriteString(strconv.FormatInt(int64(len(data)), 16))
		w.WriteString("\r\n")
		w.Write(data)
		w.WriteString("\r\n")
	}
	return writeLastChunk(w, source)
}

// splitAuthority returns the host (without brackets) and port of a Host field value; the port
// defaults by scheme.
func splitAuthority(authority, scheme string) (string, int) {
	port := 80
	if scheme == "https" {
		port = 443
	}
	host := authority
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
	}
	return host, port
}

// parkedUpstream is the upstream connection set aside while a request goes to another origin.
type parkedUpstream struct {
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	exchanges int
	dead      bool
}

// enterInternal replaces the upstream by a fresh connection to the origin of an internal
// rewrite for the length of one exchange. The previous upstream stays untouched, with its
// own buffers, and returns after the exchange (leaveInternal).
func (s *session) enterInternal(in *rewrite.Internal) error {
	if s.options.Internal == nil {
		return E.New("no dialer for internal rewrite")
	}
	conn, err := s.options.Internal(s.ctx, in)
	if err != nil {
		return err
	}
	if conn == nil {
		return E.New("internal rewrite: no connection")
	}
	conn = withReadDeadline(conn)
	reader := bufio.NewReaderSize(conn, ioBufferSize)
	writer := bufio.NewWriterSize(conn, ioBufferSize)
	s.upstreamMu.Lock()
	if s.closed {
		s.upstreamMu.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	s.parked = &parkedUpstream{conn: s.upstream, reader: s.upstreamR, writer: s.upstreamW, exchanges: s.upstreamExchanges, dead: s.upstreamDead}
	s.upstream = conn
	s.upstreamMu.Unlock()
	s.upstreamR, s.upstreamW = reader, writer
	s.upstreamHead.Reader = reader
	s.upstreamFlush.w = writer
	s.upstreamWatch.conn = conn
	s.upstreamWatch.reader = reader
	s.upstreamExchanges = 0
	s.upstreamDead = false
	return nil
}

// leaveInternal closes the internal connection and puts the parked upstream back. The loop
// counts the finished exchange once more, so the saved count is lowered by one.
func (s *session) leaveInternal() {
	s.upstreamMu.Lock()
	parked := s.parked
	s.parked = nil
	internal := s.upstream
	if parked != nil {
		s.upstream = parked.conn
	}
	s.upstreamMu.Unlock()
	if parked == nil {
		return
	}
	internal.Close()
	s.upstreamR, s.upstreamW = parked.reader, parked.writer
	s.upstreamHead.Reader = parked.reader
	s.upstreamFlush.w = parked.writer
	s.upstreamWatch.conn = parked.conn
	s.upstreamWatch.reader = parked.reader
	s.upstreamWatch.failed.Store(false)
	s.upstreamExchanges = parked.exchanges - 1
	s.upstreamDead = parked.dead
}

// writeHeldRequest sends a buffered request body upstream, in the framing of the head.
func (s *session) writeHeldRequest(h *rewrite.Held, framing httpx.Framing) error {
	defer rewrite.ReleaseHold(&s.reserved)
	if s.reqBody != nil {
		if len(h.Data) > 0 {
			s.reqBody.Write(h.Data)
		}
		s.reqBody.Done()
	}
	if framing.Kind == httpx.BodyChunked {
		if s.obs != nil && len(s.bodyChunkedR.Trailer()) > 0 {
			s.obs.Trailers(flow.Request, trailerHeaders(s.bodyChunkedR.Trailer()))
		}
		return writeChunked(s.upstreamW, h.Data, &s.bodyChunkedR)
	}
	s.upstreamW.Write(h.Data)
	return s.upstreamW.Flush()
}

// writeHeldResponse sends a buffered response body to the client, in the framing of the head
// (already written).
func (s *session) writeHeldResponse(h *rewrite.Held, framing httpx.Framing, chunkedOut bool) error {
	defer rewrite.ReleaseHold(&s.reserved)
	if s.respBody != nil {
		if len(h.Data) > 0 {
			s.respBody.Write(h.Data)
		}
		s.respBody.Done()
	}
	if framing.Kind == httpx.BodyChunked && chunkedOut {
		if s.obs != nil && len(s.chunkedR.Trailer()) > 0 {
			s.obs.Trailers(flow.Response, trailerHeaders(s.chunkedR.Trailer()))
		}
		return writeChunked(s.clientW, h.Data, &s.chunkedR)
	}
	s.clientW.Write(h.Data)
	return s.clientW.Flush()
}
