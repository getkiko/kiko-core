package h2

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	E "github.com/sagernet/sing/common/exceptions"
)

var errRewriteAbort = E.New("rejected by rewrite rule")

// rewritePlan matches the current rule set against the stream's URL. It returns nil without
// allocating when there is no rule set or no match.
func (s *session) rewritePlan(r *http.Request) (*rewrite.Plan, *rewrite.Set) {
	if s.opts.Rewrite == nil {
		return nil, nil
	}
	set := s.opts.Rewrite()
	if set.Empty() || len(r.RequestURI) == 0 || r.RequestURI[0] != '/' {
		return nil, nil
	}
	return set.Plan("https", r.Host, r.RequestURI), set
}

// authorityPort returns the port of an :authority value, or fallback when it names none.
func authorityPort(authority string, fallback int) int {
	if _, port, err := net.SplitHostPort(authority); err == nil {
		if n, err := strconv.Atoi(port); err == nil {
			return n
		}
	}
	return fallback
}

func cloneHeader(header http.Header) http.Header {
	return header.Clone()
}

// dropDigests removes the integrity fields that no longer describe an edited body and notes
// their removal in the first edit record. header must be a private copy.
func dropDigests(header http.Header, hits []flow.RewriteHit) {
	for _, name := range []string{"Digest", "Content-Digest", "Repr-Digest", "Content-Md5"} {
		values, ok := header[name]
		if !ok {
			continue
		}
		if len(hits) > 0 {
			hits[0].Changes = append(hits[0].Changes, flow.RewriteChange{Op: rewrite.OpDelete, Name: strings.ToLower(name), Before: strings.Join(values, ", "), HadBefore: true})
		}
		delete(header, name)
	}
}

// maxInternalOrigins bounds the target origins of internal rewrites per session.
const maxInternalOrigins = 16

var errTooManyOrigins = E.New("too many internal rewrite origins in one session")

var errNoInternal = E.New("no dialer for internal rewrite")

// internalTransport returns the HTTP/1.1 transport of the session for an internal rewrite's
// origin. Its connections come from Options.Internal.
func (s *session) internalTransport(in *rewrite.Internal) (*http.Transport, error) {
	key := in.Scheme + "://" + net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
	s.extMu.Lock()
	defer s.extMu.Unlock()
	if s.extClosed {
		return nil, io.ErrClosedPipe
	}
	if t, ok := s.ext[key]; ok {
		return t, nil
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if s.opts.Internal == nil {
			return nil, errNoInternal
		}
		return s.opts.Internal(ctx, in)
	}
	if len(s.ext) >= maxInternalOrigins {
		return nil, errTooManyOrigins
	}
	t := &http.Transport{
		DisableCompression:     true,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
		// A non-nil empty map keeps the transport on HTTP/1.1.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	if in.Scheme == "https" {
		t.DialTLSContext = dial
	} else {
		t.DialContext = dial
	}
	if s.ext == nil {
		s.ext = make(map[string]*http.Transport)
	}
	s.ext[key] = t
	return t, nil
}

// relayInternal sends the request to the origin of an internal rewrite over its own HTTP/1.1
// connection and relays the answer. A failure is a 502; the original host is never tried.
func (s *session) relayInternal(w http.ResponseWriter, r *http.Request, g *hookGuard, in *rewrite.Internal, build func() *http.Request, ob *observed, plan *rewrite.Plan, set *rewrite.Set, reserved *int64, ranged bool) error {
	transport, err := s.internalTransport(in)
	if err != nil {
		reply(w, http.StatusBadGateway)
		return err
	}
	out := build()
	out = out.WithContext(s.traceContext(out.Context(), w, g, ob))
	resp, err := transport.RoundTrip(out)
	if err != nil {
		out.Body.Close()
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		s.debug("h2 internal rewrite to ", in.URL, " failed: ", err)
		reply(w, http.StatusBadGateway)
		return err
	}
	rewrite.ReleaseHold(reserved)
	return s.respond(w, r, resp, ob, plan, set, ranged)
}

// applyHeader runs the header rules of one side on header. The result is header itself when no
// rule changed anything; otherwise a new map with canonical keys.
func applyHeader(plan *rewrite.Plan, response bool, header http.Header) (http.Header, []flow.RewriteHit) {
	var edited []flow.Header
	var hits []flow.RewriteHit
	if response {
		edited, hits = plan.ApplyResponse(flowHeaders(header))
	} else {
		edited, hits = plan.ApplyRequest(flowHeaders(header))
	}
	if len(hits) == 0 {
		return header, nil
	}
	out := make(http.Header, len(edited))
	for _, h := range edited {
		key := textproto.CanonicalMIMEHeaderKey(h.Name)
		out[key] = append(out[key], h.Value)
	}
	return out, hits
}

func (o *observed) rewritten(hits []flow.RewriteHit) {
	if o != nil && len(hits) > 0 {
		o.ex.Rewritten(hits)
	}
}

// serveLocal answers the stream with a rule's own response. It panics with
// http.ErrAbortHandler (resetting the stream) for an abort.
func (s *session) serveLocal(w http.ResponseWriter, r *http.Request, local *rewrite.LocalResponse, ob *observed, failure *error) {
	ob.rewritten([]flow.RewriteHit{local.Hit})
	ob.mark(flow.PointRequestHeaders)
	if s.opts.OnRequest != nil {
		s.opts.OnRequest()
	}
	if local.Abort {
		*failure = errRewriteAbort
		panic(http.ErrAbortHandler)
	}
	status := local.Status
	header := make(http.Header, len(local.Headers))
	for _, f := range local.Headers {
		if status == 204 && f.Name == "Content-Length" {
			continue
		}
		key := textproto.CanonicalMIMEHeaderKey(f.Name)
		header[key] = append(header[key], f.Value)
	}
	h := w.Header()
	for k, vv := range header {
		h[k] = append([]string(nil), vv...)
	}
	if _, ok := h["Content-Type"]; !ok {
		// The server must not sniff a type for the answer.
		h["Content-Type"] = nil
	}
	ob.mark(flow.PointFirstByte)
	ob.mark(flow.PointResponseHeaders)
	ob.responseHead(status, header)
	w.WriteHeader(status)
	if len(local.Body) > 0 && r.Method != http.MethodHead && status != 204 && status != 304 {
		if ob != nil {
			ob.resp.Write(local.Body)
		}
		if _, err := w.Write(local.Body); err != nil {
			*failure = err
		}
	}
	if ob != nil {
		ob.resp.Done()
	}
}
