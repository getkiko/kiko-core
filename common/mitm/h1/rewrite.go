package h1

import (
	"io"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/httpx"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	N "github.com/sagernet/sing/common/network"
)

// errRewriteAbort is what the observer is told when a rule dropped the connection.
var errRewriteAbort = &abortError{}

type abortError struct{}

func (*abortError) Error() string { return "rejected by rewrite rule" }

func (s *session) scheme() string {
	if s.internalScheme != "" {
		return s.internalScheme
	}
	if s.options.Scheme != "" {
		return s.options.Scheme
	}
	return "https"
}

// rewritePlan matches the current rule set against the request in s.req. It returns nil without
// allocating when there is no rule set, no match, or the request has no origin-form target.
func (s *session) rewritePlan() *rewrite.Plan {
	if s.options.Rewrite == nil {
		return nil
	}
	set := s.options.Rewrite()
	if set.Empty() {
		return nil
	}
	s.planSet = set
	req := &s.req
	if req.Method == "CONNECT" || len(req.Target) == 0 || req.Target[0] != '/' {
		return nil
	}
	return set.Plan(s.scheme(), req.Header.Get("Host"), req.Target)
}

// rewriteSet returns the current rewrite rule set, nil without one.
func (s *session) rewriteSet() *rewrite.Set {
	if s.options.Rewrite == nil {
		return nil
	}
	return s.options.Rewrite()
}

// firstNonEmpty returns the first of the lists that has records.
func firstNonEmpty(lists ...[]flow.RewriteHit) []flow.RewriteHit {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}

func toFlowHeaders(header httpx.Header) []flow.Header {
	out := make([]flow.Header, len(header))
	for i := range header {
		out[i] = flow.Header{Name: header[i].Name, Value: header[i].Value}
	}
	return out
}

func fromFlowHeaders(header []flow.Header) httpx.Header {
	out := make(httpx.Header, len(header))
	for i := range header {
		out[i] = httpx.Field{Name: header[i].Name, Value: header[i].Value}
	}
	return out
}

// applyHeaders runs the header rules of one side on header. The result is header itself when no
// rule changed anything.
func applyHeaders(plan *rewrite.Plan, response bool, header httpx.Header) (httpx.Header, []flow.RewriteHit) {
	var edited []flow.Header
	var hits []flow.RewriteHit
	if response {
		edited, hits = plan.ApplyResponse(toFlowHeaders(header))
	} else {
		edited, hits = plan.ApplyRequest(toFlowHeaders(header))
	}
	if len(hits) == 0 {
		return header, nil
	}
	return fromFlowHeaders(edited), hits
}

// serveLocal answers the request with a rule's own response. The upstream is not used. It
// returns errClose when the connection must end.
func (s *session) serveLocal(local *rewrite.LocalResponse, hasBody, http10, closeAfter bool) error {
	if s.obs != nil {
		s.obs.Rewritten([]flow.RewriteHit{local.Hit})
		s.obs.Mark(flow.PointRequestHeaders, time.Now())
	}
	if s.options.OnRequest != nil {
		s.options.OnRequest()
	}
	s.localServed = true
	if local.Abort {
		s.abortErr = errRewriteAbort
		return errClose
	}
	// A request body or an expectation is not consumed: end the connection after the answer.
	closeAfter = closeAfter || hasBody || s.req.Header.Has("Expect")
	status := local.Status
	header := make(httpx.Header, 0, len(local.Headers)+1)
	for _, h := range local.Headers {
		if status == 204 && h.Name == "Content-Length" {
			continue
		}
		header = append(header, httpx.Field{Name: h.Name, Value: h.Value})
	}
	if closeAfter {
		header = append(header, httpx.Field{Name: "Connection", Value: "close"})
	}
	resp := httpx.Response{
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		StatusCode: status, Reason: http.StatusText(status), Header: header,
	}
	withBody := len(local.Body) > 0 && s.req.Method != "HEAD" && status != 204 && status != 304
	if s.obs != nil {
		now := time.Now()
		s.obs.Mark(flow.PointFirstByte, now)
		s.obs.Mark(flow.PointResponseHeaders, now)
		s.obs.ResponseHead(status, s.flowHeaders(header))
		if withBody {
			s.respBody.Write(local.Body)
		}
		s.respBody.Done()
	}
	httpx.WriteResponseHead(s.clientW, &resp)
	if withBody {
		s.clientW.Write(local.Body)
	}
	if err := s.clientW.Flush(); err != nil {
		return err
	}
	if !closeAfter {
		return nil
	}
	if hasBody || s.req.Header.Has("Expect") {
		// Unread data would turn the close into a reset that can destroy the answer.
		_ = N.CloseWrite(s.client)
		_ = s.client.SetReadDeadline(time.Now().Add(rejectLinger))
		_, _ = io.CopyN(io.Discard, s.clientR, rejectDrainLimit)
	}
	return errClose
}
