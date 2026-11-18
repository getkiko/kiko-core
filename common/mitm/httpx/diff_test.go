package httpx

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The differential tests compare httpx's head parsing and framing decision with net/http.
// Whenever both accept a message they must agree on method, target, version and body framing.
// Rejecting more than net/http is fine; every message httpx accepts and net/http does not, or
// frames differently, must match one of the deliberate differences below.

type deliberate struct {
	reason string
	match  func(raw string, method string) bool
}

var requestDifferences = []deliberate{
	{"RFC 9112 section 2.2: empty lines before the request line are ignored", func(raw, _ string) bool {
		return strings.HasPrefix(raw, "\r\n")
	}},
	{"the request target is forwarded verbatim; beyond excluding SP and CTLs its syntax is the origin's business (net/http insists on a parseable URI)", func(raw, _ string) bool {
		line, _, _ := strings.Cut(raw, "\r\n")
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			return false
		}
		if parts[0] == "CONNECT" && !strings.HasPrefix(parts[1], "/") {
			_, err := url.Parse("http://" + parts[1])
			return err != nil
		}
		_, err := url.ParseRequestURI(parts[1])
		return err != nil
	}},
	{"RFC 9110 section 8.6: a Content-Length list of identical values is that value", func(raw, _ string) bool {
		return fieldValueHas(raw, "Content-Length", ",")
	}},
	{"RFC 9110 section 5.6.1: empty list elements in Transfer-Encoding are ignored", func(raw, _ string) bool {
		return emptyListElement(raw, "Transfer-Encoding")
	}},
	{"RFC 9112 section 3.2: the Host rules (one valid Host in HTTP/1.1) are enforced by h1, not by the head parser", func(raw, _ string) bool {
		return len(fieldValues(raw, "Host")) > 1
	}},
}

var responseDifferences = []deliberate{
	{"RFC 9112 section 6.3 rule 2: a 2xx answer to CONNECT has no body", func(raw, method string) bool {
		return method == "CONNECT" && strings.HasPrefix(raw[min(len(raw), 9):], "2")
	}},
	{"RFC 9110 section 8.6: a Content-Length list of identical values is that value", func(raw, _ string) bool {
		return fieldValueHas(raw, "Content-Length", ",")
	}},
	{"RFC 9110 section 5.6.1: empty list elements in Transfer-Encoding are ignored", func(raw, _ string) bool {
		return emptyListElement(raw, "Transfer-Encoding")
	}},
	{"RFC 9112 section 6.3 rule 4: transfer codings before a final chunked are kept, a final coding other than chunked is delimited by close (net/http only knows chunked)", func(raw, _ string) bool {
		for _, value := range fieldValues(raw, "Transfer-Encoding") {
			if !strings.EqualFold(strings.Trim(value, " \t"), "chunked") {
				return true
			}
		}
		return len(fieldValues(raw, "Transfer-Encoding")) > 1
	}},
	{"RFC 9112 section 6.1: Transfer-Encoding in an HTTP/1.0 message is faulty framing, the body runs to close and Content-Length is ignored (net/http ignores Transfer-Encoding instead)", func(raw, _ string) bool {
		return strings.HasPrefix(raw, "HTTP/1.0") && len(fieldValues(raw, "Transfer-Encoding")) > 0 && len(fieldValues(raw, "Content-Length")) > 0
	}},
}

func headOf(raw string) string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	return head
}

func fieldValues(raw, name string) []string {
	var values []string
	lines := strings.Split(headOf(raw), "\r\n")
	for _, line := range lines[min(1, len(lines)):] {
		n, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(n, name) {
			values = append(values, v)
		}
	}
	return values
}

func fieldValueHas(raw, name, s string) bool {
	for _, v := range fieldValues(raw, name) {
		if strings.Contains(v, s) {
			return true
		}
	}
	return false
}

func emptyListElement(raw, name string) bool {
	for _, v := range fieldValues(raw, name) {
		for _, element := range strings.Split(v, ",") {
			if strings.Trim(element, " \t") == "" {
				return true
			}
		}
	}
	return false
}

func explain(list []deliberate, raw, method string) string {
	for _, d := range list {
		if d.match(raw, method) {
			return d.reason
		}
	}
	return ""
}

// generatedRequests crosses request lines with framing and Host fields.
func generatedRequests() []string {
	lines := []string{
		"GET / HTTP/1.1", "POST /a?b=c HTTP/1.1", "GET / HTTP/1.0", "POST / HTTP/1.2", "GET / HTTP/2.0",
		"GET * HTTP/1.1", "OPTIONS * HTTP/1.1", "GET http://h/x HTTP/1.1", "CONNECT h:443 HTTP/1.1",
		"GET a HTTP/1.1", "GET /%zz HTTP/1.1", "get / HTTP/1.1", "GET / http/1.1", "GET / HTTP/1.1 ",
		"GET  / HTTP/1.1", "G@T / HTTP/1.1", "GET /\x7f HTTP/1.1", "GET /\xff HTTP/1.1",
	}
	framings := []string{
		"",
		"Content-Length: 5\r\n",
		"Content-Length: 0\r\n",
		"Content-Length: 05\r\n",
		"Content-Length:5\r\n",
		"Content-Length: 5 \r\n",
		"Content-Length: 5\r\nContent-Length: 5\r\n",
		"Content-Length: 5, 5\r\n",
		"Content-Length: 5\r\nContent-Length: 6\r\n",
		"Content-Length: +5\r\n",
		"Content-Length: 5x\r\n",
		"Content-Length: 1 5\r\n",
		"Content-Length: 18446744073709551616\r\n",
		"Content-Length: 999999999999999999\r\n",
		"Transfer-Encoding: chunked\r\n",
		"Transfer-Encoding: Chunked\r\n",
		"Transfer-Encoding: chunked \r\n",
		"Transfer-Encoding: , chunked\r\n",
		"Transfer-Encoding: chunked,\r\n",
		"Transfer-Encoding: chunked, chunked\r\n",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: gzip, chunked\r\n",
		"Transfer-Encoding: identity\r\n",
		"Transfer-Encoding: xchunked\r\n",
		"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
		"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding : chunked\r\n",
		"Transfer-Encoding:\tchunked\r\n",
		" Transfer-Encoding: chunked\r\n",
		"X: a\r\n chunked\r\n",
		"X: a\x01\r\n",
		"X: \xff\r\n",
		"X\x00: a\r\n",
		"Expect: 100-continue\r\nContent-Length: 5\r\n",
	}
	hosts := []string{"Host: h\r\n", "", "Host: h\r\nHost: h\r\n", "Host: a b\r\n"}
	var out []string
	for _, line := range lines {
		for _, framing := range framings {
			for _, host := range hosts {
				out = append(out, line+"\r\n"+host+framing+"\r\n")
			}
		}
	}
	out = append(out, "\r\n"+lines[0]+"\r\nHost: h\r\n\r\n")
	return out
}

func generatedResponses() []string {
	lines := []string{
		"HTTP/1.1 200 OK", "HTTP/1.1 200", "HTTP/1.1 200 ", "HTTP/1.0 200 OK", "HTTP/1.1 204 No Content",
		"HTTP/1.1 304 Not Modified", "HTTP/1.1 101 Switching Protocols", "HTTP/1.1 100 Continue",
		"HTTP/1.1 404 Not Found", "HTTP/1.1 999 Odd", "HTTP/1.1 099 Low", "HTTP/1.1 20 OK", "HTTP/2.0 200 OK",
		"HTTP/1.1  200 OK", "http/1.1 200 OK", "HTTP/1.1 200 \x01",
	}
	framings := []string{
		"",
		"Content-Length: 5\r\n",
		"Content-Length: 0\r\n",
		"Content-Length: 5\r\nContent-Length: 5\r\n",
		"Content-Length: 5, 5\r\n",
		"Content-Length: 5\r\nContent-Length: 6\r\n",
		"Content-Length: -1\r\n",
		"Transfer-Encoding: chunked\r\n",
		"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
		"Transfer-Encoding: gzip, chunked\r\n",
		"Transfer-Encoding: chunked, gzip\r\n",
		"Transfer-Encoding: identity\r\n",
		"Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: , chunked\r\n",
		"Transfer-Encoding : chunked\r\n",
		"X: a\r\n folded\r\n",
	}
	var out []string
	for _, line := range lines {
		for _, framing := range framings {
			out = append(out, line+"\r\n"+framing+"\r\n")
		}
	}
	return out
}

type parsedRequest struct {
	method, target, proto string
	kind                  BodyKind
	length                int64
}

func httpxRequest(raw string) (parsedRequest, bool) {
	var req Request
	if err := NewHeadReader(bufio.NewReader(strings.NewReader(raw))).ReadRequest(&req); err != nil {
		return parsedRequest{}, false
	}
	framing, err := RequestFraming(&req)
	if err != nil {
		return parsedRequest{}, false
	}
	return parsedRequest{req.Method, req.Target, req.Proto, framing.Kind, framing.Length}, true
}

func netRequest(raw string) (parsedRequest, bool) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return parsedRequest{}, false
	}
	p := parsedRequest{method: req.Method, target: req.RequestURI, proto: req.Proto}
	switch {
	case len(req.TransferEncoding) == 1 && req.TransferEncoding[0] == "chunked":
		p.kind = BodyChunked
	case len(req.TransferEncoding) > 0:
		p.kind = 255
	case req.ContentLength > 0:
		p.kind, p.length = BodyLength, req.ContentLength
	case req.ContentLength == 0:
		p.kind = BodyNone
	default:
		p.kind = BodyClose
	}
	return p, true
}

func TestDifferentialRequests(t *testing.T) {
	corpus := append(append([]string{}, smuggleSeeds...), generatedRequests()...)
	var agreed, stricter int
	explained := map[string]int{}
	for _, raw := range corpus {
		ours, oursOK := httpxRequest(raw)
		theirs, theirsOK := netRequest(raw)
		switch {
		case !oursOK:
			if theirsOK {
				stricter++
			}
		case !theirsOK || ours != theirs:
			reason := explain(requestDifferences, raw, ours.method)
			if reason == "" {
				t.Errorf("%q: httpx %+v, net/http %+v (accepted %v)", raw, ours, theirs, theirsOK)
				continue
			}
			explained[reason]++
		default:
			agreed++
		}
	}
	t.Logf("%d requests: %d agree, %d rejected by httpx only, deliberate differences %v", len(corpus), agreed, stricter, explained)
}

type parsedResponse struct {
	proto  string
	status int
	kind   BodyKind
	length int64
}

func httpxResponse(raw, method string) (parsedResponse, bool) {
	var resp Response
	if err := NewHeadReader(bufio.NewReader(strings.NewReader(raw))).ReadResponse(&resp); err != nil {
		return parsedResponse{}, false
	}
	framing, err := ResponseFraming(method, &resp)
	if err != nil {
		return parsedResponse{}, false
	}
	return parsedResponse{resp.Proto, resp.StatusCode, framing.Kind, framing.Length}, true
}

func netResponse(raw, method string) (parsedResponse, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), &http.Request{Method: method})
	if err != nil {
		return parsedResponse{}, false
	}
	p := parsedResponse{proto: resp.Proto, status: resp.StatusCode}
	switch {
	case resp.Body == http.NoBody:
		p.kind = BodyNone
	case len(resp.TransferEncoding) == 1 && resp.TransferEncoding[0] == "chunked":
		p.kind = BodyChunked
	case len(resp.TransferEncoding) > 0:
		p.kind = 255
	case resp.ContentLength > 0:
		p.kind, p.length = BodyLength, resp.ContentLength
	case resp.ContentLength == 0:
		p.kind = BodyNone
	default:
		p.kind = BodyClose
	}
	return p, true
}

func TestDifferentialResponses(t *testing.T) {
	corpus := append(append([]string{}, responseSeeds...), generatedResponses()...)
	var agreed, stricter int
	explained := map[string]int{}
	for _, raw := range corpus {
		for _, method := range []string{"GET", "HEAD", "CONNECT"} {
			ours, oursOK := httpxResponse(raw, method)
			theirs, theirsOK := netResponse(raw, method)
			switch {
			case !oursOK:
				if theirsOK {
					stricter++
				}
			case !theirsOK || ours != theirs:
				reason := explain(responseDifferences, raw, method)
				if reason == "" {
					t.Errorf("%s %q: httpx %+v, net/http %+v (accepted %v)", method, raw, ours, theirs, theirsOK)
					continue
				}
				explained[reason]++
			default:
				agreed++
			}
		}
	}
	t.Logf("%d responses x 3 methods: %d agree, %d rejected by httpx only, deliberate differences %v", len(corpus), agreed, stricter, explained)
}
