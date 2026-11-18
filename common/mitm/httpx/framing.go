package httpx

import (
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http/httpguts"
)

// BodyKind is how a message body is delimited.
type BodyKind uint8

const (
	// BodyNone means the message has no body.
	BodyNone BodyKind = iota
	// BodyLength means the body is Framing.Length bytes long.
	BodyLength
	// BodyChunked means the body uses the chunked transfer coding.
	BodyChunked
	// BodyClose means the body runs until the connection closes (responses only).
	BodyClose
)

// Framing is the body framing decision for one message.
type Framing struct {
	Kind   BodyKind
	Length int64
	// Codings are the transfer codings to keep declaring: for BodyChunked those before the
	// final chunked; for BodyClose the original list forwarded verbatim; empty otherwise.
	Codings string
}

var (
	ErrContentLengthWithTransferEncoding = E.New("both Content-Length and Transfer-Encoding")
	ErrInvalidContentLength              = E.New("invalid Content-Length")
	ErrUnsupportedTransferEncoding       = E.New("unsupported Transfer-Encoding")
	ErrInvalidTransferEncoding           = E.New("invalid Transfer-Encoding")
	ErrTransferEncodingHTTP10            = E.New("Transfer-Encoding in an HTTP/1.0 message")
	ErrConnectBody                       = E.New("CONNECT request with content")
)

// RequestFraming decides the request body framing per RFC 9112 section 6. A request carrying
// both Content-Length and Transfer-Encoding is rejected (section 6.1 allows it to be processed,
// but it is the classic smuggling vector), and so is Transfer-Encoding below HTTP/1.1 (faulty
// framing, section 6.1). A Transfer-Encoding list that is empty, malformed, applies chunked
// more than once or does not end in chunked is ErrInvalidTransferEncoding (400, section 6.3);
// chunked preceded by other codings is ErrUnsupportedTransferEncoding (501): a body is always
// re-framed when forwarded and other codings are not kept on requests. Several Content-Length
// values are accepted only when identical. A CONNECT request with content is ErrConnectBody:
// such content has no defined semantics (RFC 9110 section 9.3.6) and the bytes after the head
// belong to the tunnel.
func RequestFraming(req *Request) (Framing, error) {
	hasTE := req.Header.Has("Transfer-Encoding")
	hasCL := req.Header.Has("Content-Length")
	if hasTE && !req.ProtoAtLeast(1, 1) {
		return Framing{}, ErrTransferEncodingHTTP10
	}
	if hasTE && hasCL {
		return Framing{}, ErrContentLengthWithTransferEncoding
	}
	if hasTE {
		chunkedLast, chunked, others, err := transferCodings(req.Header)
		if err != nil {
			return Framing{}, err
		}
		if !chunkedLast {
			return Framing{}, E.Cause(ErrInvalidTransferEncoding, "chunked is not the final coding")
		}
		if chunked > 1 {
			return Framing{}, E.Cause(ErrInvalidTransferEncoding, "chunked applied more than once")
		}
		if others {
			return Framing{}, ErrUnsupportedTransferEncoding
		}
		if req.Method == "CONNECT" {
			return Framing{}, ErrConnectBody
		}
		return Framing{Kind: BodyChunked}, nil
	}
	if hasCL {
		length, err := ContentLength(req.Header)
		if err != nil {
			return Framing{}, err
		}
		if length == 0 {
			return Framing{Kind: BodyNone}, nil
		}
		if req.Method == "CONNECT" {
			return Framing{}, ErrConnectBody
		}
		return Framing{Kind: BodyLength, Length: length}, nil
	}
	return Framing{Kind: BodyNone}, nil
}

// ResponseHasBody reports whether a response with the given status to a request with the given
// method can have content (RFC 9112 section 6.3, rules 1 and 2): not for HEAD, 1xx, 204, 304 or
// a 2xx answer to CONNECT.
func ResponseHasBody(method string, code int) bool {
	return method != "HEAD" && code >= 200 && code != 204 && code != 304 &&
		!(method == "CONNECT" && code < 300)
}

// ResponseFraming decides the response body framing per RFC 9112 section 6.3 for a response to
// a request with the given method. Responses to HEAD and 1xx, 204 and 304 responses have no body;
// a 2xx response to CONNECT switches the connection to a tunnel right after its header block,
// so it has no body whatever its Content-Length or Transfer-Encoding say. Transfer-Encoding
// takes precedence over Content-Length:
//   - final coding chunked: BodyChunked, Codings holds the codings before it ("gzip" for
//     "gzip, chunked"), which stay applied to the decoded data;
//   - final coding not chunked: BodyClose with the list in Codings, forwarded verbatim;
//   - in an HTTP/1.0 response: faulty framing (section 6.1), BodyClose with the list in Codings.
//
// A list that is empty or malformed, or that ends in chunked applied more than once, is
// ErrInvalidTransferEncoding. An invalid Content-Length is an error also when the response has
// no body. Otherwise the body is delimited by Content-Length or by close.
func ResponseFraming(method string, resp *Response) (Framing, error) {
	if !ResponseHasBody(method, resp.StatusCode) {
		// The field is forwarded, so it must still be valid (RFC 9110 section 8.6). Beside
		// Transfer-Encoding it is overridden (RFC 9112 section 6.3) and the relay drops it.
		if resp.Header.Has("Content-Length") && !resp.Header.Has("Transfer-Encoding") {
			if _, err := ContentLength(resp.Header); err != nil {
				return Framing{}, err
			}
		}
		return Framing{Kind: BodyNone}, nil
	}
	if resp.Header.Has("Transfer-Encoding") {
		if !resp.ProtoAtLeast(1, 1) {
			return Framing{Kind: BodyClose, Codings: joinValues(resp.Header, "Transfer-Encoding")}, nil
		}
		chunkedLast, chunked, others, err := transferCodings(resp.Header)
		if err != nil {
			return Framing{}, err
		}
		if !chunkedLast {
			return Framing{Kind: BodyClose, Codings: joinValues(resp.Header, "Transfer-Encoding")}, nil
		}
		if chunked > 1 {
			return Framing{}, E.Cause(ErrInvalidTransferEncoding, "chunked applied more than once")
		}
		framing := Framing{Kind: BodyChunked}
		if others {
			framing.Codings = codingsBeforeChunked(resp.Header)
		}
		return framing, nil
	}
	if resp.Header.Has("Content-Length") {
		length, err := ContentLength(resp.Header)
		if err != nil {
			return Framing{}, err
		}
		if length == 0 {
			return Framing{Kind: BodyNone}, nil
		}
		return Framing{Kind: BodyLength, Length: length}, nil
	}
	return Framing{Kind: BodyClose}, nil
}

// transferCodings walks the Transfer-Encoding fields as one list (RFC 9110 section 5.3) and
// reports whether chunked is the final coding, how often chunked appears, and whether other
// codings appear. Every element must be a token, optionally with parameters (chunked takes
// none), and the list must not be empty.
func transferCodings(h Header) (chunkedLast bool, chunked int, others bool, err error) {
	count := 0
	for i := range h {
		if !strings.EqualFold(h[i].Name, "Transfer-Encoding") {
			continue
		}
		list := h[i].Value
		for list != "" {
			var element string
			element, list, _ = strings.Cut(list, ",")
			element = trimOWS(element)
			if element == "" {
				continue
			}
			name, _, _ := strings.Cut(element, ";")
			name = trimOWS(name)
			if !validToken(name) {
				return false, 0, false, E.Cause(ErrInvalidTransferEncoding, "coding")
			}
			switch {
			case strings.EqualFold(element, "chunked"):
				chunked++
				chunkedLast = true
			case strings.EqualFold(name, "chunked"):
				return false, 0, false, E.Cause(ErrInvalidTransferEncoding, "chunked with parameters")
			default:
				others = true
				chunkedLast = false
			}
			count++
		}
	}
	if count == 0 {
		return false, 0, false, E.Cause(ErrInvalidTransferEncoding, "empty list")
	}
	return chunkedLast, chunked, others, nil
}

// codingsBeforeChunked returns the Transfer-Encoding list without its final chunked element,
// elements separated by ", ".
func codingsBeforeChunked(h Header) string {
	var b strings.Builder
	for i := range h {
		if !strings.EqualFold(h[i].Name, "Transfer-Encoding") {
			continue
		}
		list := h[i].Value
		for list != "" {
			var element string
			element, list, _ = strings.Cut(list, ",")
			element = trimOWS(element)
			if element == "" || strings.EqualFold(element, "chunked") {
				continue
			}
			if b.Len() > 0 {
				b.WriteString(", ")
			}
			b.WriteString(element)
		}
	}
	return b.String()
}

// joinValues returns the values of every field named name joined by ", ", without allocating
// for a single field.
func joinValues(h Header, name string) string {
	var joined string
	for i := range h {
		if !strings.EqualFold(h[i].Name, name) {
			continue
		}
		if joined == "" {
			joined = h[i].Value
		} else if h[i].Value != "" {
			joined += ", " + h[i].Value
		}
	}
	return joined
}

func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !httpguts.IsTokenRune(rune(s[i])) {
			return false
		}
	}
	return true
}

// ContentLength parses every Content-Length field (each possibly a comma-separated list) and
// returns the value when all are identical non-negative decimals.
func ContentLength(h Header) (int64, error) {
	var (
		length int64 = -1
		found  bool
	)
	for i := range h {
		if !strings.EqualFold(h[i].Name, "Content-Length") {
			continue
		}
		list := h[i].Value
		if trimOWS(list) == "" {
			return 0, ErrInvalidContentLength
		}
		for list != "" {
			var element string
			element, list, _ = strings.Cut(list, ",")
			value, ok := parseDecimal(trimOWS(element))
			if !ok || found && value != length {
				return 0, ErrInvalidContentLength
			}
			length, found = value, true
		}
	}
	if !found {
		return 0, ErrInvalidContentLength
	}
	return length, nil
}

func parseDecimal(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var value int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		value = value*10 + int64(c-'0')
	}
	return value, true
}
