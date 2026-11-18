package httpx

import (
	"errors"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http/httpguts"
)

var (
	ErrMissingHost  = E.New("missing Host")
	ErrMultipleHost = E.New("more than one Host field")
	ErrInvalidHost  = E.New("invalid Host")
)

// RequestErrorStatus returns the status code answering a request whose head or framing was
// rejected with err: 414 for an overlong request line, 431 for a header section over its size
// or field limit, 505 for a major version other than 1, 501 for a transfer coding other than
// chunked (RFC 9112 section 6.1), and 400 for everything else.
func RequestErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrStartLineTooLong):
		return 414
	case errors.Is(err, ErrHeaderTooLarge), errors.Is(err, ErrTooManyFields):
		return 431
	case errors.Is(err, ErrVersion):
		return 505
	case errors.Is(err, ErrUnsupportedTransferEncoding):
		return 501
	default:
		return 400
	}
}

// CheckHost validates the Host field of a request per RFC 9112 section 3.2: an HTTP/1.1
// request must carry exactly one, and no request may carry more than one or an invalid value.
// An empty value is valid (a target without authority). The target is not compared with Host:
// an absolute-form target is forwarded unchanged with its Host, and the origin decides by the
// target's authority (section 3.2.2).
func CheckHost(req *Request) error {
	count := 0
	var host string
	for i := range req.Header {
		if strings.EqualFold(req.Header[i].Name, "Host") {
			count++
			host = req.Header[i].Value
		}
	}
	switch {
	case count > 1:
		return ErrMultipleHost
	case count == 0:
		if req.ProtoAtLeast(1, 1) {
			return ErrMissingHost
		}
		return nil
	}
	if !httpguts.ValidHostHeader(host) || strings.IndexByte(host, ',') >= 0 {
		return ErrInvalidHost
	}
	return nil
}

// UpgradeAccepted reports whether a 101 response switches only to protocols the request
// offered (RFC 9110 section 7.8): its Upgrade list must be non-empty and every protocol in it
// must appear in the request's Upgrade list.
func UpgradeAccepted(request Header, response Header) bool {
	found := false
	for i := range response {
		if !strings.EqualFold(response[i].Name, "Upgrade") {
			continue
		}
		list := response[i].Value
		for list != "" {
			var element string
			element, list, _ = strings.Cut(list, ",")
			element = trimOWS(element)
			if element == "" {
				continue
			}
			if !request.HasToken("Upgrade", element) {
				return false
			}
			found = true
		}
	}
	return found
}

// trailerDenied lists the fields a trailer section must not carry, or that a recipient must
// not merge into the header (RFC 9110 section 6.5.1): framing, routing, request modifiers
// (controls and conditionals), authentication, response control data, content processing, and
// hop-by-hop fields. Cookies are included since they act like authentication.
var trailerDenied = [...]string{
	// framing
	"Content-Length", "Transfer-Encoding", "Trailer",
	// routing
	"Host",
	// hop-by-hop
	"Connection", "Keep-Alive", "Proxy-Connection", "TE", "Upgrade",
	// request modifiers
	"Cache-Control", "Expect", "Max-Forwards", "Pragma", "Range",
	"If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range",
	// authentication
	"Authorization", "Proxy-Authorization", "WWW-Authenticate", "Proxy-Authenticate",
	"Authentication-Info", "Proxy-Authentication-Info", "Cookie", "Set-Cookie",
	// response control data
	"Age", "Date", "Expires", "Location", "Retry-After", "Vary", "Warning",
	// content processing
	"Content-Encoding", "Content-Type", "Content-Range",
}

// TrailerAllowed reports whether a trailer field named name may be forwarded.
func TrailerAllowed(name string) bool {
	for _, denied := range trailerDenied {
		if strings.EqualFold(name, denied) {
			return false
		}
	}
	return true
}

// FilterTrailer removes in place the fields TrailerAllowed rejects and returns the shortened
// trailer section.
func FilterTrailer(h Header) Header {
	return h.filter(func(field *Field) bool { return TrailerAllowed(field.Name) })
}
