package h2

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/httpx"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

// chromeHeaderOrder is the order in which Chrome sends request header fields
// (navigation and fetch requests merged), after the pseudo-header fields.
// net/http hands the relay a map, so the client's own order is gone; fields
// the list does not name follow `accept` in name order, which keeps a request
// deterministic.
var chromeHeaderOrder = []string{
	"content-length",
	"pragma",
	"cache-control",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"upgrade-insecure-requests",
	"user-agent",
	"content-type",
	"accept",
	// unnamed fields rank here
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"cookie",
	"priority",
}

const chromeUnnamedRank = 10

var chromeRank = func() map[string]int {
	m := make(map[string]int, len(chromeHeaderOrder))
	for i, name := range chromeHeaderOrder {
		if i >= chromeUnnamedRank {
			m[name] = i + 1
		} else {
			m[name] = i
		}
	}
	return m
}()

func chromeFieldRank(name string) int {
	if rank, ok := chromeRank[name]; ok {
		return rank
	}
	if strings.HasPrefix(name, "sec-ch-") {
		return chromeRank["sec-ch-ua-platform"]
	}
	return chromeUnnamedRank
}

// chromeRequestFields builds the header block fields of req in Chrome's order:
// :method, :authority, :scheme, :path, then the regular fields. A cookie
// header is split into one field per cookie like Chrome does.
func chromeRequestFields(req *http.Request) ([]hpack.HeaderField, error) {
	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	if !httpguts.ValidHostHeader(authority) {
		return nil, fmt.Errorf("http2: invalid Host header %q", authority)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if !httpguts.ValidHeaderFieldName(method) {
		return nil, fmt.Errorf("http2: invalid method %q", method)
	}
	if req.URL == nil {
		return nil, fmt.Errorf("http2: request without URL")
	}
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	fields := make([]hpack.HeaderField, 0, 8+len(req.Header))
	fields = append(fields, hpack.HeaderField{Name: ":method", Value: method})
	if method == http.MethodConnect {
		fields = append(fields, hpack.HeaderField{Name: ":authority", Value: authority})
	} else {
		path := req.URL.RequestURI()
		if path == "" {
			path = "/"
		}
		fields = append(fields,
			hpack.HeaderField{Name: ":authority", Value: authority},
			hpack.HeaderField{Name: ":scheme", Value: scheme},
			hpack.HeaderField{Name: ":path", Value: path},
		)
	}

	hasBody := req.Body != nil && req.Body != http.NoBody
	var regular []hpack.HeaderField
	for key, values := range req.Header {
		name := strings.ToLower(key)
		if !httpguts.ValidHeaderFieldName(key) {
			return nil, fmt.Errorf("http2: invalid header field name %q", key)
		}
		switch name {
		case "host", "content-length", "connection", "proxy-connection", "transfer-encoding",
			"upgrade", "keep-alive", "trailer":
			continue
		case "te":
			// Only "trailers" is allowed (gRPC).
			if !trailersOnly(values) {
				continue
			}
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("http2: invalid header field value for %q", key)
			}
			switch name {
			case "user-agent":
				if value == "" {
					// The relay marks "no User-Agent" with an empty one.
					continue
				}
			case "cookie":
				for _, crumb := range strings.Split(value, "; ") {
					regular = append(regular, hpack.HeaderField{Name: name, Value: crumb})
				}
				continue
			}
			regular = append(regular, hpack.HeaderField{Name: name, Value: value})
		}
	}
	if keys := allowedTrailerKeys(req.Trailer); len(keys) > 0 {
		// Declares the trailer fields (the origin ignores undeclared ones).
		for i, key := range keys {
			keys[i] = http.CanonicalHeaderKey(key)
		}
		sort.Strings(keys)
		regular = append(regular, hpack.HeaderField{Name: "trailer", Value: strings.Join(keys, ",")})
	}
	switch {
	case hasBody && req.ContentLength > 0:
		regular = append(regular, hpack.HeaderField{Name: "content-length", Value: strconv.FormatInt(req.ContentLength, 10)})
	case !hasBody && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch):
		regular = append(regular, hpack.HeaderField{Name: "content-length", Value: "0"})
	}
	// Equal ranks keep the order in which the map was walked out of the
	// result: sort by name, then by value for repeated names, stably.
	sort.SliceStable(regular, func(i, j int) bool {
		ri, rj := chromeFieldRank(regular[i].Name), chromeFieldRank(regular[j].Name)
		if ri != rj {
			return ri < rj
		}
		return regular[i].Name < regular[j].Name
	})
	return append(fields, regular...), nil
}

func trailersOnly(values []string) bool {
	for _, v := range values {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "trailers") {
				return true
			}
		}
	}
	return false
}

// allowedTrailerKeys lists the trailer fields of a request that may be
// forwarded, as the HTTP/1 path does (httpx.TrailerAllowed).
func allowedTrailerKeys(trailer http.Header) []string {
	var keys []string
	for key := range trailer {
		if httpx.TrailerAllowed(key) {
			keys = append(keys, key)
		}
	}
	return keys
}
