package script

import (
	"context"
	"time"
)

// HTTPRequest is one $httpClient call after the runtime validated it. The host performs it
// through the core's router (so it shows up in the connection list) and enforces the target
// restrictions.
type HTTPRequest struct {
	// Script is the tag of the calling script.
	Script string
	Phase  Phase
	// Method is upper case: GET POST PUT DELETE HEAD OPTIONS PATCH.
	Method string
	// URL is absolute, http or https, without credentials.
	URL     string
	Headers []Header
	Body    []byte
	// Timeout bounds the whole request including redirects.
	Timeout time.Duration
	// Outbound names the outbound to use ("node" / "policy" option); empty follows the rules.
	Outbound string
	// Insecure skips TLS certificate verification.
	Insecure bool
	// NoRedirect disables following redirects (default: follow up to MaxHTTPRedirects).
	NoRedirect bool
	// MaxResponse is the largest response body the host may return; a larger one is an error.
	MaxResponse int64
}

// HTTPResponse is the answer to an HTTPRequest. Headers keep repeated fields apart.
type HTTPResponse struct {
	Status  int
	Headers []Header
	Body    []byte
}

// HTTPClient performs $httpClient requests. The error text goes to the script's callback.
type HTTPClient interface {
	Do(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error)
}

// $httpClient limits.
const (
	// MaxHTTPRequests is the most requests one script call may start.
	MaxHTTPRequests = 16
	// MaxHTTPInflight is the most requests of one call in flight at once.
	MaxHTTPInflight = 4
	// MaxHTTPRequestBody and MaxHTTPResponse bound one request body and one response body.
	MaxHTTPRequestBody = 8 << 20
	MaxHTTPResponse    = 8 << 20
	// DefaultHTTPTimeout applies when the script gives none; MaxHTTPTimeout caps it.
	DefaultHTTPTimeout = 10 * time.Second
	MaxHTTPTimeout     = 60 * time.Second
	// MaxHTTPRedirects is the redirect limit of a request.
	MaxHTTPRedirects = 10
)
