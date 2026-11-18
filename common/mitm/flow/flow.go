// Package flow describes decrypted HTTP exchanges independently of the HTTP
// version. The h1 and h2 engines report to an Observer; the capture store
// implements it. A nil Observer disables reporting, so callers test it once
// per connection.
package flow

import (
	"io"
	"sync/atomic"
	"time"
)

// Header is one header field. Slices of Header keep wire order and case.
type Header struct {
	Name  string
	Value string
}

// Side selects the request or the response of an exchange.
type Side uint8

const (
	Request Side = iota
	Response
)

func (s Side) String() string {
	if s == Response {
		return "response"
	}
	return "request"
}

// Timing holds the moments of an exchange. A zero time means the moment was
// not reached. The duration fields are zero when the engine cannot tell.
type Timing struct {
	Start           time.Time // request line or first header byte read
	RequestHeaders  time.Time // request head written upstream
	RequestBody     time.Time // request body written upstream
	FirstByte       time.Time // first response byte read
	ResponseHeaders time.Time // response head read
	ResponseBody    time.Time // response body delivered
	End             time.Time // exchange finished
	DNS             time.Duration
	Connect         time.Duration
	TLS             time.Duration
}

// ConnectionInfo describes the connection that carries exchanges. It is
// filled once by the engine and must not change after it was passed to an
// Observer.
type ConnectionInfo struct {
	ID           string
	Source       string
	Destination  string
	Host         string
	Inbound      string
	InboundType  string
	Outbound     string
	OutboundType string
	Rule         string
	ProcessName  string
	ProcessPath  string
	ProcessID    uint32
	User         string
	// Unverified reports that the upstream certificate was not verified.
	Unverified bool

	requests atomic.Uint32
}

// NextRequest returns the 1-based number of the next exchange on the
// connection.
func (c *ConnectionInfo) NextRequest() uint32 { return c.requests.Add(1) }

// RequestHead is the request as received from the client. Headers are copied
// by the receiver.
type RequestHead struct {
	Method    string
	Scheme    string
	Authority string
	Path      string // with query
	Proto     string // "http/1.1" or "h2"
	Headers   []Header
}

// RewriteHit is one rewrite rule that matched an exchange. Kind is "url",
// "header", "map_local", "connect", "body" or "script"; Side is "request" or "response" for
// header rules.
type RewriteHit struct {
	Kind    string
	Rule    string
	Action  string
	Side    string
	Target  string
	Status  int
	Changes []RewriteChange
	// Run is set for Kind "script": the details of the script run.
	Run *ScriptRun
}

// ScriptRun describes one script run in a RewriteHit of Kind "script". Rule and Target of the
// hit are the script's tag; Action is modify, respond, abort, none, error, timeout, limit,
// paused or skipped.
type ScriptRun struct {
	// Phase is "http-request" or "http-response".
	Phase    string
	Duration time.Duration
	// Error is the message of an error, timeout or limit hit.
	Error string
	// Reason is why a script was skipped (stream, size, timeout, busy, encoding, decode,
	// decoded-size) or paused.
	Reason string
	Logs   []ScriptLog
}

// ScriptLog is one console line of a script run.
type ScriptLog struct {
	Level   string // log, info, warn, error
	Message string
}

// RewriteChange is one header operation that changed a message.
type RewriteChange struct {
	Op        string
	Name      string
	Before    string
	HadBefore bool
	After     string
	HasAfter  bool
}

// Observer creates one Exchange per request.
type Observer interface {
	NewExchange(conn *ConnectionInfo) Exchange
}

// Body observes the bytes of one message body. It never changes what is
// forwarded: the wrappers return the same data, and the observer copies what
// it keeps.
type Body interface {
	// Reader returns r observing the bytes read from it. Reaching EOF or an
	// error ends the body.
	Reader(r io.Reader) io.Reader
	// Writer returns w observing the bytes written to it.
	Writer(w io.Writer) io.Writer
	// Write observes p when wrapping is inconvenient. p is not retained.
	Write(p []byte)
	// Done ends the body. Calling it more than once is allowed.
	Done()
}

// Exchange follows one request and its response. Methods may be called from
// the goroutines that carry the request and the response, never concurrently
// for the same Side. A nil Exchange is not valid; callers keep the Observer
// nil instead.
type Exchange interface {
	RequestHead(head RequestHead)
	RequestBody() Body
	// Informational reports a 1xx response other than 101.
	Informational(code int, headers []Header)
	ResponseHead(status int, headers []Header)
	ResponseBody() Body
	Trailers(side Side, headers []Header)
	// Mark records a moment; DNS, connect and TLS durations use SetDurations.
	Mark(point Point, at time.Time)
	SetDurations(dns, connect, tls time.Duration)
	// Upgrade reports a switch of protocol (101): bytes after it are not
	// captured.
	Upgrade(status int, headers []Header)
	// Rewritten reports the rewrite rules that changed the exchange. Hits
	// accumulate in call order. RequestHead is called with the rewritten
	// head, so the recorded request is what was sent upstream.
	Rewritten(hits []RewriteHit)
	// Finish ends the exchange. err is nil on success.
	Finish(err error)
}

// Point names a moment of Timing.
type Point uint8

const (
	PointStart Point = iota
	PointRequestHeaders
	PointRequestBody
	PointFirstByte
	PointResponseHeaders
	PointResponseBody
	PointEnd
)

// NopExchange is an Exchange that ignores everything.
type NopExchange struct{}

func (NopExchange) RequestHead(RequestHead)            {}
func (NopExchange) RequestBody() Body                  { return NopBody{} }
func (NopExchange) Informational(int, []Header)        {}
func (NopExchange) ResponseHead(int, []Header)         {}
func (NopExchange) ResponseBody() Body                 { return NopBody{} }
func (NopExchange) Trailers(Side, []Header)            {}
func (NopExchange) Mark(Point, time.Time)              {}
func (NopExchange) SetDurations(_, _, _ time.Duration) {}
func (NopExchange) Upgrade(int, []Header)              {}
func (NopExchange) Rewritten([]RewriteHit)             {}
func (NopExchange) Finish(error)                       {}

// NopBody is a Body that passes streams through unobserved.
type NopBody struct{}

func (NopBody) Reader(r io.Reader) io.Reader { return r }
func (NopBody) Writer(w io.Writer) io.Writer { return w }
func (NopBody) Write([]byte)                 {}
func (NopBody) Done()                        {}
