package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/script"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http/httpguts"
)

// ScriptHTTPRouter takes the connections of the script $httpClient like any other inbound.
type ScriptHTTPRouter interface {
	RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)
}

// ScriptHTTPOutbounds resolves the outbound tags of the "node" / "policy" option.
type ScriptHTTPOutbounds interface {
	Outbound(tag string) (adapter.Outbound, bool)
}

// scriptHTTPRouteWait is how long a failed request waits for the reason the router gave when
// it closed the connection: the pipe itself only shows that it closed.
const scriptHTTPRouteWait = 500 * time.Millisecond

// scriptHTTPConnectionWait bounds the wait for the router to link its tracked connection.
const scriptHTTPConnectionWait = 300 * time.Millisecond

// scriptHopHeaders are connection-level fields the transport manages itself.
var scriptHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"content-length":      true,
}

// ScriptHTTPClient returns the $httpClient implementation of the script runtime. Requests go
// through the router as internal connections (inbound "kiko-script", user = the script tag):
// they show up in the connection list, follow the route rules or the named outbound, are never
// decrypted and never run scripts. Every dial, so the first request and each redirect hop,
// is checked against the target restrictions (see ScriptAddressRefused); the exchanges are
// recorded into the capture manager while it is enabled.
func (e *Engine) ScriptHTTPClient(router ScriptHTTPRouter, outbounds ScriptHTTPOutbounds) script.HTTPClient {
	return &scriptHTTPClient{engine: e, router: router, outbounds: outbounds}
}

type scriptHTTPClient struct {
	engine    *Engine
	router    ScriptHTTPRouter
	outbounds ScriptHTTPOutbounds
}

// scriptRefusal is the error of a target the restrictions refuse.
type scriptRefusal struct{ reason string }

func (r *scriptRefusal) Error() string { return "refused: " + r.reason }

type scriptDial struct {
	host     string
	metadata adapter.InboundContext
	state    *adapter.MITMState
	done     chan error
}

type scriptHTTPRun struct {
	client   *scriptHTTPClient
	req      *script.HTTPRequest
	routeCtx context.Context
	record   bool

	mu    sync.Mutex
	pipes []net.Conn
	last  *scriptDial
	// routeErr is the last error the router reported.
	routeErr error
}

func (c *scriptHTTPClient) Do(ctx context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
	if c.router == nil {
		return nil, errors.New("not available")
	}
	target, err := url.Parse(req.URL)
	if err != nil {
		return nil, errors.New("invalid url")
	}
	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, errors.New("url scheme must be http or https")
	}
	if target.Hostname() == "" {
		return nil, errors.New("url has no host")
	}
	if target.User != nil {
		return nil, &scriptRefusal{"url must not carry credentials"}
	}
	if reason := c.engine.scriptHostRefused(target.Hostname()); reason != "" {
		return nil, &scriptRefusal{reason}
	}
	if req.Outbound != "" && c.outbounds != nil {
		if _, loaded := c.outbounds.Outbound(req.Outbound); !loaded {
			return nil, errors.New("outbound not found")
		}
	}
	timeout := req.Timeout
	switch {
	case timeout <= 0:
		timeout = script.DefaultHTTPTimeout
	case timeout > script.MaxHTTPTimeout:
		timeout = script.MaxHTTPTimeout
	}
	limit := req.MaxResponse
	if limit <= 0 || limit > script.MaxHTTPResponse {
		limit = script.MaxHTTPResponse
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	routeCtx, routeCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer routeCancel()
	run := &scriptHTTPRun{
		client:   c,
		req:      req,
		routeCtx: routeCtx,
		record:   c.engine.capture != nil && c.engine.capture.Options().Enabled,
	}
	defer run.closePipes()
	transport := &http.Transport{
		DialContext:         run.dial,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: req.Insecure},
	}
	defer transport.CloseIdleConnections()
	var roundTripper http.RoundTripper = transport
	if run.record {
		roundTripper = &scriptRecorder{run: run, inner: transport}
	}
	httpClient := &http.Client{
		Transport: roundTripper,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if req.NoRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) > script.MaxHTTPRedirects {
				return errors.New("stopped after " + strconv.Itoa(script.MaxHTTPRedirects) + " redirects")
			}
			if next.URL.User != nil {
				return &scriptRefusal{"url must not carry credentials"}
			}
			if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
				return errors.New("redirect to unsupported scheme " + next.URL.Scheme)
			}
			if reason := c.engine.scriptHostRefused(next.URL.Hostname()); reason != "" {
				return &scriptRefusal{reason}
			}
			return nil
		},
	}
	httpRequest, err := newScriptRequest(ctx, req, target)
	if err != nil {
		return nil, err
	}
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, run.explain(ctx, err)
	}
	defer response.Body.Close()
	// HEAD, 1xx, 204 and 304 carry no body whatever Content-Length says.
	bodyless := httpRequest.Method == http.MethodHead || response.StatusCode < 200 || response.StatusCode == 204 || response.StatusCode == 304
	if bodyless {
		return &script.HTTPResponse{Status: response.StatusCode, Headers: scriptResponseHeaders(response.Header)}, nil
	}
	if response.ContentLength > limit {
		return nil, errors.New("response body larger than " + strconv.FormatInt(limit, 10))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, run.explain(ctx, err)
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response body larger than " + strconv.FormatInt(limit, 10))
	}
	return &script.HTTPResponse{Status: response.StatusCode, Headers: scriptResponseHeaders(response.Header), Body: body}, nil
}

func newScriptRequest(ctx context.Context, req *script.HTTPRequest, target *url.URL) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !httpguts.ValidHeaderFieldName(method) || method == http.MethodConnect {
		return nil, errors.New("invalid method")
	}
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, errors.New("invalid url")
	}
	hasAgent := false
	for _, header := range req.Headers {
		if !httpguts.ValidHeaderFieldName(header.Name) || !httpguts.ValidHeaderFieldValue(header.Value) {
			return nil, errors.New("invalid header: " + header.Name)
		}
		lower := strings.ToLower(header.Name)
		if scriptHopHeaders[lower] {
			continue
		}
		if lower == "host" {
			// Only the Host header changes; the dial target stays the URL's.
			request.Host = header.Value
			continue
		}
		if lower == "user-agent" {
			hasAgent = true
		}
		request.Header.Add(header.Name, header.Value)
	}
	if !hasAgent {
		// An empty value keeps the transport from adding its own agent.
		request.Header["User-Agent"] = []string{""}
	}
	return request, nil
}

func scriptResponseHeaders(header http.Header) []script.Header {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	var result []script.Header
	for _, name := range names {
		for _, value := range header[name] {
			result = append(result, script.Header{Name: name, Value: value})
		}
	}
	return result
}

// dial opens one routed connection. The transport dials once per request (keep-alive is off),
// so each redirect hop passes the target check here again.
func (r *scriptHTTPRun) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, reason := r.client.engine.scriptTargetRefused(address)
	if reason != "" {
		return nil, &scriptRefusal{reason}
	}
	destination := M.ParseSocksaddrHostPort(host, port)
	state := adapter.NewMITMState(adapter.MITMStatusSkipped, "script")
	dial := &scriptDial{
		host:  host,
		state: state,
		done:  make(chan error, 1),
		metadata: adapter.InboundContext{
			Inbound:        adapter.InboundKikoScript,
			InboundType:    adapter.InboundKikoInternal,
			Internal:       true,
			Network:        N.NetworkTCP,
			Source:         M.SocksaddrFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0),
			Destination:    destination,
			User:           r.req.Script,
			ForcedOutbound: r.req.Outbound,
			MITM:           state,
			ScriptClient:   true,
		},
	}
	if destination.IsFqdn() {
		dial.metadata.Domain = host
	}
	client, server := net.Pipe()
	r.mu.Lock()
	r.pipes = append(r.pipes, client)
	r.last = dial
	r.mu.Unlock()
	go r.client.router.RouteConnectionEx(r.routeCtx, server, dial.metadata, func(err error) {
		if err != nil {
			r.mu.Lock()
			r.routeErr = err
			r.mu.Unlock()
		}
		select {
		case dial.done <- err:
		default:
		}
	})
	return client, nil
}

func (r *scriptHTTPRun) closePipes() {
	r.mu.Lock()
	pipes := r.pipes
	r.pipes = nil
	r.mu.Unlock()
	for _, pipe := range pipes {
		_ = pipe.Close()
	}
}

func (r *scriptHTTPRun) lastDial() *scriptDial {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// explain gives the reason of a failed request: the timeout, a refusal (the target check or
// the router's own after-dial check), or the error as the transport reported it.
func (r *scriptHTTPRun) explain(ctx context.Context, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var refusal *scriptRefusal
	if errors.As(err, &refusal) {
		return refusal
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("timeout")
	}
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return errors.New("canceled")
	}
	if dial := r.lastDial(); dial != nil && isPipeClosed(err) {
		r.mu.Lock()
		routeErr := r.routeErr
		r.mu.Unlock()
		if routeErr == nil {
			select {
			case routeErr = <-dial.done:
			case <-time.After(scriptHTTPRouteWait):
			}
		}
		if routeErr != nil {
			text := routeErr.Error()
			if index := strings.Index(text, "refused: "); index >= 0 {
				return errors.New(text[index:])
			}
			return routeErr
		}
	}
	return err
}

func isPipeClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(err.Error(), "closed pipe") || strings.Contains(err.Error(), "EOF") ||
		strings.Contains(err.Error(), "server closed idle connection")
}

// connectionInfo describes the connection of the exchange being recorded.
func (r *scriptHTTPRun) connectionInfo(target *url.URL, wait bool) *flow.ConnectionInfo {
	info := &flow.ConnectionInfo{
		Inbound:     adapter.InboundKikoScript,
		InboundType: adapter.InboundKikoInternal,
		Outbound:    r.req.Outbound,
		User:        r.req.Script,
		Host:        target.Hostname(),
		Unverified:  r.req.Insecure && target.Scheme == "https",
	}
	if r.req.Outbound != "" && r.client.outbounds != nil {
		if outbound, loaded := r.client.outbounds.Outbound(r.req.Outbound); loaded {
			info.OutboundType = outbound.Type()
		}
	}
	dial := r.lastDial()
	if dial == nil {
		return info
	}
	info.Source = dial.metadata.Source.String()
	info.Destination = dial.metadata.Destination.String()
	deadline := time.Now().Add(scriptHTTPConnectionWait)
	for wait && dial.state.Connection().ID == "" && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	linked := dial.state.Connection()
	info.ID, info.Rule = linked.ID, linked.Rule
	return info
}

// scriptRecorder records every round trip, so each redirect hop, as an exchange of the
// capture manager.
type scriptRecorder struct {
	run   *scriptHTTPRun
	inner http.RoundTripper
}

type scriptHop struct {
	run      *scriptHTTPRun
	exchange flow.Exchange
	body     flow.Body
	start    time.Time
	proto    string
	finished atomic.Bool
	response *http.Response
	times    struct {
		sync.Mutex
		gotConn, wroteHeaders, wroteRequest, firstByte, tlsStart, tlsDone time.Time
	}
}

func (t *scriptRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	hop := &scriptHop{run: t.run, start: time.Now()}
	var requestBody []byte
	if request.ContentLength > 0 && request.GetBody != nil {
		if copyBody, err := request.GetBody(); err == nil {
			requestBody, _ = io.ReadAll(copyBody)
			_ = copyBody.Close()
		}
	}
	trace := &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { hop.mark(&hop.times.gotConn) },
		WroteHeaders:         func() { hop.mark(&hop.times.wroteHeaders) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { hop.mark(&hop.times.wroteRequest) },
		GotFirstResponseByte: func() { hop.mark(&hop.times.firstByte) },
		TLSHandshakeStart:    func() { hop.mark(&hop.times.tlsStart) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { hop.mark(&hop.times.tlsDone) },
	}
	response, err := t.inner.RoundTrip(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
	hop.proto = "http/1.1"
	if response != nil && response.ProtoMajor == 2 {
		hop.proto = "h2"
	}
	info := t.run.connectionInfo(request.URL, err == nil)
	hop.exchange = t.run.client.engine.capture.NewExchange(info)
	hop.recordRequest(request, requestBody)
	if err != nil {
		hop.exchange.Finish(t.run.explain(request.Context(), err))
		return nil, err
	}
	hop.exchange.ResponseHead(response.StatusCode, responseFlowHeaders(response.Header))
	hop.exchange.Mark(flow.PointResponseHeaders, time.Now())
	hop.body = hop.exchange.ResponseBody()
	hop.response = response
	response.Body = &scriptBody{hop: hop, closer: response.Body, reader: hop.body.Reader(response.Body)}
	return response, nil
}

func (h *scriptHop) mark(at *time.Time) {
	now := time.Now()
	h.times.Lock()
	if at.IsZero() {
		*at = now
	}
	h.times.Unlock()
}

func (h *scriptHop) recordRequest(request *http.Request, body []byte) {
	exchange := h.exchange
	authority := request.URL.Host
	hostHeader := authority
	if request.Host != "" {
		hostHeader = request.Host
	}
	headers := make([]flow.Header, 0, len(request.Header)+2)
	headers = append(headers, flow.Header{Name: "Host", Value: hostHeader})
	for _, header := range responseFlowHeaders(request.Header) {
		if header.Name == "User-Agent" && header.Value == "" {
			continue
		}
		headers = append(headers, header)
	}
	if len(body) > 0 {
		headers = append(headers, flow.Header{Name: "Content-Length", Value: strconv.Itoa(len(body))})
	}
	exchange.RequestHead(flow.RequestHead{
		Method:    request.Method,
		Scheme:    request.URL.Scheme,
		Authority: authority,
		Path:      request.URL.RequestURI(),
		Proto:     h.proto,
		Headers:   headers,
	})
	if len(body) > 0 {
		requestBody := exchange.RequestBody()
		requestBody.Write(body)
		requestBody.Done()
	}
	h.times.Lock()
	gotConn, wroteHeaders, wroteRequest, firstByte := h.times.gotConn, h.times.wroteHeaders, h.times.wroteRequest, h.times.firstByte
	tlsStart, tlsDone := h.times.tlsStart, h.times.tlsDone
	h.times.Unlock()
	start := h.start
	if !gotConn.IsZero() {
		start = gotConn
	}
	exchange.Mark(flow.PointStart, start)
	markIfSet(exchange, flow.PointRequestHeaders, wroteHeaders)
	markIfSet(exchange, flow.PointRequestBody, wroteRequest)
	markIfSet(exchange, flow.PointFirstByte, firstByte)
	var connect, tlsTime time.Duration
	if dial := h.run.lastDial(); dial != nil {
		connect = dial.state.ConnectDuration()
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		tlsTime = tlsDone.Sub(tlsStart) - connect
	}
	exchange.SetDurations(0, max(connect, 0), max(tlsTime, 0))
}

func markIfSet(exchange flow.Exchange, point flow.Point, at time.Time) {
	if !at.IsZero() {
		exchange.Mark(point, at)
	}
}

func (h *scriptHop) finish(err error) {
	if !h.finished.CompareAndSwap(false, true) {
		return
	}
	h.body.Done()
	if err == nil && h.response != nil && len(h.response.Trailer) > 0 {
		h.exchange.Trailers(flow.Response, responseFlowHeaders(h.response.Trailer))
	}
	h.exchange.Mark(flow.PointResponseBody, time.Now())
	h.exchange.Finish(err)
}

// scriptBody ends the recorded exchange when the body is read to its end, fails or is closed.
type scriptBody struct {
	hop    *scriptHop
	closer io.Closer
	reader io.Reader
}

func (b *scriptBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.hop.finish(nil)
	} else if err != nil {
		b.hop.finish(err)
	}
	return n, err
}

func (b *scriptBody) Close() error {
	err := b.closer.Close()
	b.hop.finish(errors.New("canceled"))
	return err
}

func responseFlowHeaders(header http.Header) []flow.Header {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	var result []flow.Header
	for _, name := range names {
		for _, value := range header[name] {
			result = append(result, flow.Header{Name: name, Value: value})
		}
	}
	return result
}
