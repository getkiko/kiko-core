package daemon

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
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	replayDefaultTimeout = 30 * time.Second
	replayMaxTimeout     = 120 * time.Second
	replayMaxRequestBody = 8 << 20
	// HTTPReplayMaxMessage is the largest gRPC message the server accepts, so
	// that a request body of the maximum size fits.
	HTTPReplayMaxMessage = replayMaxRequestBody + 1<<20

	replayRouteErrorWait   = 300 * time.Millisecond
	replayConnectionWait   = 500 * time.Millisecond
	replayConnectionPeriod = 2 * time.Millisecond
)

// HTTPReplayTarget is what Replay needs from the running core.
type HTTPReplayTarget struct {
	// Router takes the replayed connections like any other inbound.
	Router interface {
		RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)
	}
	// Outbounds resolves outbound tags.
	Outbounds interface {
		Outbound(tag string) (adapter.Outbound, bool)
	}
	// Connection returns the tracked connection of an id, open or closed.
	Connection func(id string) *trafficcontrol.TrackerMetadata
}

// HTTPReplayProvider is implemented by a HTTPCaptureProvider that can
// replay requests; HTTPReplay returns nil while no core is running.
type HTTPReplayProvider interface {
	HTTPReplay() *HTTPReplayTarget
}

// HTTPReplay returns the replay target of the running core, or nil.
func (s *StartedService) HTTPReplay() *HTTPReplayTarget {
	s.serviceAccess.RLock()
	instance := s.instance
	s.serviceAccess.RUnlock()
	if instance == nil || instance.instance == nil {
		return nil
	}
	target := &HTTPReplayTarget{
		Router:    instance.instance.Router(),
		Outbounds: instance.outboundManager,
	}
	if manager := instance.trafficManager; manager != nil {
		target.Connection = func(id string) *trafficcontrol.TrackerMetadata {
			parsed, err := uuid.FromString(id)
			if err != nil {
				return nil
			}
			if tracker := manager.Connection(parsed); tracker != nil {
				return tracker.Metadata()
			}
			for _, closed := range manager.ClosedConnections() {
				if closed.ID == parsed {
					return closed
				}
			}
			return nil
		}
	}
	if target.Outbounds == nil {
		target.Outbounds = instance.instance.Outbound()
	}
	return target
}

// replayHopHeaders are connection-level fields the transport manages itself.
var replayHopHeaders = map[string]bool{
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

type replayPlan struct {
	method   string
	target   *url.URL
	host     string
	port     uint16
	headers  []flow.Header
	body     []byte
	timeout  time.Duration
	verify   bool
	outbound string
}

func parseReplayRequest(request *mitmapi.ReplayRequest) (*replayPlan, error) {
	plan := &replayPlan{method: strings.TrimSpace(request.Method), verify: request.VerifyTls, outbound: request.Outbound}
	if plan.method == "" {
		plan.method = http.MethodGet
	}
	if !httpguts.ValidHeaderFieldName(plan.method) {
		return nil, status.Error(codes.InvalidArgument, "invalid method")
	}
	plan.method = strings.ToUpper(plan.method)
	if plan.method == http.MethodConnect {
		return nil, status.Error(codes.InvalidArgument, "method not allowed: CONNECT")
	}
	target, err := url.Parse(request.Url)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid url")
	}
	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, status.Error(codes.InvalidArgument, "url scheme must be http or https")
	}
	if target.Hostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "url has no host")
	}
	if target.User != nil {
		return nil, status.Error(codes.InvalidArgument, "url must not carry credentials")
	}
	target.Fragment = ""
	target.User = nil
	plan.target = target
	plan.host = target.Hostname()
	port := target.Port()
	switch {
	case port == "" && target.Scheme == "https":
		plan.port = 443
	case port == "":
		plan.port = 80
	default:
		value, convErr := strconv.ParseUint(port, 10, 16)
		if convErr != nil || value == 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid port")
		}
		plan.port = uint16(value)
	}
	if len(request.Body) > replayMaxRequestBody {
		return nil, status.Error(codes.InvalidArgument, "request body exceeds 8 MB")
	}
	plan.body = request.Body
	for _, header := range request.Headers {
		if header == nil {
			continue
		}
		if !httpguts.ValidHeaderFieldName(header.Name) || !httpguts.ValidHeaderFieldValue(header.Value) {
			return nil, status.Error(codes.InvalidArgument, "invalid header: "+header.Name)
		}
		if replayHopHeaders[strings.ToLower(header.Name)] {
			continue
		}
		plan.headers = append(plan.headers, flow.Header{Name: header.Name, Value: header.Value})
	}
	switch timeout := time.Duration(request.TimeoutMs) * time.Millisecond; {
	case timeout <= 0:
		plan.timeout = replayDefaultTimeout
	case timeout > replayMaxTimeout:
		plan.timeout = replayMaxTimeout
	default:
		plan.timeout = timeout
	}
	return plan, nil
}

// replayConn measures how long the router needs to take the first bytes,
// which is when its outbound is connected.
type replayConn struct {
	net.Conn
	firstWriteDone atomic.Int64
	once           sync.Once
}

func (c *replayConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil {
		c.once.Do(func() { c.firstWriteDone.Store(time.Now().UnixNano()) })
	}
	return n, err
}

func (s *httpCaptureServer) Replay(ctx context.Context, request *mitmapi.ReplayRequest) (*mitmapi.ReplayResponse, error) {
	manager, err := s.manager()
	if err != nil {
		return nil, err
	}
	if !manager.Options().Enabled {
		return nil, status.Error(codes.FailedPrecondition, "HTTP capture is disabled")
	}
	if request.Instance != "" && request.Instance != manager.Instance() {
		return nil, status.Error(codes.FailedPrecondition, "capture instance changed")
	}
	replayer, ok := s.provider.(HTTPReplayProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "replay is not available")
	}
	target := replayer.HTTPReplay()
	if target == nil || target.Router == nil {
		return nil, status.Error(codes.FailedPrecondition, "core is not running")
	}
	plan, err := parseReplayRequest(request)
	if err != nil {
		return nil, err
	}
	if plan.outbound != "" && target.Outbounds != nil {
		if _, loaded := target.Outbounds.Outbound(plan.outbound); !loaded {
			return nil, status.Error(codes.InvalidArgument, "outbound not found: "+plan.outbound)
		}
	}
	run := &replayRun{plan: plan, target: target, manager: manager}
	return run.execute(ctx)
}

type replayRun struct {
	plan    *replayPlan
	target  *HTTPReplayTarget
	manager *capture.Manager

	state     *adapter.MITMState
	metadata  adapter.InboundContext
	routeDone chan error
	dialed    atomic.Bool
	dialStart time.Time
	conn      atomic.Pointer[replayConn]
	// routeCtx belongs to the routed connection and ends with the run, so that
	// a timeout reaches the router.
	routeCtx context.Context

	times struct {
		sync.Mutex
		gotConn, wroteHeaders, wroteRequest, firstByte, tlsStart, tlsDone time.Time
	}
}

func (r *replayRun) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	if old := r.conn.Load(); old != nil {
		_ = old.Close()
	}
	r.dialStart = time.Now()
	r.dialed.Store(true)
	wrapped := &replayConn{Conn: client}
	r.conn.Store(wrapped)
	// The router owns the connection for as long as it lives; the run ends it
	// by closing the client side.
	go r.target.Router.RouteConnectionEx(r.routeCtx, server, r.metadata, func(err error) {
		select {
		case r.routeDone <- err:
		default:
		}
	})
	return wrapped, nil
}

func (r *replayRun) execute(ctx context.Context) (*mitmapi.ReplayResponse, error) {
	plan := r.plan
	ctx, cancel := context.WithTimeout(ctx, plan.timeout)
	defer cancel()
	routeCtx, routeCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer routeCancel()
	r.routeCtx = routeCtx
	r.state = adapter.NewMITMState(adapter.MITMStatusSkipped, "replay")
	r.routeDone = make(chan error, 1)
	destination := M.ParseSocksaddrHostPort(plan.host, plan.port)
	r.metadata = adapter.InboundContext{
		Inbound:        adapter.InboundKikoInternal,
		Internal:       true,
		InboundType:    adapter.InboundKikoInternal,
		Network:        N.NetworkTCP,
		Source:         M.SocksaddrFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0),
		Destination:    destination,
		ForcedOutbound: plan.outbound,
		MITM:           r.state,
	}
	if destination.IsFqdn() {
		r.metadata.Domain = plan.host
	}
	transport := &http.Transport{
		DialContext:         r.dial,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: plan.timeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !plan.verify},
	}
	defer transport.CloseIdleConnections()
	httpRequest, err := plan.newRequest(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	start := time.Now()
	trace := &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { r.mark(&r.times.gotConn) },
		WroteHeaders:         func() { r.mark(&r.times.wroteHeaders) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { r.mark(&r.times.wroteRequest) },
		GotFirstResponseByte: func() { r.mark(&r.times.firstByte) },
		TLSHandshakeStart:    func() { r.mark(&r.times.tlsStart) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { r.mark(&r.times.tlsDone) },
	}
	httpRequest = httpRequest.WithContext(httptrace.WithClientTrace(ctx, trace))
	response, roundTripErr := transport.RoundTrip(httpRequest)
	var (
		exchange flow.Exchange
		finish   error
	)
	if roundTripErr != nil {
		finish = r.explain(ctx, roundTripErr)
		exchange = r.manager.NewExchange(r.connectionInfo())
		r.recordRequest(exchange, start, "http/1.1")
		exchange.Finish(finish)
	} else {
		proto := "http/1.1"
		if response.ProtoMajor == 2 {
			proto = "h2"
		}
		exchange = r.manager.NewExchange(r.connectionInfo())
		r.recordRequest(exchange, start, proto)
		exchange.ResponseHead(response.StatusCode, responseHeaders(response.Header))
		exchange.Mark(flow.PointResponseHeaders, time.Now())
		body := exchange.ResponseBody()
		_, copyErr := io.Copy(io.Discard, body.Reader(response.Body))
		body.Done()
		response.Body.Close()
		if copyErr != nil {
			finish = r.explain(ctx, copyErr)
		}
		if len(response.Trailer) > 0 {
			exchange.Trailers(flow.Response, responseHeaders(response.Trailer))
		}
		exchange.Mark(flow.PointResponseBody, time.Now())
		exchange.Finish(finish)
	}
	if conn := r.conn.Load(); conn != nil {
		conn.Close()
	}
	id := capture.ExchangeID(exchange)
	if id == "" {
		return nil, status.Error(codes.FailedPrecondition, "HTTP capture is disabled")
	}
	record, found := r.manager.Get(id)
	if !found {
		return nil, status.Error(codes.NotFound, "record evicted")
	}
	result := &mitmapi.ReplayResponse{Record: captureRecord(&record)}
	if finish != nil {
		result.Error = finish.Error()
	}
	return result, nil
}

func (r *replayRun) mark(at *time.Time) {
	now := time.Now()
	r.times.Lock()
	if at.IsZero() {
		*at = now
	}
	r.times.Unlock()
}

// explain gives the reason of a failed exchange: the router's own error when
// it reported one, since the pipe only shows that it closed.
func (r *replayRun) explain(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("timeout")
	}
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return errors.New("canceled")
	}
	if r.dialed.Load() {
		select {
		case routeErr := <-r.routeDone:
			if routeErr != nil {
				return routeErr
			}
		case <-time.After(replayRouteErrorWait):
		}
	}
	return err
}

func (p *replayPlan) newRequest(ctx context.Context) (*http.Request, error) {
	var body io.Reader
	if len(p.body) > 0 {
		body = bytes.NewReader(p.body)
	}
	request, err := http.NewRequestWithContext(ctx, p.method, p.target.String(), body)
	if err != nil {
		return nil, err
	}
	hasAgent := false
	for _, header := range p.headers {
		if strings.EqualFold(header.Name, "Host") {
			request.Host = header.Value
			continue
		}
		if strings.EqualFold(header.Name, "User-Agent") {
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

// connectionInfo describes the replay connection after the router tracked it.
func (r *replayRun) connectionInfo() *flow.ConnectionInfo {
	info := &flow.ConnectionInfo{
		Source:      r.metadata.Source.String(),
		Destination: r.metadata.Destination.String(),
		Host:        r.plan.host,
		Inbound:     adapter.InboundKikoInternal,
		InboundType: adapter.InboundKikoInternal,
		Outbound:    r.plan.outbound,
		Unverified:  !r.plan.verify && r.plan.target.Scheme == "https",
	}
	if !r.dialed.Load() {
		return info
	}
	deadline := time.Now().Add(replayConnectionWait)
	for r.state.Connection().ID == "" && time.Now().Before(deadline) {
		select {
		case routeErr := <-r.routeDone:
			r.routeDone <- routeErr
			deadline = time.Now()
		case <-time.After(replayConnectionPeriod):
		}
	}
	linked := r.state.Connection()
	info.ID, info.Rule = linked.ID, linked.Rule
	if linked.ID != "" && r.target.Connection != nil {
		if tracked := r.target.Connection(linked.ID); tracked != nil {
			info.Outbound, info.OutboundType = tracked.Outbound, tracked.OutboundType
			info.User = tracked.Metadata.User
		}
	}
	return info
}

func (r *replayRun) recordRequest(exchange flow.Exchange, start time.Time, proto string) {
	plan := r.plan
	target := plan.target
	path := target.RequestURI()
	authority := target.Host
	hostHeader := authority
	headers := make([]flow.Header, 0, len(plan.headers)+2)
	for _, header := range plan.headers {
		if strings.EqualFold(header.Name, "Host") {
			hostHeader = header.Value
		}
	}
	headers = append(headers, flow.Header{Name: "Host", Value: hostHeader})
	for _, header := range plan.headers {
		if strings.EqualFold(header.Name, "Host") {
			continue
		}
		headers = append(headers, header)
	}
	if len(plan.body) > 0 {
		headers = append(headers, flow.Header{Name: "Content-Length", Value: strconv.Itoa(len(plan.body))})
	}
	exchange.RequestHead(flow.RequestHead{
		Method:    plan.method,
		Scheme:    target.Scheme,
		Authority: authority,
		Path:      path,
		Proto:     proto,
		Headers:   headers,
	})
	if len(plan.body) > 0 {
		requestBody := exchange.RequestBody()
		requestBody.Write(plan.body)
		requestBody.Done()
	}
	r.times.Lock()
	gotConn, wroteHeaders, wroteRequest, firstByte := r.times.gotConn, r.times.wroteHeaders, r.times.wroteRequest, r.times.firstByte
	tlsDone, tlsStart := r.times.tlsDone, r.times.tlsStart
	r.times.Unlock()
	// The exchange starts once the connection is ready, as for decrypted
	// traffic; the setup durations come before it.
	if !gotConn.IsZero() {
		start = gotConn
	}
	exchange.Mark(flow.PointStart, start)
	markIfSet(exchange, flow.PointRequestHeaders, wroteHeaders)
	markIfSet(exchange, flow.PointRequestBody, wroteRequest)
	markIfSet(exchange, flow.PointFirstByte, firstByte)
	// The router measures the real outbound dial. With a sniff rule the first
	// write is accepted before the dial, so the write time alone would charge
	// the dial to the TLS phase; it stays as the fallback for a router that
	// reports none.
	var connect, tlsTime time.Duration
	routed := r.state.ConnectDuration()
	if conn := r.conn.Load(); conn != nil {
		if written := conn.firstWriteDone.Load(); written != 0 {
			writeTime := time.Unix(0, written)
			connect = writeTime.Sub(r.dialStart)
			if routed > 0 {
				connect = routed
			}
			if !tlsDone.IsZero() && plan.target.Scheme == "https" {
				handshakeStart := writeTime
				if routed > 0 && !tlsStart.IsZero() {
					handshakeStart = tlsStart
				}
				tlsTime = tlsDone.Sub(handshakeStart)
				if routed > 0 {
					tlsTime -= routed
				}
			}
		}
	}
	exchange.SetDurations(0, max(connect, 0), max(tlsTime, 0))
}

func markIfSet(exchange flow.Exchange, point flow.Point, at time.Time) {
	if !at.IsZero() {
		exchange.Mark(point, at)
	}
}

func responseHeaders(header http.Header) []flow.Header {
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
