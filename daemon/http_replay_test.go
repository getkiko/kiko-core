package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeRouter plays the core's router: it records the metadata, links the
// connection like the tracker does and forwards to the destination.
type fakeRouter struct {
	mu       sync.Mutex
	seen     []adapter.InboundContext
	ctxs     []context.Context
	dialErr  error
	stall    bool
	outbound string
}

func (r *fakeRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.mu.Lock()
	r.seen = append(r.seen, metadata)
	r.ctxs = append(r.ctxs, ctx)
	r.mu.Unlock()
	metadata.MITM.SetConnection("tracked-9", "rule-x")
	if r.dialErr != nil {
		conn.Close()
		onClose(r.dialErr)
		return
	}
	if r.stall {
		// Holds the connection open without forwarding anything.
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			onClose(nil)
		}()
		return
	}
	remote, err := net.Dial("tcp", metadata.Destination.String())
	if err != nil {
		conn.Close()
		onClose(err)
		return
	}
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			conn.Close()
			remote.Close()
			onClose(nil)
		})
	}
	go func() {
		_, _ = io.Copy(remote, conn)
		closeAll()
	}()
	go func() {
		_, _ = io.Copy(conn, remote)
		closeAll()
	}()
}

type fakeOutbounds map[string]bool

func (o fakeOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	return nil, o[tag]
}

type replayProvider struct {
	manager *capture.Manager
	target  *HTTPReplayTarget
}

func (p *replayProvider) HTTPCapture() *capture.Manager { return p.manager }
func (p *replayProvider) HTTPReplay() *HTTPReplayTarget { return p.target }

type replayFixture struct {
	router  *fakeRouter
	manager *capture.Manager
	client  mitmapi.HTTPCaptureClient
}

func newReplayFixture(t *testing.T, running bool) *replayFixture {
	t.Helper()
	router := &fakeRouter{}
	manager := capture.New(capture.Options{Enabled: true, Body: true, MaxBody: 1 << 10})
	provider := &replayProvider{manager: manager}
	if running {
		provider.target = &HTTPReplayTarget{
			Router:    router,
			Outbounds: fakeOutbounds{"proxy-a": true},
			Connection: func(id string) *trafficcontrol.TrackerMetadata {
				if id != "tracked-9" {
					return nil
				}
				return &trafficcontrol.TrackerMetadata{Outbound: "proxy-a", OutboundType: "socks"}
			},
		}
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.MaxRecvMsgSize(HTTPReplayMaxMessage))
	RegisterHTTPCapture(server, provider)
	go server.Serve(listener)
	conn, err := grpc.NewClient("passthrough:///replay", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
		server.Stop()
		listener.Close()
	})
	return &replayFixture{router: router, manager: manager, client: mitmapi.NewHTTPCaptureClient(conn)}
}

func (f *replayFixture) replay(t *testing.T, request *mitmapi.ReplayRequest) (*mitmapi.ReplayResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return f.client.Replay(ctx, request)
}

func headerOf(headers []*mitmapi.HTTPHeader, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Host", r.Host)
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Proto", r.Proto)
		w.WriteHeader(201)
		_, _ = w.Write(append([]byte("echo:"), body...))
	})
}

func TestReplayHTTP1(t *testing.T) {
	server := httptest.NewServer(echoHandler())
	defer server.Close()
	fixture := newReplayFixture(t, true)
	response, err := fixture.replay(t, &mitmapi.ReplayRequest{
		SourceId: "5",
		Method:   "post",
		Url:      server.URL + "/path?q=1#frag",
		Headers: []*mitmapi.HTTPHeader{
			{Name: "Authorization", Value: "Bearer x"},
			{Name: "Host", Value: "override.test"},
			{Name: "Connection", Value: "close"},
			{Name: "Content-Length", Value: "999"},
		},
		Body:     []byte("payload"),
		Outbound: "proxy-a",
	})
	require.NoError(t, err)
	require.Empty(t, response.Error)
	record := response.Record
	require.Equal(t, mitmapi.RecordState_RECORD_STATE_COMPLETE, record.State)
	require.Equal(t, int32(201), record.Status)
	require.Equal(t, "POST", record.Method)
	require.Equal(t, "http", record.Scheme)
	require.Equal(t, "/path?q=1", record.Path)
	require.Equal(t, "http/1.1", record.Proto)
	require.Equal(t, "override.test", headerOf(record.RequestHeaders, "Host"))
	require.Equal(t, "7", headerOf(record.RequestHeaders, "Content-Length"))
	require.Equal(t, "", headerOf(record.RequestHeaders, "Connection"))
	require.Equal(t, "override.test", headerOf(record.ResponseHeaders, "X-Echo-Host"))
	require.Equal(t, "Bearer x", headerOf(record.ResponseHeaders, "X-Echo-Auth"))
	require.Equal(t, "POST", headerOf(record.ResponseHeaders, "X-Echo-Method"))
	require.Equal(t, int64(len("echo:payload")), record.ResponseBytes)
	require.Equal(t, int64(7), record.RequestBytes)
	require.Equal(t, "tracked-9", record.ConnectionId)
	require.Equal(t, "kiko-internal", record.Connection.Inbound)
	require.Equal(t, "proxy-a", record.Connection.Outbound)
	require.Equal(t, "socks", record.Connection.OutboundType)
	require.Equal(t, "rule-x", record.Connection.Rule)
	require.False(t, record.Unverified)
	require.Greater(t, record.Timing.Connect, int64(0))
	require.Zero(t, record.Timing.Tls)
	require.NotZero(t, record.Timing.FirstByte)
	require.NotZero(t, record.Timing.RequestHeaders)
	require.NotZero(t, record.Timing.End)

	fixture.router.mu.Lock()
	metadata := fixture.router.seen[0]
	fixture.router.mu.Unlock()
	require.Equal(t, adapter.InboundKikoInternal, metadata.Inbound)
	require.True(t, metadata.Internal)
	require.Equal(t, "proxy-a", metadata.ForcedOutbound)
	require.Equal(t, adapter.MITMStatusSkipped, metadata.MITM.Status())

	stream, err := fixture.client.GetBody(context.Background(), &mitmapi.GetBodyRequest{Id: record.Id, Side: mitmapi.BodySide_BODY_SIDE_RESPONSE})
	require.NoError(t, err)
	chunk, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, "echo:payload", string(chunk.Data))
	stored, found := fixture.manager.Get(record.Id)
	require.True(t, found)
	require.Equal(t, record.Id, stored.ID)
}

func TestReplayTLSAndHTTP2(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "h1"
		if h2 {
			name = "h2"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(echoHandler())
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			fixture := newReplayFixture(t, true)
			response, err := fixture.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: server.URL + "/tls", VerifyTls: false})
			require.NoError(t, err)
			require.Empty(t, response.Error)
			record := response.Record
			require.Equal(t, int32(201), record.Status)
			require.Equal(t, "https", record.Scheme)
			require.True(t, record.Unverified)
			if h2 {
				require.Equal(t, "h2", record.Proto)
				require.Equal(t, "HTTP/2.0", headerOf(record.ResponseHeaders, "X-Echo-Proto"))
			} else {
				require.Equal(t, "http/1.1", record.Proto)
			}
			require.Greater(t, record.Timing.Tls, int64(0))

			failed, err := fixture.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: server.URL + "/tls", VerifyTls: true})
			require.NoError(t, err)
			require.NotEmpty(t, failed.Error)
			require.Equal(t, mitmapi.RecordState_RECORD_STATE_FAILED, failed.Record.State)
			require.Contains(t, failed.Record.Error, "certificate")
			require.False(t, failed.Record.Unverified)
		})
	}
}

func TestReplayRouteFailureKeepsReason(t *testing.T) {
	fixture := newReplayFixture(t, true)
	fixture.router.dialErr = errors.New("open connection: connection refused")
	response, err := fixture.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: "http://127.0.0.1:9/x"})
	require.NoError(t, err)
	require.Contains(t, response.Error, "connection refused")
	require.Equal(t, mitmapi.RecordState_RECORD_STATE_FAILED, response.Record.State)
	require.Equal(t, "tracked-9", response.Record.ConnectionId)
	require.Equal(t, "GET", response.Record.Method)
}

func TestReplayTimeout(t *testing.T) {
	fixture := newReplayFixture(t, true)
	fixture.router.stall = true
	started := time.Now()
	response, err := fixture.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: "http://127.0.0.1:9/x", TimeoutMs: 300})
	require.NoError(t, err)
	require.Less(t, time.Since(started), 5*time.Second)
	require.Equal(t, "timeout", response.Error)
	require.Equal(t, mitmapi.RecordState_RECORD_STATE_FAILED, response.Record.State)
	fixture.router.mu.Lock()
	routeCtx := fixture.router.ctxs[0]
	fixture.router.mu.Unlock()
	select {
	case <-routeCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the router side context outlives the run")
	}
}

func TestReplayDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer server.Close()
	fixture := newReplayFixture(t, true)
	response, err := fixture.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: server.URL})
	require.NoError(t, err)
	require.Equal(t, int32(302), response.Record.Status)
	require.Equal(t, "/elsewhere", headerOf(response.Record.ResponseHeaders, "Location"))
	require.Len(t, fixture.router.seen, 1)
}

func TestReplayBodyBeyondCaptureLimitIsCounted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 100<<10))
	}))
	defer server.Close()
	fixture := newReplayFixture(t, true)
	response, err := fixture.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: server.URL})
	require.NoError(t, err)
	require.Equal(t, int64(100<<10), response.Record.ResponseBytes)
	require.True(t, response.Record.ResponseBodyTruncated)
	require.LessOrEqual(t, response.Record.ResponseBodyStored, int64(1<<10))
}

func TestReplayRejectsInvalidRequests(t *testing.T) {
	fixture := newReplayFixture(t, true)
	cases := map[string]*mitmapi.ReplayRequest{
		"scheme":       {Method: "GET", Url: "ftp://example.com/"},
		"no host":      {Method: "GET", Url: "http:///path"},
		"bad url":      {Method: "GET", Url: "http://exa mple.com/"},
		"credentials":  {Method: "GET", Url: "http://user:pw@example.com/"},
		"bad method":   {Method: "GE T", Url: "http://example.com/"},
		"connect":      {Method: "CONNECT", Url: "http://example.com/"},
		"bad port":     {Method: "GET", Url: "http://example.com:0/"},
		"bad header":   {Method: "GET", Url: "http://example.com/", Headers: []*mitmapi.HTTPHeader{{Name: "Bad Name", Value: "x"}}},
		"header value": {Method: "GET", Url: "http://example.com/", Headers: []*mitmapi.HTTPHeader{{Name: "X", Value: "a\r\nb"}}},
		"big body":     {Method: "POST", Url: "http://example.com/", Body: make([]byte, replayMaxRequestBody+1)},
		"outbound":     {Method: "GET", Url: "http://example.com/", Outbound: "missing"},
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.replay(t, request)
			require.Equal(t, codes.InvalidArgument, status.Code(err), err)
		})
	}
	fixture.router.mu.Lock()
	defer fixture.router.mu.Unlock()
	require.Empty(t, fixture.router.seen)
}

func TestReplayPreconditions(t *testing.T) {
	stopped := newReplayFixture(t, false)
	_, err := stopped.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: "http://example.com/"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	disabled := newReplayFixture(t, true)
	disabled.manager.SetOptions(capture.Options{Enabled: false})
	_, err = disabled.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: "http://example.com/"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	stale := newReplayFixture(t, true)
	_, err = stale.replay(t, &mitmapi.ReplayRequest{Method: "GET", Url: "http://example.com/", Instance: "old"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestReplayDefaults(t *testing.T) {
	plan, err := parseReplayRequest(&mitmapi.ReplayRequest{Url: "https://example.com"})
	require.NoError(t, err)
	require.Equal(t, "GET", plan.method)
	require.Equal(t, uint16(443), plan.port)
	require.Equal(t, replayDefaultTimeout, plan.timeout)
	plan, err = parseReplayRequest(&mitmapi.ReplayRequest{Url: "http://example.com:8080/", TimeoutMs: 999999})
	require.NoError(t, err)
	require.Equal(t, uint16(8080), plan.port)
	require.Equal(t, replayMaxTimeout, plan.timeout)
}
