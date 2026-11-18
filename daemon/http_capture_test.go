package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type captureFixture struct {
	manager *atomic.Pointer[capture.Manager]
	client  mitmapi.HTTPCaptureClient
	conn    *grpc.ClientConn
}

func newCaptureFixture(t *testing.T, manager *capture.Manager) *captureFixture {
	t.Helper()
	holder := &atomic.Pointer[capture.Manager]{}
	holder.Store(manager)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterHTTPCapture(server, HTTPCaptureProviderFunc(holder.Load))
	go server.Serve(listener)
	conn, err := grpc.NewClient("passthrough:///capture", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
		server.Stop()
		listener.Close()
	})
	return &captureFixture{manager: holder, client: mitmapi.NewHTTPCaptureClient(conn), conn: conn}
}

func captureExchange(manager *capture.Manager, path string, responseBody []byte, encoding string) {
	x := manager.NewExchange(&flow.ConnectionInfo{ID: "conn-1", ProcessName: "curl", Outbound: "direct"})
	x.RequestHead(flow.RequestHead{Method: "POST", Scheme: "https", Authority: "api.example.com", Path: path, Proto: "http/1.1",
		Headers: []flow.Header{{Name: "Host", Value: "api.example.com"}, {Name: "X-Dup", Value: "1"}, {Name: "x-dup", Value: "2"}}})
	x.RequestBody().Write([]byte("hello"))
	x.RequestBody().Done()
	headers := []flow.Header{{Name: "Content-Type", Value: "text/plain"}}
	if encoding != "" {
		headers = append(headers, flow.Header{Name: "Content-Encoding", Value: encoding})
	}
	x.ResponseHead(200, headers)
	x.ResponseBody().Write(responseBody)
	x.ResponseBody().Done()
	x.Finish(nil)
}

func recvPayload(t *testing.T, stream grpc.ServerStreamingClient[mitmapi.CapturePayload]) *mitmapi.CapturePayload {
	t.Helper()
	type result struct {
		payload *mitmapi.CapturePayload
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		payload, err := stream.Recv()
		ch <- result{payload, err}
	}()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.payload
	case <-time.After(5 * time.Second):
		t.Fatal("no payload")
		return nil
	}
}

func TestHTTPCaptureSubscribeListGetBodyClear(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true, Body: true})
	fixture := newCaptureFixture(t, manager)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := fixture.client.SubscribeEvents(ctx, &mitmapi.SubscribeEventsRequest{})
	require.NoError(t, err)
	first := recvPayload(t, stream)
	require.True(t, first.Reset_)
	require.Equal(t, manager.Instance(), first.Instance)
	require.Empty(t, first.Events)

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(strings.Repeat("kiko ", 50)))
	w.Close()
	captureExchange(manager, "/v1/a?x=1", gz.Bytes(), "gzip")

	var latest *mitmapi.HTTPRecord
	cursor := first.Seq
	deadline := time.Now().Add(5 * time.Second)
	for latest == nil || latest.State != mitmapi.RecordState_RECORD_STATE_COMPLETE {
		require.True(t, time.Now().Before(deadline), "completion not delivered")
		payload := recvPayload(t, stream)
		require.False(t, payload.Reset_)
		require.GreaterOrEqual(t, payload.Seq, cursor)
		cursor = payload.Seq
		for _, event := range payload.Events {
			latest = event.Record
		}
	}
	require.Equal(t, "/v1/a?x=1", latest.Path)
	require.Equal(t, "api.example.com", latest.Host)
	require.Equal(t, "curl", latest.Connection.ProcessName)
	require.Len(t, latest.RequestHeaders, 3)
	require.Equal(t, "x-dup", latest.RequestHeaders[2].Name)
	require.EqualValues(t, 5, latest.RequestBytes)
	require.EqualValues(t, gz.Len(), latest.ResponseBytes)

	list, err := fixture.client.ListRecords(ctx, &mitmapi.ListRecordsRequest{Search: "v1/a", ConnectionId: "conn-1", Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Records, 1)
	require.Equal(t, manager.Instance(), list.Instance)
	none, err := fixture.client.ListRecords(ctx, &mitmapi.ListRecordsRequest{Host: "other.com"})
	require.NoError(t, err)
	require.Empty(t, none.Records)

	record, err := fixture.client.GetRecord(ctx, &mitmapi.GetRecordRequest{Id: latest.Id, Instance: latest.Instance})
	require.NoError(t, err)
	require.Equal(t, latest.Id, record.Id)
	_, err = fixture.client.GetRecord(ctx, &mitmapi.GetRecordRequest{Id: "999"})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = fixture.client.GetRecord(ctx, &mitmapi.GetRecordRequest{Id: latest.Id, Instance: "stale"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	readBody := func(request *mitmapi.GetBodyRequest) ([]byte, *mitmapi.BodyChunk) {
		bodyStream, err := fixture.client.GetBody(ctx, request)
		require.NoError(t, err)
		var data []byte
		var last *mitmapi.BodyChunk
		for {
			chunk, err := bodyStream.Recv()
			if err == io.EOF {
				return data, last
			}
			require.NoError(t, err)
			data = append(data, chunk.Data...)
			last = chunk
		}
	}
	raw, rawMeta := readBody(&mitmapi.GetBodyRequest{Id: latest.Id, Side: mitmapi.BodySide_BODY_SIDE_RESPONSE})
	require.Equal(t, gz.Bytes(), raw)
	require.Equal(t, "gzip", rawMeta.Encoding)
	require.True(t, rawMeta.Saved)
	decoded, decodedMeta := readBody(&mitmapi.GetBodyRequest{Id: latest.Id, Side: mitmapi.BodySide_BODY_SIDE_RESPONSE, Decoded: true})
	require.Equal(t, strings.Repeat("kiko ", 50), string(decoded))
	require.EqualValues(t, 300, decodedMeta.Total)
	request, _ := readBody(&mitmapi.GetBodyRequest{Id: latest.Id, Side: mitmapi.BodySide_BODY_SIDE_REQUEST, Offset: 1, Length: 3})
	require.Equal(t, "ell", string(request))
	_, err = fixture.client.GetBody(ctx, &mitmapi.GetBodyRequest{Id: "999"})
	require.NoError(t, err)
	missing, err := fixture.client.GetBody(ctx, &mitmapi.GetBodyRequest{Id: "999"})
	require.NoError(t, err)
	_, err = missing.Recv()
	require.Equal(t, codes.NotFound, status.Code(err))

	state, err := fixture.client.GetStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.True(t, state.Enabled)
	require.True(t, state.BodyEnabled)
	require.EqualValues(t, 1, state.RecordCount)
	require.Greater(t, state.ByteEstimate, int64(0))

	cleared, err := fixture.client.Clear(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.EqualValues(t, 0, cleared.RecordCount)
	reload := recvPayload(t, stream)
	require.True(t, reload.Reset_)
	require.True(t, reload.Gap)
	require.Empty(t, reload.Events)
}

func TestHTTPCaptureStoppedCore(t *testing.T) {
	fixture := newCaptureFixture(t, nil)
	ctx := context.Background()
	_, err := fixture.client.GetStatus(ctx, &emptypb.Empty{})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	stream, err := fixture.client.SubscribeEvents(ctx, &mitmapi.SubscribeEventsRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestHTTPCaptureSubscribeReleasesOnCancel(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true})
	fixture := newCaptureFixture(t, manager)
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := fixture.client.SubscribeEvents(ctx, &mitmapi.SubscribeEventsRequest{})
		require.NoError(t, err)
		recvPayload(t, stream)
		cancel()
	}
	require.Eventually(t, func() bool { return manager.Subscribers() == 0 }, 5*time.Second, 20*time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := fixture.client.SubscribeEvents(ctx, &mitmapi.SubscribeEventsRequest{})
		require.NoError(t, err)
		recvPayload(t, stream)
		cancel()
	}
	require.Eventually(t, func() bool { return manager.Subscribers() == 0 && runtime.NumGoroutine() <= before+5 }, 5*time.Second, 20*time.Millisecond)
}

func TestHTTPCaptureStreamEndsWhenCoreRestarts(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true})
	fixture := newCaptureFixture(t, manager)
	stream, err := fixture.client.SubscribeEvents(context.Background(), &mitmapi.SubscribeEventsRequest{})
	require.NoError(t, err)
	recvPayload(t, stream)
	fixture.manager.Store(capture.New(capture.Options{Enabled: true}))
	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()
	select {
	case err := <-done:
		require.Equal(t, codes.Unavailable, status.Code(err))
	case <-time.After(6 * time.Second):
		t.Fatal("stream did not end after the store changed")
	}
}

func TestHTTPCaptureGetBodyRangeLimits(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true, Body: true})
	fixture := newCaptureFixture(t, manager)
	captureExchange(manager, "/r", []byte("0123456789"), "")
	id := manager.List(capture.Filter{}).Records[0].ID
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, decoded := range []bool{false, true} {
		stream, err := fixture.client.GetBody(ctx, &mitmapi.GetBodyRequest{Id: id, Side: mitmapi.BodySide_BODY_SIDE_RESPONSE, Decoded: decoded, Offset: 1, Length: 1<<63 - 1})
		require.NoError(t, err)
		chunk, err := stream.Recv()
		require.NoError(t, err)
		require.Equal(t, "123456789", string(chunk.Data))
		for _, bad := range []*mitmapi.GetBodyRequest{{Id: id, Offset: -1}, {Id: id, Length: -1}} {
			bad.Decoded = decoded
			stream, err = fixture.client.GetBody(ctx, bad)
			require.NoError(t, err)
			_, err = stream.Recv()
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		}
	}
}

func TestHTTPCaptureSubscribeBatchesByBytes(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true})
	for i := 0; i < 40; i++ {
		x := manager.NewExchange(&flow.ConnectionInfo{ID: "c"})
		x.RequestHead(flow.RequestHead{Method: "GET", Scheme: "https", Authority: "big.example.com", Path: "/", Proto: "h2",
			Headers: []flow.Header{{Name: "X-Big", Value: strings.Repeat("v", 200<<10)}}})
		x.Finish(nil)
	}
	view := manager.Poll("", 0)
	view = manager.Poll(view.Instance, 0)
	payloads := captureViews(view, 1<<20)
	require.Greater(t, len(payloads), 1)
	total := 0
	var previous uint64
	for i, payload := range payloads {
		require.Equal(t, i == 0 && view.Reset, payload.Reset_)
		require.GreaterOrEqual(t, payload.Seq, previous)
		previous = payload.Seq
		require.Less(t, proto.Size(payload), 2<<20)
		total += len(payload.Events)
	}
	require.Equal(t, len(view.Events), total)
	require.Equal(t, view.Seq, payloads[len(payloads)-1].Seq)

	fixture := newCaptureFixture(t, manager)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := fixture.client.SubscribeEvents(ctx, &mitmapi.SubscribeEventsRequest{})
	require.NoError(t, err)
	received := 0
	for received < 40 {
		payload := recvPayload(t, stream)
		require.Less(t, proto.Size(payload), 5<<20)
		received += len(payload.Events)
	}
}

func TestHTTPCaptureResetSnapshotCursor(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true})
	bigHead := func(path string) flow.RequestHead {
		return flow.RequestHead{Method: "GET", Scheme: "https", Authority: "big.example.com", Path: path, Proto: "h2",
			Headers: []flow.Header{{Name: "X-Big", Value: strings.Repeat("v", 200<<10)}}}
	}
	running := manager.NewExchange(&flow.ConnectionInfo{ID: "c"})
	running.RequestHead(bigHead("/running"))
	for i := 0; i < 5; i++ {
		x := manager.NewExchange(&flow.ConnectionInfo{ID: "c"})
		x.RequestHead(bigHead("/done"))
		x.Finish(nil)
	}
	running.ResponseHead(200, nil)
	for _, instance := range []string{"", "stale-instance"} {
		view := manager.Poll(instance, 0)
		require.True(t, view.Reset)
		require.Len(t, view.Events, 6)
		require.Equal(t, "/running", view.Events[0].Record.Path)
		payloads := captureViews(view, 300<<10)
		require.Greater(t, len(payloads), 2)
		for i, payload := range payloads {
			require.Equal(t, i == 0, payload.Reset_)
			if i < len(payloads)-1 {
				require.Zero(t, payload.Seq)
				continue
			}
			require.Equal(t, view.Seq, payload.Seq)
		}
	}
}

func TestHTTPCaptureRewriteHits(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true})
	x := manager.NewExchange(&flow.ConnectionInfo{ID: "conn-1"})
	x.RequestHead(flow.RequestHead{Method: "GET", Scheme: "https", Authority: "a.example.com", Path: "/", Proto: "http/1.1"})
	x.Rewritten(nil)
	x.Rewritten([]flow.RewriteHit{{Kind: "header", Rule: "headers#1", Action: "replace", Side: "request",
		Changes: []flow.RewriteChange{{Op: "replace", Name: "User-Agent", Before: "a", HadBefore: true, After: "b", HasAfter: true}}}})
	x.Rewritten([]flow.RewriteHit{{Kind: "url", Rule: "u1", Action: "302", Target: "https://b.example.com/", Status: 302}})
	x.Finish(nil)

	records := manager.List(capture.Filter{}).Records
	require.Len(t, records, 1)
	require.True(t, records[0].Rewritten)
	require.Len(t, records[0].Rewrites, 2)

	record := captureRecord(&records[0])
	require.True(t, record.Rewritten)
	require.Len(t, record.Rewrites, 2)
	require.Equal(t, "headers#1", record.Rewrites[0].Rule)
	require.Equal(t, "request", record.Rewrites[0].Side)
	require.Len(t, record.Rewrites[0].Changes, 1)
	change := record.Rewrites[0].Changes[0]
	require.Equal(t, "User-Agent", change.Name)
	require.True(t, change.HadBefore)
	require.True(t, change.HasAfter)
	require.Equal(t, "b", change.After)
	require.Equal(t, int32(302), record.Rewrites[1].Status)
	require.Equal(t, "https://b.example.com/", record.Rewrites[1].Target)
}
