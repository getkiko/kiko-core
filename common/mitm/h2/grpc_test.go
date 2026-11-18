//go:build go1.26

package h2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// rawCodec carries []byte messages so that no generated proto is needed.
type rawCodec struct{}

func (rawCodec) Name() string { return "raw" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	switch m := v.(type) {
	case *[]byte:
		return *m, nil
	}
	return nil, fmt.Errorf("rawCodec: unsupported %T", v)
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: unsupported %T", v)
	}
	*m = append((*m)[:0], data...)
	return nil
}

func init() { encoding.RegisterCodec(rawCodec{}) }

const grpcMax = 16 << 20

type grpcOrigin struct {
	ln      net.Listener
	srv     *grpc.Server
	started atomic.Int32
	// seen records the incoming metadata and deadline of the last "Meta" call.
	metaSeen  atomic.Value
	cancelled chan struct{}
}

func (g *grpcOrigin) dial(ctx context.Context) (net.Conn, error) {
	return dialTLS(ctx, g.ln.Addr().String())
}

func newGRPCOrigin(t *testing.T) *grpcOrigin {
	g := &grpcOrigin{cancelled: make(chan struct{}, 8)}
	cert := selfSigned(t)
	g.srv = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})),
		grpc.ForceServerCodec(rawCodec{}),
		grpc.MaxRecvMsgSize(grpcMax), grpc.MaxSendMsgSize(grpcMax),
	)
	unary := func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var in []byte
		if err := dec(&in); err != nil {
			return nil, err
		}
		switch string(in) {
		case "fail":
			return nil, status.Error(codes.NotFound, "nope")
		case "meta":
			md, _ := metadata.FromIncomingContext(ctx)
			dl, ok := ctx.Deadline()
			g.metaSeen.Store(fmt.Sprintf("%v|%v|%v", md.Get("x-req"), ok, time.Until(dl) > 0))
			grpc.SetHeader(ctx, metadata.Pairs("x-head", "h1"))
			grpc.SetTrailer(ctx, metadata.Pairs("x-trail", "t1"))
			return &in, nil
		case "wait":
			select {
			case <-ctx.Done():
				g.cancelled <- struct{}{}
				return nil, ctx.Err()
			case <-time.After(20 * time.Second):
				return &in, nil
			}
		case "deadline":
			dl, ok := ctx.Deadline()
			out := []byte("none")
			if ok {
				out = []byte(time.Until(dl).Round(time.Second).String())
			}
			return &out, nil
		}
		return &in, nil
	}
	stream := func(srv any, ss grpc.ServerStream) error {
		g.started.Add(1)
		var first []byte
		if err := ss.RecvMsg(&first); err != nil {
			return err
		}
		switch string(first) {
		case "server-stream":
			for i := 0; i < 5; i++ {
				m := []byte(fmt.Sprintf("item-%d", i))
				if err := ss.SendMsg(&m); err != nil {
					return err
				}
			}
			ss.SetTrailer(metadata.Pairs("x-count", "5"))
			return nil
		case "client-stream":
			var total int
			for {
				var m []byte
				if err := ss.RecvMsg(&m); err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
				total += len(m)
			}
			out := []byte(fmt.Sprint(total))
			return ss.SendMsg(&out)
		case "stream-fail":
			return status.Error(codes.PermissionDenied, "denied")
		case "hold":
			<-ss.Context().Done()
			g.cancelled <- struct{}{}
			return ss.Context().Err()
		default: // bidi echo
			if err := ss.SendMsg(&first); err != nil {
				return err
			}
			for {
				var m []byte
				if err := ss.RecvMsg(&m); err != nil {
					if err == io.EOF {
						return nil
					}
					return err
				}
				if err := ss.SendMsg(&m); err != nil {
					return err
				}
			}
		}
	}
	g.srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "t.Test",
		HandlerType: (*any)(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "Unary", Handler: unary}},
		Streams:     []grpc.StreamDesc{{StreamName: "Stream", Handler: stream, ServerStreams: true, ClientStreams: true}},
	}, struct{}{})
	var err error
	g.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go g.srv.Serve(g.ln)
	t.Cleanup(g.srv.Stop)
	return g
}

func grpcClient(t *testing.T, e *proxyEnv) *grpc.ClientConn {
	cc, err := grpc.NewClient("passthrough:///"+testHost+":443",
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, ServerName: testHost})),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", e.addr)
		}),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{}), grpc.MaxCallRecvMsgSize(grpcMax), grpc.MaxCallSendMsgSize(grpcMax)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return cc
}

var streamDesc = &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}

func grpcSetup(t *testing.T) (*grpcOrigin, *proxyEnv, *grpc.ClientConn) {
	g := newGRPCOrigin(t)
	e := startProxy(t, proxyConfig{dial: g.dial})
	return g, e, grpcClient(t, e)
}

func call(t *testing.T, cc *grpc.ClientConn, msg string, opts ...grpc.CallOption) (string, error) {
	in := []byte(msg)
	var out []byte
	err := cc.Invoke(context.Background(), "/t.Test/Unary", &in, &out, opts...)
	return string(out), err
}

func TestGRPCUnary(t *testing.T) {
	_, e, cc := grpcSetup(t)
	got, err := call(t, cc, "hello")
	if err != nil || got != "hello" {
		t.Fatalf("got %q %v", got, err)
	}
	if e.forward.Load() != 1 {
		t.Fatalf("forwarded %d", e.forward.Load())
	}
}

func TestGRPCTrailersOnlyError(t *testing.T) {
	_, _, cc := grpcSetup(t)
	_, err := call(t, cc, "fail")
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound || st.Message() != "nope" {
		t.Fatalf("status %v", err)
	}
	// A streaming call failing before any message is trailers-only as well.
	s, err := cc.NewStream(context.Background(), streamDesc, "/t.Test/Stream")
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("stream-fail")
	if err := s.SendMsg(&first); err != nil {
		t.Fatal(err)
	}
	var out []byte
	err = s.RecvMsg(&out)
	st, _ = status.FromError(err)
	if st.Code() != codes.PermissionDenied || st.Message() != "denied" {
		t.Fatalf("stream status %v", err)
	}
	// Unimplemented methods answer trailers-only too.
	err = cc.Invoke(context.Background(), "/t.Test/Missing", &first, &out)
	if st, _ := status.FromError(err); st.Code() != codes.Unimplemented {
		t.Fatalf("missing method: %v", err)
	}
}

func TestGRPCMetadata(t *testing.T) {
	g, _, cc := grpcSetup(t)
	var head, trail metadata.MD
	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-req", "r1")
	in := []byte("meta")
	var out []byte
	if err := cc.Invoke(ctx, "/t.Test/Unary", &in, &out, grpc.Header(&head), grpc.Trailer(&trail)); err != nil {
		t.Fatal(err)
	}
	if got := head.Get("x-head"); len(got) != 1 || got[0] != "h1" {
		t.Fatalf("header md %v", head)
	}
	if got := trail.Get("x-trail"); len(got) != 1 || got[0] != "t1" {
		t.Fatalf("trailer md %v", trail)
	}
	if got := g.metaSeen.Load(); got != "[r1]|false|false" {
		t.Fatalf("origin saw %v", got)
	}
}

func TestGRPCDeadline(t *testing.T) {
	_, _, cc := grpcSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	in := []byte("deadline")
	var out []byte
	if err := cc.Invoke(ctx, "/t.Test/Unary", &in, &out); err != nil {
		t.Fatal(err)
	}
	var d time.Duration
	d, err := time.ParseDuration(string(out))
	if err != nil || d < 5*time.Second || d > 7*time.Second {
		t.Fatalf("origin deadline %q", out)
	}
	// An expiring deadline reaches the caller as DeadlineExceeded.
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	in = []byte("wait")
	err = cc.Invoke(ctx, "/t.Test/Unary", &in, &out)
	if st, _ := status.FromError(err); st.Code() != codes.DeadlineExceeded {
		t.Fatalf("status %v", err)
	}
}

func TestGRPCServerStreaming(t *testing.T) {
	_, _, cc := grpcSetup(t)
	s, err := cc.NewStream(context.Background(), streamDesc, "/t.Test/Stream")
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("server-stream")
	if err := s.SendMsg(&first); err != nil {
		t.Fatal(err)
	}
	s.CloseSend()
	for i := 0; i < 5; i++ {
		var m []byte
		if err := s.RecvMsg(&m); err != nil || string(m) != fmt.Sprintf("item-%d", i) {
			t.Fatalf("item %d: %q %v", i, m, err)
		}
	}
	var m []byte
	if err := s.RecvMsg(&m); err != io.EOF {
		t.Fatalf("end: %v", err)
	}
	if got := s.Trailer().Get("x-count"); len(got) != 1 || got[0] != "5" {
		t.Fatalf("trailer %v", s.Trailer())
	}
}

func TestGRPCClientStreaming(t *testing.T) {
	_, _, cc := grpcSetup(t)
	s, err := cc.NewStream(context.Background(), streamDesc, "/t.Test/Stream")
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("client-stream")
	s.SendMsg(&first)
	chunk := bytes.Repeat([]byte("c"), 100000)
	for i := 0; i < 30; i++ {
		if err := s.SendMsg(&chunk); err != nil {
			t.Fatal(err)
		}
	}
	s.CloseSend()
	var out []byte
	if err := s.RecvMsg(&out); err != nil || string(out) != "3000000" {
		t.Fatalf("total %q %v", out, err)
	}
}

func TestGRPCBidirectional(t *testing.T) {
	_, _, cc := grpcSetup(t)
	s, err := cc.NewStream(context.Background(), streamDesc, "/t.Test/Stream")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		msg := []byte(fmt.Sprintf("ping-%d", i))
		if err := s.SendMsg(&msg); err != nil {
			t.Fatal(err)
		}
		var out []byte
		if err := s.RecvMsg(&out); err != nil || !bytes.Equal(out, msg) {
			t.Fatalf("echo %d: %q %v", i, out, err)
		}
	}
	s.CloseSend()
	var out []byte
	if err := s.RecvMsg(&out); err != io.EOF {
		t.Fatalf("end: %v", err)
	}
}

func TestGRPCLargeMessage(t *testing.T) {
	_, _, cc := grpcSetup(t)
	big := make([]byte, 4<<20)
	for i := range big {
		big[i] = byte(i * 7)
	}
	var out []byte
	if err := cc.Invoke(context.Background(), "/t.Test/Unary", &big, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, big) {
		t.Fatalf("echoed %d bytes", len(out))
	}
}

func TestGRPCClientCancel(t *testing.T) {
	g, _, cc := grpcSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		in := []byte("wait")
		var out []byte
		done <- cc.Invoke(ctx, "/t.Test/Unary", &in, &out)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	if err := <-done; status.Code(err) != codes.Canceled {
		t.Fatalf("client status %v", err)
	}
	select {
	case <-g.cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("origin did not see the cancellation")
	}

	// Same for a stream.
	ctx, cancel = context.WithCancel(context.Background())
	s, err := cc.NewStream(ctx, streamDesc, "/t.Test/Stream")
	if err != nil {
		t.Fatal(err)
	}
	hold := []byte("hold")
	s.SendMsg(&hold)
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-g.cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("origin did not see the stream cancellation")
	}
}

func TestGRPCConcurrent(t *testing.T) {
	_, e, cc := grpcSetup(t)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := fmt.Sprintf("m%d", i)
			if got, err := call(t, cc, msg); err != nil || got != msg {
				t.Errorf("unary %d: %q %v", i, got, err)
			}
		}()
	}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := cc.NewStream(context.Background(), streamDesc, "/t.Test/Stream")
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 20; j++ {
				msg := []byte(fmt.Sprintf("s%d-%d", i, j))
				if err := s.SendMsg(&msg); err != nil {
					t.Error(err)
					return
				}
				var out []byte
				if err := s.RecvMsg(&out); err != nil || !bytes.Equal(out, msg) {
					t.Errorf("echo: %q %v", out, err)
					return
				}
			}
			s.CloseSend()
		}()
	}
	wg.Wait()
	if e.forward.Load() != 230 {
		t.Fatalf("forwarded %d", e.forward.Load())
	}
}

func TestGRPCUpstreamGone(t *testing.T) {
	g := newGRPCOrigin(t)
	e := startProxy(t, proxyConfig{dial: g.dial, noRedial: true})
	cc := grpcClient(t, e)
	if _, err := call(t, cc, "ok"); err != nil {
		t.Fatal(err)
	}
	g.srv.Stop()
	_, err := call(t, cc, "again")
	if err == nil {
		t.Fatal("call succeeded without an origin")
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		t.Fatalf("err %v", err)
	}
}
