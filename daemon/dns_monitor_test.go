package daemon

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	dnsmonitorapi "github.com/sagernet/sing-box/common/dnsmonitor/api"
	"github.com/sagernet/sing/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestDNSMonitorRPCAuthResumeAndInstanceSwitch(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	m := dnsmonitor.New(dnsmonitor.Options{})
	defer m.Close()
	service.MustRegisterPtr(ctx, m)
	started := NewStartedService(ServiceOptions{Context: ctx})
	defer started.Close()
	started.instance = &Instance{ctx: ctx}
	server := NewServer(started, "dns-secret")
	defer server.Stop()
	listener := bufconn.Listen(1 << 20)
	defer listener.Close()
	go server.Serve(listener)
	conn, err := grpc.NewClient("passthrough:///dns-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := dnsmonitorapi.NewDNSMonitorClient(conn)
	if _, err = client.GetCapabilities(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("auth: %v", err)
	}
	auth := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer dns-secret")
	auth, cancel := context.WithTimeout(auth, 3*time.Second)
	defer cancel()
	cap, err := client.GetCapabilities(auth, &emptypb.Empty{})
	if err != nil || !cap.Enabled {
		t.Fatalf("capabilities: %+v %v", cap, err)
	}
	stream, err := client.SubscribeEvents(auth, &dnsmonitorapi.SubscribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var first dnsmonitor.View
	if json.Unmarshal(frame.Json, &first) != nil || !first.Reset {
		t.Fatal("missing initial snapshot")
	}
	request := new(dns.Msg)
	request.SetQuestion("rpc.example.", dns.TypeA)
	_, trace := dnsmonitor.Begin(ctx, request, "query")
	trace.End(nil, nil)
	frame, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var next dnsmonitor.View
	_ = json.Unmarshal(frame.Json, &next)
	if len(next.Queries) != 1 || next.Seq <= first.Seq {
		t.Fatalf("stream %+v", next)
	}
	detail, err := client.GetQuery(auth, &dnsmonitorapi.GetRequest{Id: trace.ID(), Instance: next.Instance})
	if err != nil || len(detail.Json) == 0 {
		t.Fatalf("detail: %v", err)
	}
	_, err = client.GetQuery(auth, &dnsmonitorapi.GetRequest{Id: trace.ID(), Instance: "old"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("instance guard: %v", err)
	}
	_, err = client.ClearHistory(auth, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetQuery(auth, &dnsmonitorapi.GetRequest{Id: trace.ID()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expired: %v", err)
	}
	started.serviceAccess.Lock()
	started.instance = nil
	started.serviceAccess.Unlock()
	_, err = client.ListQueries(auth, &dnsmonitorapi.ListRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped: %v", err)
	}
}
