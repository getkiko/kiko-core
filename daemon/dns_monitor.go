package daemon

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sagernet/sing-box/common/dnsmonitor"
	dnsmonitorapi "github.com/sagernet/sing-box/common/dnsmonitor/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type dnsMonitorServer struct {
	dnsmonitorapi.UnimplementedDNSMonitorServer
	started *StartedService
	slots   chan struct{}
}

func RegisterDNSMonitor(server *grpc.Server, started *StartedService) {
	dnsmonitorapi.RegisterDNSMonitorServer(server, &dnsMonitorServer{started: started, slots: make(chan struct{}, 64)})
}

func (s *dnsMonitorServer) manager() *dnsmonitor.Manager {
	s.started.serviceAccess.RLock()
	defer s.started.serviceAccess.RUnlock()
	if s.started.instance == nil {
		return nil
	}
	return dnsmonitor.FromContext(s.started.instance.ctx)
}

func (s *dnsMonitorServer) require() (*dnsmonitor.Manager, error) {
	m := s.manager()
	if m == nil {
		return nil, status.Error(codes.FailedPrecondition, "DNS monitoring is disabled or the core is stopped")
	}
	return m, nil
}

func (s *dnsMonitorServer) GetCapabilities(context.Context, *emptypb.Empty) (*dnsmonitorapi.Capabilities, error) {
	return &dnsmonitorapi.Capabilities{SchemaVersion: dnsmonitor.SchemaVersion, Enabled: s.manager() != nil,
		Features:    []string{"history", "stream", "questions", "resource_records", "cache", "policy", "process", "attempts", "actual_outbound", "connection_reuse", "udp_tcp_fallback", "http_trace", "quic_stream", "delivery", "parallel_resolvers"},
		Limitations: []string{"platform resolver delegates socket visibility to the operating system", "HTTP/3 connection binding requires a unique active address pair", "DNS resolved by remote proxies or applications stays outside this engine", "wire capture contains reconstructed DNS messages; transport framing is separate"}}, nil
}

func payload(value any) (*dnsmonitorapi.Payload, error) {
	b, err := json.Marshal(value)
	return &dnsmonitorapi.Payload{Json: b}, err
}

func (s *dnsMonitorServer) ListQueries(ctx context.Context, r *dnsmonitorapi.ListRequest) (*dnsmonitorapi.Payload, error) {
	m, err := s.require()
	if err != nil {
		return nil, err
	}
	return payload(m.List(dnsmonitor.Filter{Search: r.Search, Status: r.Status, Resolver: r.Resolver, Limit: int(r.Limit), Before: r.Before}))
}

func (s *dnsMonitorServer) GetQuery(ctx context.Context, r *dnsmonitorapi.GetRequest) (*dnsmonitorapi.Payload, error) {
	m, err := s.require()
	if err != nil {
		return nil, err
	}
	if r.Instance != "" && r.Instance != m.Instance() {
		return nil, status.Error(codes.FailedPrecondition, "DNS monitor instance changed")
	}
	q, ok := m.Get(r.Id)
	if !ok {
		return nil, status.Error(codes.NotFound, "DNS query expired or was evicted")
	}
	return payload(q)
}

func (s *dnsMonitorServer) ClearHistory(ctx context.Context, _ *emptypb.Empty) (*dnsmonitorapi.Payload, error) {
	m, err := s.require()
	if err != nil {
		return nil, err
	}
	return payload(m.Clear())
}

func (s *dnsMonitorServer) SubscribeEvents(r *dnsmonitorapi.SubscribeRequest, stream grpc.ServerStreamingServer[dnsmonitorapi.Payload]) error {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return status.Error(codes.ResourceExhausted, "too many DNS monitor subscribers")
	}
	instance, after := r.Instance, r.After
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		m, err := s.require()
		if err != nil {
			return err
		}
		v := m.Poll(instance, after)
		frame, err := payload(v)
		if err != nil {
			return err
		}
		if err = stream.Send(frame); err != nil {
			return err
		}
		instance, after = v.Instance, v.Seq
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-m.Done():
			return status.Error(codes.Unavailable, "DNS monitor instance closed")
		case <-ticker.C:
		}
	}
}
