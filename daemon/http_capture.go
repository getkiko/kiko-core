package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	httpCaptureStreamSlots = 64
	httpCaptureBatchDelay  = 50 * time.Millisecond
	httpCaptureStaleCheck  = 2 * time.Second
	httpCaptureChunkSize   = 64 << 10
	httpCaptureBatchBytes  = 4 << 20
)

// HTTPCaptureProvider returns the capture store of the running core, or nil
// while none is running.
type HTTPCaptureProvider interface {
	HTTPCapture() *capture.Manager
}

// HTTPCaptureProviderFunc adapts a function to HTTPCaptureProvider.
type HTTPCaptureProviderFunc func() *capture.Manager

func (f HTTPCaptureProviderFunc) HTTPCapture() *capture.Manager { return f() }

type httpCaptureServer struct {
	mitmapi.UnimplementedHTTPCaptureServer
	provider HTTPCaptureProvider
	slots    chan struct{}
}

// RegisterHTTPCapture serves the HTTPCapture service from the store the
// provider returns.
func RegisterHTTPCapture(server *grpc.Server, provider HTTPCaptureProvider) {
	mitmapi.RegisterHTTPCaptureServer(server, newHTTPCaptureServer(provider))
}

// HTTPCapture returns the capture store of the running core, or nil while the
// core is stopped or its engine records nothing.
func (s *StartedService) HTTPCapture() *capture.Manager {
	s.serviceAccess.RLock()
	instance := s.instance
	s.serviceAccess.RUnlock()
	if instance == nil {
		return nil
	}
	provider := service.FromContext[adapter.MITMEngine](instance.ctx)
	if provider == nil {
		return nil
	}
	capturing, ok := provider.(adapter.MITMCaptureProvider)
	if !ok {
		return nil
	}
	return capturing.Capture()
}

func newHTTPCaptureServer(provider HTTPCaptureProvider) *httpCaptureServer {
	return &httpCaptureServer{provider: provider, slots: make(chan struct{}, httpCaptureStreamSlots)}
}

func (s *httpCaptureServer) manager() (*capture.Manager, error) {
	manager := s.provider.HTTPCapture()
	if manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "HTTP capture is not running")
	}
	return manager, nil
}

func (s *httpCaptureServer) SubscribeEvents(request *mitmapi.SubscribeEventsRequest, stream grpc.ServerStreamingServer[mitmapi.CapturePayload]) error {
	manager, err := s.manager()
	if err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return status.Error(codes.ResourceExhausted, "too many capture subscribers")
	}
	ctx := stream.Context()
	wake, cancel := manager.Subscribe()
	defer cancel()
	stale := time.NewTicker(httpCaptureStaleCheck)
	defer stale.Stop()
	instance, after := request.Instance, request.After
	for {
		for {
			view := manager.Poll(instance, after)
			instance, after = view.Instance, view.Seq
			if len(view.Events) > 0 || view.Reset {
				for _, payload := range captureViews(view, httpCaptureBatchBytes) {
					err = stream.Send(payload)
					if err != nil {
						return err
					}
				}
			}
			if !view.More {
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		case <-stale.C:
			if current := s.provider.HTTPCapture(); current != manager {
				return status.Error(codes.Unavailable, "HTTP capture restarted")
			}
			continue
		}
		timer := time.NewTimer(httpCaptureBatchDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *httpCaptureServer) ListRecords(_ context.Context, request *mitmapi.ListRecordsRequest) (*mitmapi.RecordList, error) {
	manager, err := s.manager()
	if err != nil {
		return nil, err
	}
	result := manager.List(capture.Filter{
		Search:       request.Search,
		Host:         request.Host,
		ConnectionID: request.ConnectionId,
		Limit:        int(request.Limit),
		Before:       request.Before,
	})
	list := &mitmapi.RecordList{
		Instance:   result.Instance,
		NextBefore: result.NextBefore,
		Status:     s.captureStatus(manager, result.Stats),
		Records:    make([]*mitmapi.HTTPRecord, 0, len(result.Records)),
	}
	for i := range result.Records {
		list.Records = append(list.Records, captureRecord(&result.Records[i]))
	}
	return list, nil
}

func (s *httpCaptureServer) GetRecord(_ context.Context, request *mitmapi.GetRecordRequest) (*mitmapi.HTTPRecord, error) {
	manager, err := s.manager()
	if err != nil {
		return nil, err
	}
	if request.Instance != "" && request.Instance != manager.Instance() {
		return nil, status.Error(codes.FailedPrecondition, "capture instance changed")
	}
	record, ok := manager.Get(request.Id)
	if !ok {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	return captureRecord(&record), nil
}

func (s *httpCaptureServer) GetBody(request *mitmapi.GetBodyRequest, stream grpc.ServerStreamingServer[mitmapi.BodyChunk]) error {
	manager, err := s.manager()
	if err != nil {
		return err
	}
	if request.Offset < 0 || request.Length < 0 {
		return status.Error(codes.InvalidArgument, "offset and length must not be negative")
	}
	side := flow.Request
	if request.Side == mitmapi.BodySide_BODY_SIDE_RESPONSE {
		side = flow.Response
	}
	result, err := manager.GetBody(capture.BodyRequest{
		ID:       request.Id,
		Instance: request.Instance,
		Side:     side,
		Offset:   request.Offset,
		Length:   request.Length,
		Decoded:  request.Decoded,
	})
	if err != nil {
		switch {
		case errors.Is(err, capture.ErrNotFound):
			return status.Error(codes.NotFound, err.Error())
		case errors.Is(err, capture.ErrRange):
			return status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, capture.ErrReset):
			return status.Error(codes.FailedPrecondition, err.Error())
		}
		return status.Error(codes.Internal, err.Error())
	}
	offset := request.Offset
	data := result.Data
	for first := true; first || len(data) > 0; first = false {
		n := min(len(data), httpCaptureChunkSize)
		err = stream.Send(&mitmapi.BodyChunk{
			Data:         data[:n],
			Truncated:    result.Truncated,
			Encoding:     result.Encoding,
			Total:        result.Total,
			OriginalSize: result.Original,
			Saved:        result.Saved,
			Complete:     result.Complete,
			DecodeError:  result.DecodeError,
			Offset:       offset,
		})
		if err != nil {
			return err
		}
		data = data[n:]
		offset += int64(n)
	}
	return nil
}

func (s *httpCaptureServer) Clear(context.Context, *emptypb.Empty) (*mitmapi.CaptureStatus, error) {
	manager, err := s.manager()
	if err != nil {
		return nil, err
	}
	manager.Clear()
	return s.captureStatus(manager, manager.Stats()), nil
}

func (s *httpCaptureServer) GetStatus(context.Context, *emptypb.Empty) (*mitmapi.CaptureStatus, error) {
	manager, err := s.manager()
	if err != nil {
		return nil, err
	}
	return s.captureStatus(manager, manager.Stats()), nil
}

func (s *httpCaptureServer) captureStatus(manager *capture.Manager, stats capture.Stats) *mitmapi.CaptureStatus {
	options := manager.Options()
	return &mitmapi.CaptureStatus{
		Instance:     manager.Instance(),
		Enabled:      options.Enabled,
		BodyEnabled:  options.Enabled && options.Body,
		RecordCount:  uint32(stats.Records),
		InProgress:   uint32(stats.InProgress),
		ByteEstimate: stats.Bytes,
		MaxMemory:    stats.MaxMemory,
		MaxRecords:   uint32(stats.MaxRecords),
		Total:        stats.Total,
		Evicted:      stats.Evicted,
		BodyDropped:  stats.BodyDropped,
	}
}

// captureViews turns a poll result into payloads of about budget bytes each.
// Only the first payload carries Reset and Gap; each later one appends events.
// Incremental payloads resume from their own last sequence number; the
// payloads of a snapshot keep the cursor at 0 until the last one.
func captureViews(view capture.View, budget int) []*mitmapi.CapturePayload {
	newPayload := func() *mitmapi.CapturePayload {
		return &mitmapi.CapturePayload{
			Instance: view.Instance,
			Seq:      view.Seq,
			Floor:    view.Floor,
			Status: &mitmapi.CaptureStatus{
				Instance:     view.Instance,
				RecordCount:  uint32(view.Stats.Records),
				InProgress:   uint32(view.Stats.InProgress),
				ByteEstimate: view.Stats.Bytes,
				MaxMemory:    view.Stats.MaxMemory,
				MaxRecords:   uint32(view.Stats.MaxRecords),
				Total:        view.Stats.Total,
				Evicted:      view.Stats.Evicted,
				BodyDropped:  view.Stats.BodyDropped,
			},
		}
	}
	current := newPayload()
	current.Reset_ = view.Reset
	current.Gap = view.Gap
	payloads := []*mitmapi.CapturePayload{current}
	used := 0
	for i := range view.Events {
		event := &view.Events[i]
		kind := mitmapi.EventKind_EVENT_KIND_UPDATE
		switch event.Kind {
		case capture.EventNew:
			kind = mitmapi.EventKind_EVENT_KIND_NEW
		case capture.EventDone:
			kind = mitmapi.EventKind_EVENT_KIND_DONE
		}
		item := &mitmapi.CaptureEvent{Kind: kind, Record: captureRecord(&event.Record)}
		size := proto.Size(item)
		if used > 0 && used+size > budget {
			if view.Reset {
				// A snapshot is ordered by creation, so a middle payload has
				// no safe cursor; only the last one advances it.
				current.Seq = 0
			} else {
				current.Seq = lastSeq(current)
			}
			current = newPayload()
			payloads = append(payloads, current)
			used = 0
		}
		current.Events = append(current.Events, item)
		used += size
	}
	return payloads
}

func lastSeq(payload *mitmapi.CapturePayload) uint64 {
	return payload.Events[len(payload.Events)-1].Record.Seq
}

func captureHeaders(headers []flow.Header) []*mitmapi.HTTPHeader {
	if len(headers) == 0 {
		return nil
	}
	result := make([]*mitmapi.HTTPHeader, len(headers))
	for i := range headers {
		result[i] = &mitmapi.HTTPHeader{Name: headers[i].Name, Value: headers[i].Value}
	}
	return result
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func captureRecord(r *capture.Record) *mitmapi.HTTPRecord {
	record := &mitmapi.HTTPRecord{
		Id:                    r.ID,
		Instance:              r.Instance,
		Seq:                   r.Seq,
		CreatedSeq:            r.CreatedSeq,
		ConnectionId:          r.ConnectionID,
		RequestIndex:          r.RequestIndex,
		Method:                r.Method,
		Scheme:                r.Scheme,
		Authority:             r.Authority,
		Host:                  r.Host,
		Path:                  r.Path,
		Url:                   r.URL,
		Proto:                 r.Proto,
		Status:                int32(r.Status),
		RequestHeaders:        captureHeaders(r.RequestHeaders),
		ResponseHeaders:       captureHeaders(r.ResponseHeaders),
		RequestTrailers:       captureHeaders(r.RequestTrailers),
		ResponseTrailers:      captureHeaders(r.ResponseTrailers),
		RequestBytes:          r.RequestBytes,
		ResponseBytes:         r.ResponseBytes,
		RequestBodySaved:      r.RequestBodySaved,
		ResponseBodySaved:     r.ResponseBodySaved,
		RequestBodyStored:     r.RequestBodyStored,
		ResponseBodyStored:    r.ResponseBodyStored,
		RequestBodyTruncated:  r.RequestBodyTruncated,
		ResponseBodyTruncated: r.ResponseBodyTruncated,
		BodyDropped:           r.BodyDropped,
		RequestEncoding:       r.RequestEncoding,
		ResponseEncoding:      r.ResponseEncoding,
		State:                 mitmapi.RecordState(r.State),
		Error:                 r.Error,
		Unverified:            r.Unverified,
		Rewritten:             r.Rewritten,
		Rewrites:              rewriteHitsToProto(r.Rewrites),
		Timing: &mitmapi.HTTPTiming{
			Start:           unixNano(r.Timing.Start),
			RequestHeaders:  unixNano(r.Timing.RequestHeaders),
			RequestBody:     unixNano(r.Timing.RequestBody),
			FirstByte:       unixNano(r.Timing.FirstByte),
			ResponseHeaders: unixNano(r.Timing.ResponseHeaders),
			ResponseBody:    unixNano(r.Timing.ResponseBody),
			End:             unixNano(r.Timing.End),
			Dns:             int64(r.Timing.DNS),
			Connect:         int64(r.Timing.Connect),
			Tls:             int64(r.Timing.TLS),
		},
	}
	for _, code := range r.Interim {
		record.Interim = append(record.Interim, int32(code))
	}
	if c := r.Connection; c != nil {
		record.Connection = &mitmapi.HTTPConnection{
			Id:           c.ID,
			Source:       c.Source,
			Destination:  c.Destination,
			Host:         c.Host,
			Inbound:      c.Inbound,
			InboundType:  c.InboundType,
			Outbound:     c.Outbound,
			OutboundType: c.OutboundType,
			Rule:         c.Rule,
			ProcessName:  c.ProcessName,
			ProcessPath:  c.ProcessPath,
			ProcessId:    c.ProcessID,
			User:         c.User,
		}
	}
	return record
}

func rewriteHitsToProto(hits []flow.RewriteHit) []*mitmapi.HTTPRewriteHit {
	if len(hits) == 0 {
		return nil
	}
	result := make([]*mitmapi.HTTPRewriteHit, len(hits))
	for i := range hits {
		hit := &hits[i]
		out := &mitmapi.HTTPRewriteHit{
			Kind:   hit.Kind,
			Rule:   hit.Rule,
			Action: hit.Action,
			Side:   hit.Side,
			Target: hit.Target,
			Status: int32(hit.Status),
		}
		if run := hit.Run; run != nil {
			out.Run = &mitmapi.HTTPScriptRun{
				Tag:        hit.Target,
				Phase:      run.Phase,
				DurationUs: run.Duration.Microseconds(),
				Error:      run.Error,
				Reason:     run.Reason,
			}
			for _, line := range run.Logs {
				out.Run.Logs = append(out.Run.Logs, &mitmapi.HTTPScriptLog{Level: line.Level, Message: line.Message})
			}
		}
		for j := range hit.Changes {
			change := &hit.Changes[j]
			out.Changes = append(out.Changes, &mitmapi.HTTPRewriteChange{
				Op:        change.Op,
				Name:      change.Name,
				Before:    change.Before,
				HadBefore: change.HadBefore,
				After:     change.After,
				HasAfter:  change.HasAfter,
			})
		}
		result[i] = out
	}
	return result
}
