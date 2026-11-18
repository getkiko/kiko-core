package daemon

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type mitmTestOutbound struct {
	adapter.Outbound
}

func (o *mitmTestOutbound) Tag() string { return "direct" }

func (o *mitmTestOutbound) Type() string { return C.TypeDirect }

func TestTrafficUpdatesCarryMITMChanges(t *testing.T) {
	manager := trafficcontrol.NewManager()
	state := adapter.NewMITMState(adapter.MITMStatusPending, "")
	client, peer := net.Pipe()
	defer peer.Close()
	conn := manager.RoutedConnection(t.Context(), client, adapter.InboundContext{
		Network:       "tcp",
		Protocol:      C.ProtocolTLS,
		Domain:        "example.com",
		OutboundChain: []adapter.Outbound{&mitmTestOutbound{}},
		MITM:          state,
	}, nil, &mitmTestOutbound{})
	s := &StartedService{}
	snapshots := make(map[uuid.UUID]connectionSnapshot)

	events := s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	require.Equal(t, ConnectionEventType_CONNECTION_EVENT_NEW, events[0].Type)
	require.Equal(t, "pending", events[0].Connection.Mitm)

	require.Empty(t, s.buildTrafficUpdates(manager, nil, snapshots))

	state.SetDecrypted()
	state.AddRequest()
	events = s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	require.Equal(t, ConnectionEventType_CONNECTION_EVENT_UPDATE, events[0].Type)
	require.NotNil(t, events[0].Connection)
	require.Equal(t, "decrypted", events[0].Connection.Mitm)
	require.Equal(t, int64(1), events[0].Connection.HttpRequests)

	require.Empty(t, s.buildTrafficUpdates(manager, nil, snapshots))

	// Traffic alone carries only deltas.
	go func() {
		buffer := make([]byte, 5)
		_, _ = peer.Read(buffer)
	}()
	_, err := conn.Write([]byte("hello"))
	require.NoError(t, err)
	events = s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	require.Equal(t, int64(5), events[0].UplinkDelta+events[0].DownlinkDelta)
	require.Nil(t, events[0].Connection)

	state.AddRequest()
	state.SetFailed("upstream closed")
	conn.Close()
	events = s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	require.Equal(t, ConnectionEventType_CONNECTION_EVENT_CLOSED, events[0].Type)
	require.Equal(t, "failed", events[0].Connection.Mitm)
	require.Equal(t, int64(2), events[0].Connection.HttpRequests)
	require.Equal(t, "upstream closed", events[0].Connection.MitmError)
}

func TestConnectionProtoWithoutMITM(t *testing.T) {
	connection := buildConnectionProto(&trafficcontrol.TrackerMetadata{Upload: new(atomic.Int64), Download: new(atomic.Int64)}, nil)
	require.Empty(t, connection.Mitm)
	require.Zero(t, connection.HttpRequests)
	require.Empty(t, connection.MitmError)
}

func TestUnverifiedDecryptedConnectionIsMarked(t *testing.T) {
	manager := trafficcontrol.NewManager()
	state := adapter.NewMITMState(adapter.MITMStatusPending, "")
	client, peer := net.Pipe()
	defer peer.Close()
	conn := manager.RoutedConnection(t.Context(), client, adapter.InboundContext{
		Network:       "tcp",
		Protocol:      C.ProtocolTLS,
		OutboundChain: []adapter.Outbound{&mitmTestOutbound{}},
		MITM:          state,
	}, nil, &mitmTestOutbound{})
	defer conn.Close()
	s := &StartedService{}
	snapshots := make(map[uuid.UUID]connectionSnapshot)
	events := s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	// The tracker links its identity to the state for the capture records.
	require.Equal(t, events[0].Connection.Id, state.Connection().ID)

	state.SetDecrypted()
	events = s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	require.Empty(t, events[0].Connection.MitmError)

	state.SetUnverified()
	events = s.buildTrafficUpdates(manager, nil, snapshots)
	require.Len(t, events, 1)
	require.Equal(t, "unverified", events[0].Connection.MitmError)
	require.Equal(t, "decrypted", events[0].Connection.Mitm)
}

type captureEngine struct {
	adapter.MITMEngine
	manager *capture.Manager
}

func (e *captureEngine) Capture() *capture.Manager { return e.manager }

func TestStartedServiceHTTPCaptureProvider(t *testing.T) {
	s := &StartedService{}
	require.Nil(t, s.HTTPCapture())

	manager := capture.New(capture.Options{Enabled: true})
	ctx := service.ContextWithDefaultRegistry(t.Context())
	service.MustRegister[adapter.MITMEngine](ctx, &captureEngine{manager: manager})
	s.instance = &Instance{ctx: ctx}
	require.Same(t, manager, s.HTTPCapture())

	// An engine that records nothing yields nil, which the service reports as FailedPrecondition.
	s.instance = &Instance{ctx: service.ContextWithDefaultRegistry(t.Context())}
	require.Nil(t, s.HTTPCapture())
	service.MustRegister[adapter.MITMEngine](s.instance.ctx, &captureEngine{})
	require.Nil(t, s.HTTPCapture())
}
