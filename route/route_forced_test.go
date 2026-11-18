package route

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type forcedManager struct {
	adapter.OutboundManager
	outbounds       map[string]adapter.Outbound
	defaultOutbound adapter.Outbound
}

func (m *forcedManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}

func (m *forcedManager) Default() adapter.Outbound { return m.defaultOutbound }

type forcedHandler struct {
	outbound.Adapter
	N.Dialer
	got chan adapter.InboundContext
}

func (h *forcedHandler) NewConnection(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	h.got <- metadata
}

type forcedTracker struct {
	seen    []adapter.InboundContext
	matched []adapter.Rule
}

func (t *forcedTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, rule adapter.Rule, _ adapter.Outbound) net.Conn {
	t.seen = append(t.seen, metadata)
	t.matched = append(t.matched, rule)
	metadata.MITM.SetConnection("tracked-1", "")
	return conn
}

func (t *forcedTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return conn
}

func (t *forcedTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type forcedEngine struct {
	adapter.MITMEngine
	decided int
}

func (e *forcedEngine) Decide(*adapter.InboundContext) *adapter.MITMState {
	e.decided++
	return adapter.NewMITMState(adapter.MITMStatusPending, "")
}

func newForcedRouter() (*Router, *forcedHandler, *forcedHandler, *forcedTracker, *forcedEngine) {
	chosen := &forcedHandler{Adapter: outbound.NewAdapter("direct", "chosen", []string{N.NetworkTCP}, nil), got: make(chan adapter.InboundContext, 1)}
	fallback := &forcedHandler{Adapter: outbound.NewAdapter("direct", "fallback", []string{N.NetworkTCP}, nil), got: make(chan adapter.InboundContext, 1)}
	manager := &forcedManager{
		outbounds:       map[string]adapter.Outbound{"chosen": chosen, "fallback": fallback},
		defaultOutbound: fallback,
	}
	tracker := &forcedTracker{}
	engine := &forcedEngine{}
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: manager,
		trackers: []adapter.ConnectionTracker{tracker},
		mitm:     engine,
	}
	return router, chosen, fallback, tracker, engine
}

func forcedMetadata(state *adapter.MITMState, forced string) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound:        adapter.InboundKikoInternal,
		InboundType:    adapter.InboundKikoInternal,
		Internal:       true,
		Destination:    M.ParseSocksaddrHostPort("example.com", 443),
		Domain:         "example.com",
		ForcedOutbound: forced,
		MITM:           state,
	}
}

// A forced outbound takes the connection without rule matching; the tracker
// sees it and the MITM engine is not asked.
func TestForcedOutboundSkipsRulesAndMITM(t *testing.T) {
	router, chosen, fallback, tracker, engine := newForcedRouter()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	state := adapter.NewMITMState(adapter.MITMStatusSkipped, "replay")
	err := router.routeConnection(context.Background(), server, forcedMetadata(state, "chosen"), nil)
	require.NoError(t, err)
	metadata := <-chosen.got
	require.Empty(t, fallback.got)
	require.Equal(t, "chosen", metadata.RouteOutbound)
	require.Len(t, metadata.OutboundChain, 1)
	require.Same(t, state, metadata.MITM)
	require.Equal(t, adapter.MITMStatusSkipped, metadata.MITM.Status())
	require.Zero(t, engine.decided)
	require.Len(t, tracker.seen, 1)
	require.Nil(t, tracker.matched[0])
	require.Equal(t, "tracked-1", state.Connection().ID)
}

func TestForcedOutboundNotFound(t *testing.T) {
	router, chosen, fallback, tracker, _ := newForcedRouter()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	err := router.routeConnection(context.Background(), server, forcedMetadata(adapter.NewMITMState(adapter.MITMStatusSkipped, "replay"), "missing"), nil)
	require.ErrorContains(t, err, "outbound not found: missing")
	require.Empty(t, chosen.got)
	require.Empty(t, fallback.got)
	require.Empty(t, tracker.seen)
}
