package mitm

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"

	"github.com/stretchr/testify/require"
)

// Connections the core opens for itself are never decrypted, even to hosts
// the include list selects.
func TestDecideSkipsInternalInbound(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"*.example.com"}, nil))
	metadata := tlsMetadata("a.example.com", "10.0.0.1:443")
	require.Equal(t, adapter.MITMStatusPending, engine.Decide(metadata).Status())
	metadata.Inbound = adapter.InboundKikoInternal
	require.Equal(t, adapter.MITMStatusPending, engine.Decide(metadata).Status(), "the inbound name alone does not mark a connection internal")
	metadata.Internal = true
	require.Nil(t, engine.Decide(metadata))
	status, reason := engine.Explain(metadata)
	require.Equal(t, "skipped", status)
	require.Equal(t, ReasonInternal, reason)
}

// The first exchange of a connection carries the setup durations, later ones
// none.
func TestTimedObserverReportsSetupOnce(t *testing.T) {
	manager := capture.New(capture.Options{Enabled: true})
	observer := &timedObserver{Observer: manager.Observer(), connect: 7 * time.Millisecond, tls: 11 * time.Millisecond}
	info := &flow.ConnectionInfo{ID: "c1"}
	first := observer.NewExchange(info)
	second := observer.NewExchange(info)
	first.Finish(nil)
	second.Finish(nil)
	record, ok := manager.Get(capture.ExchangeID(first))
	require.True(t, ok)
	require.Equal(t, 7*time.Millisecond, record.Timing.Connect)
	require.Equal(t, 11*time.Millisecond, record.Timing.TLS)
	record, ok = manager.Get(capture.ExchangeID(second))
	require.True(t, ok)
	require.Zero(t, record.Timing.Connect)
	require.Zero(t, record.Timing.TLS)
}
