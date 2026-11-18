package trafficcontrol

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Refusals of one source address, destination and rule count on one
// closed record; another destination gets its own.
func TestRejectedConnectionMerges(t *testing.T) {
	m := NewManager(nil)
	metadata := adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.168.1.2:50000"),
		Destination: M.ParseSocksaddr("203.0.113.1:443"),
		Domain:      "ads.example.com",
	}
	m.RejectedConnection(context.Background(), metadata, nil)
	metadata.Source = M.ParseSocksaddr("192.168.1.2:50001")
	m.RejectedConnection(context.Background(), metadata, nil)
	closed := m.ClosedConnections()
	if len(closed) != 1 || closed[0].Rejects.Load() != 2 || closed[0].OutboundType != RejectOutboundType || closed[0].ClosedAt.IsZero() {
		t.Fatalf("merged: %d records", len(closed))
	}
	metadata.Destination = M.ParseSocksaddr("203.0.113.2:443")
	m.RejectedConnection(context.Background(), metadata, nil)
	if closed = m.ClosedConnections(); len(closed) != 2 || closed[1].Rejects.Load() != 1 {
		t.Fatalf("another destination: %d records", len(closed))
	}
}
