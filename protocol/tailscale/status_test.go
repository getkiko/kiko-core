//go:build with_gvisor

package tailscale

import (
	"testing"
	"time"

	"github.com/sagernet/tailscale/health"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
)

func TestStatusHealthChangeSchedulesRefresh(t *testing.T) {
	if !statusNotificationChanged(&ipn.Notify{Health: &health.State{}}) {
		t.Fatal("health-only disconnect notification must refresh status")
	}
	if statusNotificationChanged(&ipn.Notify{}) {
		t.Fatal("empty notification should not schedule work")
	}
}

func TestStatusPreservesControlDisconnectWhileBackendRunning(t *testing.T) {
	before := time.Now().UnixMilli()
	status := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{Online: false}, Health: []string{"control connection lost"}}
	result := convertTailscaleStatus(status)
	if result.BackendState != "Running" || result.Self.Online || len(result.Health) != 1 || result.ObservedAt < before {
		t.Fatalf("disconnect state lost: %+v", result)
	}
	status.Health[0] = "changed"
	if result.Health[0] != "control connection lost" {
		t.Fatal("status must own health snapshot")
	}
}
