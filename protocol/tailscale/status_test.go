//go:build with_gvisor

package tailscale

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
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

func TestStatusUDPPathAnnotation(t *testing.T) {
	manager := newUDPPathManager(context.Background(), newCaptureLogger(), testUDPPathConfig(t), nil, "proxy-out", nil)
	manager.refresh(testUDPPathRecords(), nil)
	status := convertTailscaleStatus(&ipnstate.Status{})
	peers := []*adapter.TailscalePeer{
		{CurAddr: "203.0.113.7:41641", Relay: "hkg"},
		{CurAddr: "198.51.100.9:41641"},
		{CurAddr: "192.0.2.50:41641"},
		{Relay: "hkg"},
		{},
	}
	status.UserGroups = []*adapter.TailscaleUserGroup{{Peers: peers}}
	status.ExitNode = &adapter.TailscalePeer{CurAddr: "192.0.2.51:41641"}
	manager.annotateStatus(status)
	want := []string{"direct", "relay", "detour", "relay", ""}
	for index, peer := range peers {
		if peer.UDPPath != want[index] {
			t.Errorf("peer %d (%q, %q): udp path %q, want %q", index, peer.CurAddr, peer.Relay, peer.UDPPath, want[index])
		}
	}
	if status.ExitNode.UDPPath != "detour" {
		t.Errorf("exit node udp path %q", status.ExitNode.UDPPath)
	}
	if count := len(manager.logged); count != 0 {
		t.Errorf("status classification must not log decisions, logged %d", count)
	}
}

func TestStatusCopiesPeerAddresses(t *testing.T) {
	peer := convertTailscalePeer(&ipnstate.PeerStatus{CurAddr: "203.0.113.7:41641", Relay: "hkg"})
	if peer.CurAddr != "203.0.113.7:41641" || peer.Relay != "hkg" || peer.UDPPath != "" {
		t.Fatalf("peer addresses: %+v", peer)
	}
}
