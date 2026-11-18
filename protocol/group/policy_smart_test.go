package group

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

func smartTestGroup(t *testing.T, members []adapter.Outbound) (*Group, *time.Time) {
	g := newPolicyTestGroup(t, C.TypeSmart, &smartStrategy{}, false, members)
	now := time.Now()
	g.health.SetClock(func() time.Time { return now })
	return g, &now
}

func TestSmartPrefersReliableMember(t *testing.T) {
	members := policyNodes("fast", "steady")
	g, _ := smartTestGroup(t, members)
	for range 10 {
		g.health.ObserveOutcome("fast", true, 50*time.Millisecond, 0)
		g.health.ObserveOutcome("steady", true, 120*time.Millisecond, 0)
	}
	g.PerformUpdateCheck()
	if got := g.Selected(N.NetworkTCP); got != members[0] {
		t.Fatalf("selected %s, want fast", got.Tag())
	}
	g.switchedAt[0] = time.Time{}
	for range 10 {
		g.health.ObserveOutcome("fast", false, 0, 0)
	}
	g.PerformUpdateCheck()
	if got := g.Selected(N.NetworkTCP); got != members[1] {
		t.Fatalf("selected %s after failures, want steady", got.Tag())
	}
}

func TestSmartHysteresis(t *testing.T) {
	members := policyNodes("a", "b")
	g, _ := smartTestGroup(t, members)
	for range 10 {
		g.health.ObserveOutcome("a", true, 100*time.Millisecond, 0)
		g.health.ObserveOutcome("b", true, 200*time.Millisecond, 0)
	}
	g.PerformUpdateCheck()
	if g.Selected(N.NetworkTCP) != members[0] {
		t.Fatal("did not select a")
	}
	// b slightly better: within the switch ratio, a stays.
	for range 40 {
		g.health.ObserveOutcome("b", true, 70*time.Millisecond, 0)
	}
	g.PerformUpdateCheck()
	if g.Selected(N.NetworkTCP) != members[0] {
		t.Fatal("switched to a member less than clearly better")
	}
	// b much better, but a switch just happened: a stays until the dwell passes.
	for range 40 {
		g.health.ObserveOutcome("b", true, 30*time.Millisecond, 0)
	}
	g.switchedAt[0] = time.Now()
	g.PerformUpdateCheck()
	if g.Selected(N.NetworkTCP) != members[0] {
		t.Fatal("switched within the dwell")
	}
	g.switchedAt[0] = time.Now().Add(-2 * smartDwell)
	g.PerformUpdateCheck()
	if g.Selected(N.NetworkTCP) != members[1] {
		t.Fatal("did not switch to a clearly better member after the dwell")
	}
	// The current member going down switches at once, dwell or not.
	g.switchedAt[0] = time.Now()
	setState(g, "b", false)
	g.PerformUpdateCheck()
	if g.Selected(N.NetworkTCP) != members[0] {
		t.Fatal("did not leave a down member at once")
	}
}

func TestSmartUsesProbeDelayWithoutTraffic(t *testing.T) {
	members := policyNodes("slow", "quick")
	g, _ := smartTestGroup(t, members)
	g.history.StoreURLTestHistory("slow", &adapter.URLTestHistory{Time: time.Now(), Delay: 400})
	g.history.StoreURLTestHistory("quick", &adapter.URLTestHistory{Time: time.Now(), Delay: 80})
	g.PerformUpdateCheck()
	if got := g.Selected(N.NetworkTCP); got != members[1] {
		t.Fatalf("selected %s, want quick", got.Tag())
	}
	status := g.GroupStatus()
	if status.Mode != C.GroupModeSmart || len(status.Members) != 2 || !status.Members[1].Active || status.Members[1].Score <= 0 {
		t.Fatalf("status %+v", status)
	}
}

func TestSmartReportClose(t *testing.T) {
	members := policyNodes("a")
	g, _ := smartTestGroup(t, members)
	g.ReportClose(members[0], nil, adapter.GroupCloseReport{FirstByte: 80 * time.Millisecond, Duration: 3 * time.Second, Upload: 1000, Download: 4 << 20})
	g.ReportClose(members[0], nil, adapter.GroupCloseReport{Duration: time.Second, Upload: 1000, Err: net.ErrClosed})
	g.ReportClose(members[0], nil, adapter.GroupCloseReport{Duration: time.Second})
	stats := g.health.Stats("a")
	if stats.SuccessWeight < 1.9 || stats.SuccessWeight > 2.1 || stats.Success < 0.49 || stats.Success > 0.51 {
		t.Fatalf("stats %+v, want one success and one failure", stats)
	}
	if stats.Rate <= 0 || stats.Latency < 79 || stats.Latency > 81 {
		t.Fatalf("stats %+v, want the transfer's rate and first byte", stats)
	}
}
