package group

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/grouphealth"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// A probe by one group changes the selection of every group sharing
// the member, as the store is shared.
func TestProbeByOneGroupFailsOverAnother(t *testing.T) {
	store := grouphealth.NewStore()
	nodes := policyNodes("a", "b", "c")
	a, b, c := nodes[0], nodes[1], nodes[2]
	first := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, []adapter.Outbound{a, b})
	second := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, []adapter.Outbound{a, c})
	for _, g := range []*Group{first, second} {
		g.health = store
		g.unsubscribe = store.Subscribe(g.memberChanged)
		defer g.Close()
		if got := g.Selected(N.NetworkTCP); got != a {
			t.Fatalf("selected %s, want a", got.Tag())
		}
	}
	store.ObserveProbe("a", errors.New("down"))
	if got := second.Selected(N.NetworkTCP); got != c {
		t.Fatalf("other group selected %s after a went down, want c", got.Tag())
	}
	if got := first.Selected(N.NetworkTCP); got != b {
		t.Fatalf("selected %s after a went down, want b", got.Tag())
	}
	second.Close()
	store.ObserveProbe("a", nil)
	if got := first.Selected(N.NetworkTCP); got != a {
		t.Fatalf("selected %s after a recovered, want a", got.Tag())
	}
	if got := second.Selected(N.NetworkTCP); got != c {
		t.Fatal("a closed group still followed the store")
	}
}

// A routed connection through a nested load balance group is reported
// by the member it went through, not the group's representative.
func TestNestedLoadBalanceReportsMemberOfConnection(t *testing.T) {
	nodes := policyNodes("n1", "n2")
	inner := newLoadBalanceTestGroup(t, C.LoadBalanceRoundRobin, false, nodes)
	outer := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, []adapter.Outbound{inner})
	outer.health = inner.health
	failure := errors.New("refused")
	for i := range 3 {
		metadata := lbMetadata("192.0.2.1", fmt.Sprintf("site%d.com", i))
		metadata.OutboundChain = []adapter.Outbound{outer, inner, nodes[1]}
		outer.ReportDial(inner, metadata, adapter.GroupDialReport{Network: N.NetworkTCP, Err: failure})
	}
	if state := outer.health.State("n1"); state != adapter.GroupMemberUnknown {
		t.Fatalf("failures through n2 changed n1 to %v", state)
	}
	if state := outer.health.State("n2"); state == adapter.GroupMemberUnknown || state == adapter.GroupMemberUp {
		t.Fatalf("failures through n2 left it %v", state)
	}
}

// A probe its caller gave up on says nothing of the member.
func TestCanceledProbeKeepsMemberState(t *testing.T) {
	members := policyNodes("a", "b")
	g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, members)
	g.link = "http://192.0.2.1/"
	setState(g, "a", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.probeMember(ctx, members[0]); err == nil {
		t.Fatal("canceled probe succeeded")
	}
	if state := g.health.State("a"); state != adapter.GroupMemberUp {
		t.Fatalf("canceled probe made the member %v", state)
	}
}

type recordedFlow struct{ closed bool }

func (f *recordedFlow) CloseFlow() { f.closed = true }

// A forwarded flow through a load balance member is interrupted when
// that member goes down, and only then.
func TestLoadBalanceInterruptsFlowsOfDownMember(t *testing.T) {
	members := policyNodes("a", "b")
	g := newLoadBalanceTestGroup(t, C.LoadBalanceRoundRobin, true, members)
	flows := make([]*recordedFlow, 2)
	for i, member := range members {
		factory := g.MemberFlowTrackerFactory(member)
		if factory == nil {
			t.Fatal("no member flow tracker")
		}
		flows[i] = &recordedFlow{}
		factory().AttachFlow(flows[i])
	}
	g.memberDown(members[0])
	if !flows[0].closed || flows[1].closed {
		t.Fatalf("flows closed %v %v, want only a's", flows[0].closed, flows[1].closed)
	}
	fallback := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, true, members)
	if fallback.MemberFlowTrackerFactory(members[0]) != nil {
		t.Fatal("a fallback group tracks flows per member")
	}
}

// Every URL test history has a store of its own, which goes with it.
func TestHealthStorePerHistory(t *testing.T) {
	first, second := urltest.NewHistoryStorage(), urltest.NewHistoryStorage()
	if grouphealth.For(first) != grouphealth.For(first) || grouphealth.For(first) == grouphealth.For(second) {
		t.Fatal("stores are not per history")
	}
	if grouphealth.For(nil) != grouphealth.For((*urltest.HistoryStorage)(nil)) {
		t.Fatal("histories without a store do not share one")
	}
}

// A group whose member is a group fails over once everything under that
// group is down, and returns once any of it recovers, whichever group
// the store tells first: the member is matched by all it holds, not by
// what it uses at the moment.
func TestNestedGroupAllDownFailsOverParent(t *testing.T) {
	for _, innerType := range []string{C.TypeLoadBalance, C.TypeFallback} {
		t.Run(innerType, func(t *testing.T) {
			for range 20 {
				store := grouphealth.NewStore()
				nodes := policyNodes("n1", "n2", "z")
				var inner *Group
				if innerType == C.TypeLoadBalance {
					inner = newLoadBalanceTestGroup(t, C.LoadBalanceRoundRobin, false, nodes[:2])
				} else {
					inner = newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, nodes[:2])
				}
				outer := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, []adapter.Outbound{inner, nodes[2]})
				for _, g := range []*Group{inner, outer} {
					g.health = store
					g.unsubscribe = store.Subscribe(g.memberChanged)
				}
				if got := outer.Selected(N.NetworkTCP); got != inner {
					t.Fatalf("selected %s, want the nested group", got.Tag())
				}
				store.ObserveProbe("n1", errors.New("down"))
				if got := outer.Selected(N.NetworkTCP); got != inner {
					t.Fatalf("selected %s with n2 left, want the nested group", got.Tag())
				}
				store.ObserveProbe("n2", errors.New("down"))
				if got := outer.Selected(N.NetworkTCP); got != nodes[2] {
					t.Fatalf("selected %s with the nested group all down, want z", got.Tag())
				}
				store.ObserveProbe("n2", nil)
				if got := outer.Selected(N.NetworkTCP); got != inner {
					t.Fatalf("selected %s after n2 recovered, want the nested group", got.Tag())
				}
				inner.Close()
				outer.Close()
			}
		})
	}
}

// A down member after the current one is probed by the periodic check,
// so that it is not left down once its recovery probes end.
func TestFallbackProbesDownMembersAfterCurrent(t *testing.T) {
	for _, noReturn := range []bool{false, true} {
		members := policyNodes("a", "b", "c")
		g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{noReturn: noReturn}, false, members)
		setState(g, "c", false)
		g.PerformUpdateCheck()
		if got := g.Selected(N.NetworkTCP); got != members[0] {
			t.Fatalf("selected %s, want a", got.Tag())
		}
		probed := g.strategy.probeSet(g)
		if len(probed) != 2 || probed[0] != members[0] || probed[1] != members[2] {
			t.Fatalf("noReturn %v: probe set %v, want a and c", noReturn, probed)
		}
	}
}

// A connection through a member a probe found down has it probed again,
// at most once a window, as nothing else probes a manual group's.
func TestRoutedSuccessReconfirmsDownMember(t *testing.T) {
	store := grouphealth.NewStore()
	now := time.Now()
	store.SetClock(func() time.Time { return now })
	store.ObserveProbe("a", errors.New("down"))
	if store.ObserveDial("a", "one.example", 3, nil) {
		t.Fatal("a connection right after the probe asked for another")
	}
	now = now.Add(2 * time.Minute)
	if !store.ObserveDial("a", "one.example", 3, nil) {
		t.Fatal("a connection through a member long down did not ask for a probe")
	}
	if store.ObserveDial("a", "one.example", 3, nil) {
		t.Fatal("a second connection asked for another probe in the same window")
	}
	if store.State("a") != adapter.GroupMemberDown {
		t.Fatal("a routed success made a down member up without a probe")
	}
}

func newFastestTestGroup(tag string, history *urltest.HistoryStorage, members []adapter.Outbound) *URLTest {
	tags := make([]string, len(members))
	for i, member := range members {
		tags[i] = member.Tag()
	}
	group := &URLTestGroup{outbounds: members, history: history, tolerance: 50, interruptGroup: interrupt.NewGroup()}
	fastest := &URLTest{Adapter: outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, tags), tags: tags, group: group}
	group.performUpdateCheck()
	return fastest
}

// A fallback group whose member is a fastest group leaves it when what
// it uses goes down, and the fastest group, idle from then on, would
// keep it: the fallback group has it choose again, by the history its
// probe just changed, and returns to it.
func TestFallbackRefreshesNestedFastestGroup(t *testing.T) {
	for _, viaStore := range []bool{false, true} {
		history := urltest.NewHistoryStorage()
		nodes := policyNodes("n1", "n2", "z")
		history.StoreURLTestHistory("n1", &adapter.URLTestHistory{Time: time.Now().Add(-time.Hour), Delay: 50})
		history.StoreURLTestHistory("n2", &adapter.URLTestHistory{Time: time.Now().Add(-time.Hour), Delay: 200})
		fastest := newFastestTestGroup("fastest", history, nodes[:2])
		if got := fastest.Selected(N.NetworkTCP); got != nodes[0] {
			t.Fatalf("fastest selected %s, want n1", got.Tag())
		}
		g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, []adapter.Outbound{fastest, nodes[2]})
		g.history = history
		g.health = grouphealth.For(history)
		g.link = "http://192.0.2.1/"
		g.unsubscribe = g.health.Subscribe(g.memberChanged)
		if viaStore {
			// Another group or URL test finds n1 down.
			history.DeleteURLTestHistory("n1")
			g.health.ObserveProbe("n1", errors.New("down"))
		} else {
			// The group's own periodic check finds it down.
			g.checkOutbounds(context.Background(), []adapter.Outbound{fastest}, true)
		}
		if state := g.health.State("n1"); state != adapter.GroupMemberDown {
			t.Fatalf("n1 %v, want down", state)
		}
		if got := fastest.Selected(N.NetworkTCP); got != nodes[1] {
			t.Fatalf("via store %v: fastest selected %s with n1 down, want n2", viaStore, got.Tag())
		}
		g.PerformUpdateCheck()
		if got := g.Selected(N.NetworkTCP); got != fastest {
			t.Fatalf("via store %v: selected %s, want the fastest group on n2", viaStore, got.Tag())
		}
		g.Close()
	}
}

// A test through a load balance group may go through any member, so it
// names none; through groups with one current member it names that.
func TestProbedTag(t *testing.T) {
	nodes := policyNodes("n1", "n2", "z")
	balance := newLoadBalanceTestGroup(t, C.LoadBalanceRoundRobin, false, nodes[:2])
	fallback := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, []adapter.Outbound{balance, nodes[2]})
	fallback.health = balance.health
	if tag := ProbedTag(balance, N.NetworkTCP); tag != "" {
		t.Fatalf("load balance group probed tag %q, want none", tag)
	}
	if tag := ProbedTag(fallback, N.NetworkTCP); tag != "" {
		t.Fatalf("fallback over a load balance group probed tag %q, want none", tag)
	}
	other := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, nodes[1:])
	if tag := ProbedTag(other, N.NetworkTCP); tag != "n2" {
		t.Fatalf("fallback probed tag %q, want n2", tag)
	}
	if tag := ProbedTag(nodes[0], N.NetworkTCP); tag != "n1" {
		t.Fatalf("node probed tag %q, want n1", tag)
	}
}
