package route

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
)

type groupRouteNode struct {
	adapter.Outbound
	tag string
}

func (o *groupRouteNode) Tag() string { return o.tag }

type groupRouteGroup struct {
	adapter.Outbound
	tag      string
	selected adapter.Outbound
	eligible map[adapter.Outbound]bool
	dials    []adapter.GroupDialReport
	members  []adapter.Outbound
	closes   []adapter.GroupCloseReport
}

func (g *groupRouteGroup) Tag() string                                        { return g.tag }
func (g *groupRouteGroup) All() []string                                      { return nil }
func (g *groupRouteGroup) Selected(string) adapter.Outbound                   { return g.selected }
func (g *groupRouteGroup) AttachConnection(io.Closer) func()                  { return func() {} }
func (g *groupRouteGroup) URLTest(context.Context) (map[string]uint16, error) { return nil, nil }
func (g *groupRouteGroup) PerformUpdateCheck()                                {}
func (g *groupRouteGroup) ReportDial(member adapter.Outbound, _ *adapter.InboundContext, report adapter.GroupDialReport) {
	g.members = append(g.members, member)
	g.dials = append(g.dials, report)
}

type contextualRouteGroup struct{ *groupRouteGroup }

func (g contextualRouteGroup) SelectFor(string, *adapter.InboundContext, bool) adapter.Outbound {
	return g.selected
}

func (g contextualRouteGroup) Eligible(_ string, member adapter.Outbound) bool {
	return g.eligible[member]
}

type learningRouteGroup struct{ *groupRouteGroup }

func (g learningRouteGroup) ReportClose(_ adapter.Outbound, _ *adapter.InboundContext, report adapter.GroupCloseReport) {
	g.closes = append(g.closes, report)
}

func TestReportGroupDialReportsEachGroupWithItsMember(t *testing.T) {
	node := &groupRouteNode{tag: "node"}
	inner := &groupRouteGroup{tag: "inner", selected: node}
	outer := &groupRouteGroup{tag: "outer", selected: inner}
	metadata := &adapter.InboundContext{OutboundChain: []adapter.Outbound{outer, inner, node}}
	failure := errors.New("refused")
	reportGroupDial(metadata, N.NetworkTCP, time.Now(), failure)
	if len(outer.members) != 1 || outer.members[0] != inner || !errors.Is(outer.dials[0].Err, failure) {
		t.Fatalf("outer reports %v", outer.members)
	}
	if len(inner.members) != 1 || inner.members[0] != node {
		t.Fatalf("inner reports %v", inner.members)
	}
}

// URLTest's reaction to a failed dial stays the router deleting the
// member's delay history, whatever groups are told besides.
func TestFailedDialStillDeletesURLTestHistory(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	node := &groupRouteNode{tag: "node"}
	group := &groupRouteGroup{tag: "auto", selected: node}
	metadata := &adapter.InboundContext{OutboundChain: []adapter.Outbound{group, node}}
	manager := &ConnectionManager{urlTestHistory: history}
	manager.deleteURLTestHistory(metadata.OutboundChain)
	reportGroupDial(metadata, N.NetworkTCP, time.Now(), errors.New("refused"))
	if history.LoadURLTestHistory("node") != nil {
		t.Fatal("history of the failed member kept")
	}
	if len(group.dials) != 1 {
		t.Fatal("group not told of the failed dial")
	}
}

func TestChainStillSelected(t *testing.T) {
	a, b := &groupRouteNode{tag: "a"}, &groupRouteNode{tag: "b"}
	plain := &groupRouteGroup{tag: "plain", selected: a}
	if !chainStillSelected([]adapter.Outbound{plain, a}, N.NetworkTCP) {
		t.Fatal("unchanged selection reported changed")
	}
	plain.selected = b
	if chainStillSelected([]adapter.Outbound{plain, a}, N.NetworkTCP) {
		t.Fatal("changed selection reported unchanged")
	}
	balanced := contextualRouteGroup{&groupRouteGroup{tag: "lb", selected: b, eligible: map[adapter.Outbound]bool{a: true}}}
	if !chainStillSelected([]adapter.Outbound{balanced, a}, N.NetworkTCP) {
		t.Fatal("eligible member of a load balance group reported changed")
	}
	balanced.eligible[a] = false
	if chainStillSelected([]adapter.Outbound{balanced, a}, N.NetworkTCP) {
		t.Fatal("ineligible member reported unchanged")
	}
}

func TestMeterGroupConnReportsClose(t *testing.T) {
	node := &groupRouteNode{tag: "node"}
	plain := &groupRouteGroup{tag: "plain", selected: node}
	client, server := net.Pipe()
	defer server.Close()
	metadata := &adapter.InboundContext{OutboundChain: []adapter.Outbound{plain, node}}
	if conn, _ := meterGroupConn(metadata, client, nil); conn != client {
		t.Fatal("connection through groups that do not learn was wrapped")
	}
	learner := learningRouteGroup{&groupRouteGroup{tag: "smart", selected: node}}
	metadata.OutboundChain = []adapter.Outbound{learner, node}
	var closed error
	conn, onClose := meterGroupConn(metadata, client, func(err error) { closed = err })
	go func() {
		buffer := make([]byte, 5)
		_, _ = io.ReadFull(server, buffer)
		time.Sleep(5 * time.Millisecond)
		_, _ = server.Write([]byte("response"))
	}()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("done")
	onClose(failure)
	if !errors.Is(closed, failure) {
		t.Fatal("original close handler not called")
	}
	if len(learner.closes) != 1 {
		t.Fatal("close not reported")
	}
	report := learner.closes[0]
	if report.Upload != 5 || report.Download != 8 || report.FirstByte < 5*time.Millisecond || !errors.Is(report.Err, failure) {
		t.Fatalf("report %+v", report)
	}
}

type networkRouteNode struct{ groupRouteNode }

func (o *networkRouteNode) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

type rotatingRouteGroup struct {
	*groupRouteGroup
	choices []adapter.Outbound
	next    int
}

func (g *rotatingRouteGroup) SelectFor(_ string, _ *adapter.InboundContext, dryRun bool) adapter.Outbound {
	member := g.choices[g.next%len(g.choices)]
	if !dryRun {
		g.next++
	}
	return member
}

func (g *rotatingRouteGroup) Eligible(string, adapter.Outbound) bool { return true }

// A pre-match looks at a chain without choosing, so that a connection
// it leaves to routing advances a rotation once.
func TestResolveChainDryRunKeepsRotation(t *testing.T) {
	a, b := &networkRouteNode{groupRouteNode{tag: "a"}}, &networkRouteNode{groupRouteNode{tag: "b"}}
	group := &rotatingRouteGroup{groupRouteGroup: &groupRouteGroup{tag: "lb"}, choices: []adapter.Outbound{a, b}}
	for range 3 {
		chain, err := resolveChain(group, N.NetworkTCP, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		if chain[len(chain)-1] != a {
			t.Fatal("dry run advanced the rotation")
		}
	}
	chain, _ := resolveOutbound(group, N.NetworkTCP, nil)
	again, _ := resolveOutbound(group, N.NetworkTCP, nil)
	if chain[1] != a || again[1] != b {
		t.Fatal("routing did not advance the rotation")
	}
}
