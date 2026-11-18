package group

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/grouphealth"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type policyTestNode struct {
	adapter.Outbound
	tag      string
	networks []string
}

func (o *policyTestNode) Tag() string  { return o.tag }
func (o *policyTestNode) Type() string { return "direct" }
func (o *policyTestNode) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("test node does not dial")
}

func (o *policyTestNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test node does not dial")
}

func (o *policyTestNode) Network() []string {
	if o.networks != nil {
		return o.networks
	}
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func policyNodes(tags ...string) []adapter.Outbound {
	nodes := make([]adapter.Outbound, len(tags))
	for i, tag := range tags {
		nodes[i] = &policyTestNode{tag: tag}
	}
	return nodes
}

// newPolicyTestGroup is a started group of members without health
// checks running, on a store of its own.
func newPolicyTestGroup(t *testing.T, groupType string, strategy groupStrategy, interrupt bool, members []adapter.Outbound) *Group {
	t.Helper()
	tags := make([]string, len(members))
	for i, member := range members {
		tags[i] = member.Tag()
	}
	g, err := newGroup(context.Background(), log.NewNOPFactory().Logger(), groupType, "group", tags, option.GroupHealthCheckOptions{}, interrupt, strategy)
	if err != nil {
		t.Fatal(err)
	}
	g.history = urltest.NewHistoryStorage()
	g.health = grouphealth.NewStore()
	g.members = members
	return g
}

func setState(g *Group, tag string, up bool) {
	var err error
	if !up {
		err = errors.New("down")
	}
	g.health.ObserveProbe(tag, err)
}

type closeRecorder struct{ closed bool }

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func TestFallbackUsesFirstAvailableMember(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(fmt.Sprint("interrupt=", interrupt), func(t *testing.T) {
			members := policyNodes("a", "b", "c")
			g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, interrupt, members)
			if got := g.Selected(N.NetworkTCP); got != members[0] {
				t.Fatalf("selected %v, want a", got.Tag())
			}
			conn := &closeRecorder{}
			detach := g.AttachConnection(conn)
			defer detach()
			setState(g, "a", false)
			g.PerformUpdateCheck()
			if got := g.Selected(N.NetworkTCP); got != members[1] {
				t.Fatalf("after a down selected %v, want b", got.Tag())
			}
			if conn.closed != interrupt {
				t.Fatalf("connection closed %v, want %v", conn.closed, interrupt)
			}
			setState(g, "b", false)
			g.PerformUpdateCheck()
			if got := g.Selected(N.NetworkTCP); got != members[2] {
				t.Fatalf("after b down selected %v, want c", got.Tag())
			}
			setState(g, "a", true)
			g.PerformUpdateCheck()
			if got := g.Selected(N.NetworkTCP); got != members[0] {
				t.Fatalf("after a recovered selected %v, want a", got.Tag())
			}
		})
	}
}

func TestFallbackNoReturnKeepsCurrentMember(t *testing.T) {
	members := policyNodes("a", "b")
	g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{noReturn: true}, false, members)
	setState(g, "a", false)
	g.PerformUpdateCheck()
	if got := g.Selected(N.NetworkTCP); got != members[1] {
		t.Fatalf("selected %v, want b", got.Tag())
	}
	setState(g, "a", true)
	g.PerformUpdateCheck()
	if got := g.Selected(N.NetworkTCP); got != members[1] {
		t.Fatalf("after a recovered selected %v, want b kept", got.Tag())
	}
	if probed := (&fallbackStrategy{noReturn: true}).probeSet(g); len(probed) != 1 || probed[0] != members[1] {
		t.Fatalf("probe set %v, want the current member only", probed)
	}
	setState(g, "b", false)
	g.PerformUpdateCheck()
	if got := g.Selected(N.NetworkTCP); got != members[0] {
		t.Fatalf("after b down selected %v, want a", got.Tag())
	}
}

func TestFallbackProbesMembersUpToCurrent(t *testing.T) {
	members := policyNodes("a", "b", "c")
	g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, members)
	if probed := g.strategy.probeSet(g); len(probed) != 3 {
		t.Fatalf("probe set before a selection %d members, want all", len(probed))
	}
	setState(g, "a", false)
	g.PerformUpdateCheck()
	probed := g.strategy.probeSet(g)
	if len(probed) != 2 || probed[0] != members[0] || probed[1] != members[1] {
		t.Fatalf("probe set %v, want a and b", probed)
	}
}

func TestFallbackSkipsMembersWithoutNetwork(t *testing.T) {
	members := []adapter.Outbound{&policyTestNode{tag: "tcp", networks: []string{N.NetworkTCP}}, &policyTestNode{tag: "both"}}
	g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, members)
	if got := g.Selected(N.NetworkUDP); got != members[1] {
		t.Fatalf("UDP selected %v, want both", got.Tag())
	}
	if got := g.Selected(N.NetworkTCP); got != members[0] {
		t.Fatalf("TCP selected %v, want tcp", got.Tag())
	}
}

func lbMetadata(source, domain string) *adapter.InboundContext {
	return &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.SocksaddrFrom(netip.MustParseAddr(source), 50000),
		Destination: M.ParseSocksaddrHostPort(domain, 443),
	}
}

func TestFallbackInheritsCurrentMember(t *testing.T) {
	old := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{noReturn: true}, false, policyNodes("a", "b"))
	setState(old, "a", false)
	old.PerformUpdateCheck()
	setState(old, "a", true)
	replacement := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{noReturn: true}, false, policyNodes("a", "b"))
	replacement.health = old.health
	replacement.InheritGroupState(old)
	if got := replacement.Selected(N.NetworkTCP); got.Tag() != "b" {
		t.Fatalf("inherited %s, want b", got.Tag())
	}
}

func TestHealthStoreSuspectNeedsDistinctDestinations(t *testing.T) {
	store := grouphealth.NewStore()
	failure := errors.New("refused")
	for range 5 {
		if store.ObserveDial("a", "one.example", 3, failure) {
			t.Fatal("failures to one destination made the member suspect")
		}
	}
	store.ObserveDial("a", "", 3, nil)
	store.ObserveDial("a", "one.example", 3, failure)
	store.ObserveDial("a", "two.example", 3, failure)
	if !store.ObserveDial("a", "one.example", 3, failure) {
		t.Fatal("three failures to two destinations did not make the member suspect")
	}
	if store.State("a") != adapter.GroupMemberSuspect {
		t.Fatal("state is not suspect")
	}
	if store.ObserveDial("a", "three.example", 3, failure) {
		t.Fatal("a suspect member became suspect again")
	}
	store.ObserveProbe("a", failure)
	if store.State("a") != adapter.GroupMemberDown {
		t.Fatal("a failed probe did not make the member down")
	}
	store.ObserveDial("a", "", 3, nil)
	if store.State("a") != adapter.GroupMemberDown {
		t.Fatal("a routed success made a down member up without a probe")
	}
	store.ObserveProbe("a", nil)
	if store.State("a") != adapter.GroupMemberUp {
		t.Fatal("a successful probe did not make the member up")
	}
}

func TestHealthStoreFailureWindow(t *testing.T) {
	store := grouphealth.NewStore()
	now := time.Now()
	store.SetClock(func() time.Time { return now })
	failure := errors.New("refused")
	store.ObserveDial("a", "one.example", 3, failure)
	store.ObserveDial("a", "two.example", 3, failure)
	now = now.Add(2 * time.Minute)
	if store.ObserveDial("a", "three.example", 3, failure) {
		t.Fatal("failures outside the window counted together")
	}
}

func TestReportDialProbesSuspectMember(t *testing.T) {
	members := policyNodes("a", "b")
	g := newPolicyTestGroup(t, C.TypeFallback, &fallbackStrategy{}, false, members)
	failure := errors.New("refused")
	for i := range 3 {
		g.ReportDial(members[0], lbMetadata("192.0.2.1", fmt.Sprintf("site%d.com", i)), adapter.GroupDialReport{Network: N.NetworkTCP, Err: failure})
	}
	deadline := time.Now().Add(10 * time.Second)
	for g.health.State("a") != adapter.GroupMemberDown {
		if time.Now().After(deadline) {
			t.Fatalf("suspect member state %v, want down after its probe failed", g.health.State("a"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	for g.Selected(N.NetworkTCP) != members[1] {
		if time.Now().After(deadline) {
			t.Fatal("group did not fail over after the probe")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// URLTest chooses by delay history only: member states learned from
// routed connections do not change its choice.
func TestURLTestChoiceIgnoresMemberStates(t *testing.T) {
	history := urltest.NewHistoryStorage()
	members := policyNodes("a", "b")
	group := &URLTestGroup{outbounds: members, history: history, tolerance: 50}
	history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 300})
	grouphealth.For(history).ObserveProbe("a", errors.New("down"))
	if got, _ := group.Select(N.NetworkTCP); got != members[0] {
		t.Fatalf("selected %s, want a", got.Tag())
	}
	test := &URLTest{tags: []string{"a", "b"}, group: group}
	for i := range 3 {
		test.ReportDial(members[1], lbMetadata("192.0.2.1", fmt.Sprintf("site%d.example.com", i)), adapter.GroupDialReport{Err: errors.New("refused")})
	}
	if history.LoadURLTestHistory("b") == nil {
		t.Fatal("reporting a dial changed the delay history")
	}
	if got, _ := group.Select(N.NetworkTCP); got != members[0] {
		t.Fatalf("selected %s after reports, want a", got.Tag())
	}
}
