package group

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

func newLoadBalanceTestGroup(t *testing.T, kind string, interrupt bool, members []adapter.Outbound) *Group {
	return newPolicyTestGroup(t, C.TypeLoadBalance, &loadBalanceStrategy{kind: kind, sticky: map[string]stickyEntry{}}, interrupt, members)
}

func TestLoadBalanceRoundRobinSkipsDownMembers(t *testing.T) {
	members := policyNodes("a", "b", "c")
	g := newLoadBalanceTestGroup(t, C.LoadBalanceRoundRobin, false, members)
	counts := map[string]int{}
	for range 30 {
		counts[g.SelectFor(N.NetworkTCP, nil, false).Tag()]++
	}
	for _, tag := range []string{"a", "b", "c"} {
		if counts[tag] != 10 {
			t.Fatalf("round robin counts %v, want 10 each", counts)
		}
	}
	setState(g, "b", false)
	counts = map[string]int{}
	for range 20 {
		counts[g.SelectFor(N.NetworkTCP, nil, false).Tag()]++
	}
	if counts["b"] != 0 || counts["a"] != 10 || counts["c"] != 10 {
		t.Fatalf("counts with b down %v", counts)
	}
	first := g.SelectFor(N.NetworkTCP, nil, true)
	if again := g.SelectFor(N.NetworkTCP, nil, true); again != first {
		t.Fatal("dry run advanced the rotation")
	}
	if g.Selected(N.NetworkTCP) != members[0] {
		t.Fatal("representative member is not the first available")
	}
	if g.Eligible(N.NetworkTCP, members[1]) || !g.Eligible(N.NetworkTCP, members[2]) {
		t.Fatal("eligibility does not follow member states")
	}
}

func TestLoadBalanceAllDownFallsBackToFirstMember(t *testing.T) {
	members := policyNodes("a", "b")
	g := newLoadBalanceTestGroup(t, C.LoadBalanceRoundRobin, false, members)
	setState(g, "a", false)
	setState(g, "b", false)
	if got := g.SelectFor(N.NetworkTCP, nil, false); got != members[0] {
		t.Fatalf("selected %v, want a", got.Tag())
	}
	if !g.Eligible(N.NetworkTCP, members[1]) {
		t.Fatal("a down member is not eligible while all are down")
	}
}

func TestLoadBalanceConsistentHashing(t *testing.T) {
	members := policyNodes("a", "b", "c", "d")
	g := newLoadBalanceTestGroup(t, C.LoadBalanceConsistentHashing, false, members)
	chosen := map[string]string{}
	for i := range 64 {
		domain := fmt.Sprintf("www.site%d.com", i)
		tag := g.SelectFor(N.NetworkTCP, lbMetadata("192.0.2.1", domain), false).Tag()
		chosen[domain] = tag
		if other := g.SelectFor(N.NetworkTCP, lbMetadata("192.0.2.9", "api.site"+fmt.Sprint(i)+".com"), false).Tag(); other != tag {
			t.Fatalf("hosts of one registrable domain went to %s and %s", tag, other)
		}
	}
	setState(g, "b", false)
	for domain, before := range chosen {
		after := g.SelectFor(N.NetworkTCP, lbMetadata("192.0.2.1", domain), false).Tag()
		if before != "b" && after != before {
			t.Fatalf("%s moved from %s to %s though only b went down", domain, before, after)
		}
		if after == "b" {
			t.Fatalf("%s still on the down member", domain)
		}
	}
}

func TestLoadBalanceStickySessions(t *testing.T) {
	members := policyNodes("a", "b", "c")
	g := newLoadBalanceTestGroup(t, C.LoadBalanceStickySessions, true, members)
	metadata := lbMetadata("192.0.2.1", "example.com")
	first := g.SelectFor(N.NetworkTCP, metadata, false)
	for range 10 {
		if got := g.SelectFor(N.NetworkTCP, metadata, false); got != first {
			t.Fatal("a session moved between members")
		}
	}
	conn := &closeRecorder{}
	other := &closeRecorder{}
	var second adapter.Outbound
	for _, member := range members {
		if member != first {
			second = member
			break
		}
	}
	defer g.AttachMemberConnection(first, conn)()
	defer g.AttachMemberConnection(second, other)()
	if _, err := g.probeMember(context.Background(), first); err == nil {
		t.Fatal("probe of a test node succeeded")
	}
	if !conn.closed {
		t.Fatal("connection of the down member was not interrupted")
	}
	if other.closed {
		t.Fatal("connection of another member was interrupted")
	}
	moved := g.SelectFor(N.NetworkTCP, metadata, false)
	if moved == first {
		t.Fatal("session stayed on the down member")
	}
	setState(g, first.Tag(), true)
	if got := g.SelectFor(N.NetworkTCP, metadata, false); got != moved {
		t.Fatal("session moved back when the member recovered")
	}
}

func TestLoadBalanceInheritsState(t *testing.T) {
	members := policyNodes("a", "b", "c")
	old := newLoadBalanceTestGroup(t, C.LoadBalanceStickySessions, false, members)
	metadata := lbMetadata("192.0.2.1", "example.com")
	// Pin the session to a member that rendezvous would not choose.
	want := old.SelectFor(N.NetworkTCP, metadata, false)
	var pinned adapter.Outbound
	for _, member := range members {
		if member != want {
			pinned = member
		}
	}
	strategy := old.strategy.(*loadBalanceStrategy)
	for key := range strategy.sticky {
		strategy.sticky[key] = stickyEntry{tag: pinned.Tag(), expires: time.Now().Add(time.Minute)}
	}
	replacement := newLoadBalanceTestGroup(t, C.LoadBalanceStickySessions, false, policyNodes("a", "b", "c"))
	replacement.InheritGroupState(old)
	if got := replacement.SelectFor(N.NetworkTCP, metadata, false); got.Tag() != pinned.Tag() {
		t.Fatalf("inherited session went to %s, want %s", got.Tag(), pinned.Tag())
	}
}
