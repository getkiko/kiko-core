package mitm

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/hostmatch"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// testClock is an injectable engine clock.
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time { return c.now }

func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newClockedEngine(t testing.TB, options *option.MITMOptions) (*Engine, *testClock) {
	t.Helper()
	engine := newTestEngine(t, context.Background(), options)
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	engine.timeFunc = clock.Now
	return engine, clock
}

func policyOptions(t testing.TB, include []string, edit func(*option.MITMOptions)) *option.MITMOptions {
	t.Helper()
	ca := writeTestCA(t)
	options := fileOptions(ca, true, include, nil)
	if edit != nil {
		edit(options)
	}
	return options
}

func withSource(metadata *adapter.InboundContext, source string) *adapter.InboundContext {
	metadata.Source = M.SocksaddrFrom(netip.MustParseAddr(source), 50000)
	return metadata
}

func withProcess(metadata *adapter.InboundContext, path string) *adapter.InboundContext {
	metadata.ProcessInfo = &adapter.ConnectionOwner{ProcessPath: path}
	return metadata
}

func quicMetadata(serverName string) *adapter.InboundContext {
	metadata := tlsMetadata(serverName, "10.0.0.1:443")
	metadata.Network = "udp"
	metadata.Protocol = C.ProtocolQUIC
	return metadata
}

func decideStatus(engine *Engine, metadata *adapter.InboundContext) (adapter.MITMStatus, string) {
	state := engine.Decide(metadata)
	return state.Status(), state.Reason()
}

func TestDecideBuiltinExclusions(t *testing.T) {
	engine := newTestEngine(t, context.Background(), policyOptions(t, []string{"*.apple.com", "*.example.com", "mtalk.google.com"}, nil))
	status, _ := decideStatus(engine, tlsMetadata("a.example.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	status, _ = decideStatus(engine, tlsMetadata("www.apple.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	// A wildcard include does not override the table; an exact one does.
	status, reason := decideStatus(engine, tlsMetadata("x.push.apple.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusSkipped, status)
	require.Equal(t, ReasonBuiltin, reason)
	status, _ = decideStatus(engine, tlsMetadata("mtalk.google.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	// route-options force bypasses the table.
	forced := tlsMetadata("x.push.apple.com", "10.0.0.1:443")
	forced.MITMOverride = C.MITMOverrideForce
	status, _ = decideStatus(engine, forced)
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Equal(t, hostmatch.BuiltinCount(), engine.Status().BuiltinExclusions)

	off := false
	engine = newTestEngine(t, context.Background(), policyOptions(t, []string{"*.apple.com"}, func(options *option.MITMOptions) {
		options.Hostnames.BuiltinExclude = &off
	}))
	status, _ = decideStatus(engine, tlsMetadata("x.push.apple.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Zero(t, engine.Status().BuiltinExclusions)

	engine = newTestEngine(t, context.Background(), policyOptions(t, []string{"*.apple.com"}, func(options *option.MITMOptions) {
		options.Hostnames.DisabledBuiltin = []string{"apple-push"}
	}))
	status, _ = decideStatus(engine, tlsMetadata("x.push.apple.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Equal(t, hostmatch.BuiltinCount()-1, engine.Status().BuiltinExclusions)
}

func TestSkipTableFlow(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"example.com"}, nil))
	host := "example.com"
	key := pinKeyOf(tlsMetadata(host, "10.0.0.1:443"))
	duration := engine.config.Load().pinningDuration
	require.Equal(t, DefaultPinningSkipDuration, duration)

	// One failure does not skip; a success resets the count.
	require.False(t, engine.skips.failPinning(host, key, "bad certificate", clock.now, duration))
	status, _ := decideStatus(engine, tlsMetadata(host, "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	engine.skips.succeed(host, key)
	require.False(t, engine.skips.failPinning(host, key, "bad certificate", clock.now, duration))

	// The second consecutive failure does.
	require.True(t, engine.skips.failPinning(host, key, "bad certificate", clock.now, duration))
	status, reason := decideStatus(engine, tlsMetadata(host, "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusSkipped, status)
	require.Equal(t, ReasonPinned, reason)
	// Upper case names hit the same entry.
	status, _ = decideStatus(engine, tlsMetadata("EXAMPLE.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusSkipped, status)

	engineStatus := engine.Status()
	require.Len(t, engineStatus.Skip, 1)
	require.Equal(t, adapter.MITMSkipEntry{Host: host, Source: "auto", Until: clock.now.Add(duration), Reason: ReasonPinned}, engineStatus.Skip[0])
	require.Len(t, engineStatus.Failures, 1)
	require.Equal(t, host, engineStatus.Failures[0].Host)
	require.Equal(t, 3, engineStatus.Failures[0].Count)
	require.Equal(t, "bad certificate", engineStatus.Failures[0].LastError)

	// route-options force still decrypts.
	forced := tlsMetadata(host, "10.0.0.1:443")
	forced.MITMOverride = C.MITMOverrideForce
	status, _ = decideStatus(engine, forced)
	require.Equal(t, adapter.MITMStatusPending, status)

	// Expiry: the entry stops matching and is dropped on the lookup.
	clock.advance(duration - time.Second)
	status, _ = decideStatus(engine, tlsMetadata(host, "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusSkipped, status)
	clock.advance(2 * time.Second)
	status, _ = decideStatus(engine, tlsMetadata(host, "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Zero(t, engine.skips.active.Load())
	require.Empty(t, engine.Status().Skip)
}

func TestSkipTableKeyIsolation(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"example.com", "other.test"}, nil))
	duration := engine.config.Load().pinningDuration
	app := withProcess(tlsMetadata("example.com", "10.0.0.1:443"), "/Applications/App.app/App")
	require.False(t, engine.skips.failPinning("example.com", pinKeyOf(app), "x", clock.now, duration))
	require.True(t, engine.skips.failPinning("example.com", pinKeyOf(app), "x", clock.now, duration))

	status, _ := decideStatus(engine, app)
	require.Equal(t, adapter.MITMStatusSkipped, status)
	// Another process, another source address, another host and a connection
	// without process information are unaffected.
	status, _ = decideStatus(engine, withProcess(tlsMetadata("example.com", "10.0.0.1:443"), "/usr/bin/curl"))
	require.Equal(t, adapter.MITMStatusPending, status)
	status, _ = decideStatus(engine, withSource(tlsMetadata("example.com", "10.0.0.1:443"), "127.0.0.1"))
	require.Equal(t, adapter.MITMStatusPending, status)
	status, _ = decideStatus(engine, withProcess(tlsMetadata("other.test", "10.0.0.1:443"), "/Applications/App.app/App"))
	require.Equal(t, adapter.MITMStatusPending, status)

	// Without a process the source address is the key.
	device := withSource(tlsMetadata("example.com", "10.0.0.1:443"), "127.0.0.2")
	require.False(t, engine.skips.failPinning("example.com", pinKeyOf(device), "x", clock.now, duration))
	require.True(t, engine.skips.failPinning("example.com", pinKeyOf(device), "x", clock.now, duration))
	status, _ = decideStatus(engine, device)
	require.Equal(t, adapter.MITMStatusSkipped, status)
	status, _ = decideStatus(engine, withSource(tlsMetadata("example.com", "10.0.0.1:443"), "127.0.0.3"))
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Len(t, engine.Status().Skip, 2)

	// MatchHost reflects the skip table for any client.
	require.False(t, engine.MatchHost("example.com"))
	require.True(t, engine.MatchHost("other.test"))
}

func TestClearSkip(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"a.test", "b.test"}, nil))
	duration := engine.config.Load().pinningDuration
	key := pinKeyOf(tlsMetadata("a.test", "10.0.0.1:443"))
	for _, host := range []string{"a.test", "b.test"} {
		engine.skips.failPinning(host, key, "x", clock.now, duration)
		engine.skips.failPinning(host, key, "x", clock.now, duration)
	}
	engine.skips.failPinning("c.test", key, "x", clock.now, duration)
	require.Len(t, engine.Status().Skip, 2)

	require.False(t, engine.ClearSkip("unknown.test"))
	require.True(t, engine.ClearSkip("A.test"))
	status, _ := decideStatus(engine, tlsMetadata("a.test", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	status, _ = decideStatus(engine, tlsMetadata("b.test", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusSkipped, status)
	for _, failure := range engine.Status().Failures {
		require.NotEqual(t, "a.test", failure.Host)
	}

	// The pending count of c.test is cleared too: one more failure does not skip.
	require.True(t, engine.ClearSkip("c.test"))
	require.False(t, engine.skips.failPinning("c.test", key, "x", clock.now, duration))

	require.True(t, engine.ClearSkip(""))
	require.Empty(t, engine.Status().Skip)
	require.Empty(t, engine.Status().Failures)
	require.False(t, engine.ClearSkip(""))
	require.Zero(t, engine.skips.active.Load())
}

func TestPendingFailureExpires(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"a.test"}, nil))
	duration := engine.config.Load().pinningDuration
	key := pinKeyOf(tlsMetadata("a.test", "10.0.0.1:443"))
	require.False(t, engine.skips.failPinning("a.test", key, "x", clock.now, duration))
	clock.advance(pendingWindow + time.Second)
	require.False(t, engine.skips.failPinning("a.test", key, "x", clock.now, duration))
	require.True(t, engine.skips.failPinning("a.test", key, "x", clock.now, duration))
}

func TestSkipTableBounds(t *testing.T) {
	table := newSkipTable()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < maxSkipEntries+50; i++ {
		host := "h" + strconv.Itoa(i) + ".test"
		now = now.Add(time.Millisecond)
		table.failPinning(host, pinKey{}, "x", now, time.Hour)
		table.failPinning(host, pinKey{}, "x", now, time.Hour)
	}
	skip, failures := table.snapshot(now)
	require.Len(t, skip, maxSkipEntries)
	require.Len(t, failures, maxFailureRecords)
	require.Equal(t, int32(maxSkipEntries), table.active.Load())
	// The oldest entries made room.
	require.False(t, table.lookup("h0.test", pinKey{}, now))
	require.True(t, table.lookup("h"+strconv.Itoa(maxSkipEntries+49)+".test", pinKey{}, now))
	// Expired entries are dropped before live ones.
	now = now.Add(2 * time.Hour)
	table.failPinning("new.test", pinKey{}, "x", now, time.Hour)
	table.failPinning("new.test", pinKey{}, "x", now, time.Hour)
	skip, _ = table.snapshot(now)
	require.Len(t, skip, 1)

	for i := 0; i < maxPendingKeys+10; i++ {
		table.failPinning("p"+strconv.Itoa(i)+".test", pinKey{}, "x", now, time.Hour)
	}
	require.LessOrEqual(t, len(table.pending), maxPendingKeys)
}

func TestMatchHost(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"*.example.com", "api.example.org:8443", "x.push.apple.com", "*.apple.com"}, func(options *option.MITMOptions) {
		options.Hostnames.Exclude = []string{"skip.example.com"}
		options.Sources = []string{"203.0.113.0/24"}
	}))
	require.True(t, engine.MatchHost("a.example.com"))
	require.True(t, engine.MatchHost("A.Example.com."))
	require.False(t, engine.MatchHost("example.com"))
	require.False(t, engine.MatchHost("skip.example.com"))
	require.False(t, engine.MatchHost(""))
	// Any port counts, and device scope is ignored.
	require.True(t, engine.MatchHost("api.example.org"))
	// Built-in exclusions apply; an exact include overrides.
	require.False(t, engine.MatchHost("y.push.apple.com"))
	require.True(t, engine.MatchHost("x.push.apple.com"))
	require.True(t, engine.MatchHost("www.apple.com"))

	duration := engine.config.Load().pinningDuration
	engine.skips.failPinning("a.example.com", pinKey{}, "x", clock.now, duration)
	engine.skips.failPinning("a.example.com", pinKey{}, "x", clock.now, duration)
	require.False(t, engine.MatchHost("a.example.com"))
	require.True(t, engine.MatchHost("b.example.com"))
	clock.advance(duration + time.Second)
	require.True(t, engine.MatchHost("a.example.com"))

	disabled := newTestEngine(t, context.Background(), fileOptions(writeTestCA(t), false, []string{"a.example.com"}, nil))
	require.False(t, disabled.MatchHost("a.example.com"))
}

func TestMatchHostWithoutAuthority(t *testing.T) {
	engine := newTestEngine(t, context.Background(), &option.MITMOptions{
		Enabled:   true,
		Hostnames: &option.MITMHostnamesOptions{Include: []string{"a.test"}},
	})
	require.True(t, engine.Status().AuthorityPending)
	require.True(t, engine.MatchHost("a.test"))
	require.False(t, engine.MatchQUIC(quicMetadata("a.test")))
}

func TestMatchQUIC(t *testing.T) {
	include := []string{"*.example.com", "*.apple.com"}
	engine, clock := newClockedEngine(t, policyOptions(t, include, nil))
	require.True(t, engine.MatchQUIC(quicMetadata("a.example.com")))
	require.False(t, engine.MatchQUIC(quicMetadata("other.test")))
	require.False(t, engine.MatchQUIC(quicMetadata("x.push.apple.com")))
	require.False(t, engine.MatchQUIC(quicMetadata("")))
	// Only QUIC.
	require.False(t, engine.MatchQUIC(tlsMetadata("a.example.com", "10.0.0.1:443")))
	other := quicMetadata("a.example.com")
	other.Destination = M.ParseSocksaddr("10.0.0.1:8443")
	require.False(t, engine.MatchQUIC(other))

	override := quicMetadata("a.example.com")
	override.MITMOverride = C.MITMOverrideSkip
	require.False(t, engine.MatchQUIC(override))
	override = quicMetadata("x.push.apple.com")
	override.MITMOverride = C.MITMOverrideForce
	require.True(t, engine.MatchQUIC(override))

	// A pinned host is not blocked: the client uses QUIC undecrypted.
	duration := engine.config.Load().pinningDuration
	key := pinKeyOf(quicMetadata("a.example.com"))
	engine.skips.failPinning("a.example.com", key, "x", clock.now, duration)
	engine.skips.failPinning("a.example.com", key, "x", clock.now, duration)
	require.False(t, engine.MatchQUIC(quicMetadata("a.example.com")))
	require.True(t, engine.MatchQUIC(quicMetadata("b.example.com")))

	allow := newTestEngine(t, context.Background(), policyOptions(t, include, func(options *option.MITMOptions) {
		options.QUIC = "allow"
	}))
	require.False(t, allow.MatchQUIC(quicMetadata("a.example.com")))
	block := newTestEngine(t, context.Background(), policyOptions(t, include, func(options *option.MITMOptions) {
		options.QUIC = "block"
	}))
	require.True(t, block.MatchQUIC(quicMetadata("a.example.com")))
	disabled := newTestEngine(t, context.Background(), fileOptions(writeTestCA(t), false, include, nil))
	require.False(t, disabled.MatchQUIC(quicMetadata("a.example.com")))

	scoped := newTestEngine(t, context.Background(), policyOptions(t, include, func(options *option.MITMOptions) {
		options.Sources = []string{"203.0.113.0/24"}
	}))
	require.False(t, scoped.MatchQUIC(withSource(quicMetadata("a.example.com"), "198.51.100.7")))
	require.True(t, scoped.MatchQUIC(withSource(quicMetadata("a.example.com"), "203.0.113.7")))
}

func TestDeviceScope(t *testing.T) {
	engine := newTestEngine(t, context.Background(), policyOptions(t, []string{"example.com"}, func(options *option.MITMOptions) {
		options.Sources = []string{"local", "192.168.50.0/24", "10.1.1.5", "2001:db8::/32"}
	}))
	engine.local = &localAddresses{
		now: time.Now,
		lookup: func() ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("172.19.0.1"), Mask: net.CIDRMask(30, 32)},
				&net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)},
				&net.IPAddr{IP: net.ParseIP("fdfe:dcba:9876::1")},
			}, nil
		},
	}
	engine.local.refresh()
	testCases := []struct {
		name    string
		source  string
		decrypt bool
	}{
		{"loopback", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"mapped loopback", "::ffff:127.0.0.1", true},
		{"tun address", "172.19.0.1", true},
		{"tun v6 address", "fdfe:dcba:9876::1", true},
		{"lan interface address", "192.168.1.20", true},
		{"lan neighbour is not local", "192.168.1.21", false},
		{"tun peer address", "172.19.0.2", true},
		{"outside the tun subnet", "172.19.0.4", false},
		{"gateway device cidr", "192.168.50.77", true},
		{"gateway device ip", "10.1.1.5", true},
		{"other device ip", "10.1.1.6", false},
		{"gateway device v6", "2001:db8:1::5", true},
		{"unknown public", "198.51.100.1", false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			status, _ := decideStatus(engine, withSource(tlsMetadata("example.com", "10.0.0.1:443"), testCase.source))
			if testCase.decrypt {
				require.Equal(t, adapter.MITMStatusPending, status)
			} else {
				require.Equal(t, adapter.MITMStatusNone, status)
			}
		})
	}
	// No source address: local.
	status, _ := decideStatus(engine, tlsMetadata("example.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	// Scope applies before the route-options override.
	forced := withSource(tlsMetadata("example.com", "10.0.0.1:443"), "198.51.100.1")
	forced.MITMOverride = C.MITMOverrideForce
	status, _ = decideStatus(engine, forced)
	require.Equal(t, adapter.MITMStatusNone, status)

	// Devices only: the machine itself is out of scope.
	devices := newTestEngine(t, context.Background(), policyOptions(t, []string{"example.com"}, func(options *option.MITMOptions) {
		options.Sources = []string{"192.168.50.0/24"}
	}))
	status, _ = decideStatus(devices, withSource(tlsMetadata("example.com", "10.0.0.1:443"), "127.0.0.1"))
	require.Equal(t, adapter.MITMStatusNone, status)
	status, _ = decideStatus(devices, tlsMetadata("example.com", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusNone, status)
}

func TestLocalAddressesRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var addresses atomicAddresses
	addresses.set("172.19.0.1")
	local := &localAddresses{lookup: addresses.lookup, now: func() time.Time { return now }}
	local.refresh()
	require.True(t, local.contains(netip.MustParseAddr("172.19.0.1")))
	require.False(t, local.contains(netip.MustParseAddr("10.9.9.9")))

	// A new address shows up after the interval, without blocking the lookup.
	addresses.set("172.19.0.1", "10.9.9.9")
	require.False(t, local.contains(netip.MustParseAddr("10.9.9.9")))
	now = now.Add(localRefreshInterval)
	require.False(t, local.contains(netip.MustParseAddr("10.9.9.9")))
	require.Eventually(t, func() bool {
		return local.contains(netip.MustParseAddr("10.9.9.9"))
	}, 5*time.Second, 5*time.Millisecond)

	// A failing enumeration keeps the previous addresses.
	addresses.fail()
	local.refresh()
	require.True(t, local.contains(netip.MustParseAddr("10.9.9.9")))
}

func TestReloadValidation(t *testing.T) {
	ca := writeTestCA(t)
	directory := t.TempDir()
	notPEM := filepath.Join(directory, "empty.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))
	testCases := []struct {
		name  string
		edit  func(*option.MITMOptions)
		error string
	}{
		{"sources", func(o *option.MITMOptions) { o.Sources = []string{"bogus"} }, "sources"},
		{"sources cidr", func(o *option.MITMOptions) { o.Sources = []string{"10.0.0.0/33"} }, "sources"},
		{"quic", func(o *option.MITMOptions) { o.QUIC = "maybe" }, "quic"},
		{"fingerprint", func(o *option.MITMOptions) { o.Upstream = &option.MITMUpstreamOptions{Fingerprint: "edge"} }, "fingerprint"},
		{"skip verify", func(o *option.MITMOptions) {
			o.Upstream = &option.MITMUpstreamOptions{SkipVerify: []string{"*.com"}}
		}, "skip_verify"},
		{"custom root missing", func(o *option.MITMOptions) {
			o.Upstream = &option.MITMUpstreamOptions{CustomRoots: []string{filepath.Join(directory, "missing.pem")}}
		}, "custom root"},
		{"custom root invalid", func(o *option.MITMOptions) {
			o.Upstream = &option.MITMUpstreamOptions{CustomRoots: []string{notPEM}}
		}, "no PEM certificate"},
		{"negative duration", func(o *option.MITMOptions) { o.PinningSkipDuration = badoption.Duration(-time.Minute) }, "pinning_skip_duration"},
		{"disabled builtin", func(o *option.MITMOptions) { o.Hostnames.DisabledBuiltin = []string{"no-such-entry"} }, "no-such-entry"},
	}
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"keep.test"}, nil))
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := fileOptions(ca, true, []string{"other.test"}, nil)
			testCase.edit(options)
			commit, err := engine.Reload(options)
			require.Error(t, err)
			require.Nil(t, commit)
			require.Contains(t, err.Error(), testCase.error)
			// Nothing changed.
			status, _ := decideStatus(engine, tlsMetadata("keep.test", "10.0.0.1:443"))
			require.Equal(t, adapter.MITMStatusPending, status)
			status, _ = decideStatus(engine, tlsMetadata("other.test", "10.0.0.1:443"))
			require.Equal(t, adapter.MITMStatusNone, status)
		})
	}
}

func TestReloadKeepsSkipTableAndApplies(t *testing.T) {
	ca := writeTestCA(t)
	engine, clock := newClockedEngine(t, fileOptions(ca, true, []string{"a.test"}, nil))
	duration := engine.config.Load().pinningDuration
	engine.skips.failPinning("a.test", pinKey{}, "x", clock.now, duration)
	engine.skips.failPinning("a.test", pinKey{}, "x", clock.now, duration)

	options := fileOptions(ca, true, []string{"a.test", "b.test"}, nil)
	options.PinningSkipDuration = badoption.Duration(time.Hour)
	options.QUIC = "allow"
	options.Sources = []string{"local", "10.0.0.0/8"}
	commit, err := engine.Reload(options)
	require.NoError(t, err)
	// Prepared but not applied.
	require.Equal(t, DefaultPinningSkipDuration, engine.config.Load().pinningDuration)
	commit()
	config := engine.config.Load()
	require.Equal(t, time.Hour, config.pinningDuration)
	require.False(t, config.blockQUIC)
	status, reason := decideStatus(engine, tlsMetadata("a.test", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusSkipped, status)
	require.Equal(t, ReasonPinned, reason)
	status, _ = decideStatus(engine, tlsMetadata("b.test", "10.0.0.1:443"))
	require.Equal(t, adapter.MITMStatusPending, status)
	require.Len(t, engine.Status().Skip, 1)
}

func TestPolicyDoesNotAllocateOnMiss(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"*.example.com", "*.apple.com"}, nil))
	duration := engine.config.Load().pinningDuration
	pinned := withSource(quicMetadata("pinned.example.com"), "127.0.0.1")
	engine.skips.failPinning("pinned.example.com", pinKeyOf(pinned), "x", clock.now, duration)
	engine.skips.failPinning("pinned.example.com", pinKeyOf(pinned), "x", clock.now, duration)
	misses := []*adapter.InboundContext{
		withSource(tlsMetadata("other.test", "10.0.0.1:443"), "127.0.0.1"),
		withSource(tlsMetadata("a.example.com", "10.0.0.1:8443"), "127.0.0.1"),
	}
	quicMisses := []*adapter.InboundContext{
		withSource(quicMetadata("other.test"), "127.0.0.1"),
		withSource(quicMetadata("x.push.apple.com"), "127.0.0.1"),
		pinned,
	}
	allocations := testing.AllocsPerRun(100, func() {
		for _, metadata := range misses {
			if engine.Decide(metadata) != nil {
				t.Fatal("unexpected state")
			}
		}
		for _, metadata := range quicMisses {
			if engine.MatchQUIC(metadata) {
				t.Fatal("unexpected QUIC match")
			}
		}
		if engine.MatchHost("other.test") || engine.MatchHost("x.push.apple.com") || engine.MatchHost("pinned.example.com") {
			t.Fatal("unexpected host match")
		}
		if !engine.MatchHost("fine.example.com") {
			t.Fatal("expected host match")
		}
	})
	require.Zero(t, allocations)
}

func TestCertificateAlertClassification(t *testing.T) {
	for _, message := range []string{"bad certificate", "unsupported certificate", "unknown certificate", "unknown certificate authority"} {
		err := &net.OpError{Op: "remote error", Err: stringError("tls: " + message)}
		require.NotEmpty(t, certificateAlert(err), message)
	}
	for _, message := range []string{"internal error", "handshake failure", "protocol version not supported", "decrypt error"} {
		err := &net.OpError{Op: "remote error", Err: stringError("tls: " + message)}
		require.Empty(t, certificateAlert(err), message)
	}
	require.Empty(t, certificateAlert(&net.OpError{Op: "read", Err: stringError("tls: bad certificate")}))
	require.Empty(t, certificateAlert(nil))
}

type stringError string

func (e stringError) Error() string { return string(e) }

type atomicAddresses struct {
	addresses []string
	failing   bool
}

func (a *atomicAddresses) set(addresses ...string) { a.addresses = addresses; a.failing = false }

func (a *atomicAddresses) fail() { a.failing = true }

func (a *atomicAddresses) lookup() ([]net.Addr, error) {
	if a.failing {
		return nil, os.ErrNotExist
	}
	result := make([]net.Addr, 0, len(a.addresses))
	for _, address := range a.addresses {
		result = append(result, &net.IPNet{IP: net.ParseIP(address), Mask: net.CIDRMask(32, 32)})
	}
	return result, nil
}

func TestDecideBuiltinExclusion(t *testing.T) {
	engine, _ := newClockedEngine(t, policyOptions(t, []string{"*.example.com", "*.apple.com"}, nil))
	state := engine.Decide(tlsMetadata("push.apple.com", "10.0.0.1:443"))
	require.NotNil(t, state)
	require.Equal(t, adapter.MITMStatusSkipped, state.Status())
	require.Equal(t, ReasonBuiltin, state.Reason())
	require.Nil(t, engine.Decide(tlsMetadata("plain.test", "10.0.0.1:443")))
	require.NotNil(t, engine.Decide(tlsMetadata("a.example.com", "10.0.0.1:443")))
	require.False(t, engine.MatchQUIC(quicMetadata("push.apple.com")))
	require.False(t, engine.MatchHost("push.apple.com"))
	forced := tlsMetadata("push.apple.com", "10.0.0.1:443")
	forced.MITMOverride = C.MITMOverrideForce
	require.Equal(t, adapter.MITMStatusPending, engine.Decide(forced).Status())
}

func TestSkipTableFullWithExpiredEntriesOfTheSameHost(t *testing.T) {
	table := newSkipTable()
	now := time.Unix(1_700_000_000, 0)
	// One host holds three short entries; the rest of the table is live.
	for i := 0; i < 3; i++ {
		table.failPinning("same.test", pinKey{process: "old" + strconv.Itoa(i)}, "x", now, time.Minute)
		table.failPinning("same.test", pinKey{process: "old" + strconv.Itoa(i)}, "x", now, time.Minute)
	}
	for i := 0; table.size < maxSkipEntries; i++ {
		host := "h" + strconv.Itoa(i) + ".test"
		table.failPinning(host, pinKey{}, "x", now, time.Hour)
		table.failPinning(host, pinKey{}, "x", now, time.Hour)
	}
	require.Equal(t, maxSkipEntries, table.size)
	now = now.Add(2 * time.Minute)
	fresh := pinKey{process: "fresh"}
	table.failPinning("same.test", fresh, "x", now, time.Hour)
	table.failPinning("same.test", fresh, "x", now, time.Hour)
	require.Len(t, table.hosts["same.test"], 1)
	require.Equal(t, fresh, table.hosts["same.test"][0].key)
	total := 0
	for _, items := range table.hosts {
		total += len(items)
	}
	require.Equal(t, total, table.size)
	require.Equal(t, int32(total), table.active.Load())
	// Later purges keep the count consistent and never negative.
	now = now.Add(2 * time.Hour)
	for host := range table.hosts {
		table.purge(host, now)
	}
	require.Zero(t, table.size)
	require.Zero(t, table.active.Load())
}

func TestExplain(t *testing.T) {
	engine, clock := newClockedEngine(t, policyOptions(t, []string{"*.example.com", "port.example.org:8443", "*.apple.com"}, func(options *option.MITMOptions) {
		options.Hostnames.Exclude = []string{"skip.example.com"}
		options.Sources = []string{"192.168.1.0/24"}
	}))
	explain := func(metadata *adapter.InboundContext) string {
		status, reason := engine.Explain(metadata)
		if reason == "" {
			return status
		}
		return status + ":" + reason
	}
	inScope := func(metadata *adapter.InboundContext) *adapter.InboundContext {
		return withSource(metadata, "192.168.1.5")
	}
	require.Equal(t, "decrypted", explain(inScope(tlsMetadata("a.example.com", "10.0.0.1:443"))))
	require.Equal(t, "skipped:scope", explain(withSource(tlsMetadata("a.example.com", "10.0.0.1:443"), "198.51.100.7")))
	require.Equal(t, "skipped:not_included", explain(inScope(tlsMetadata("other.test", "10.0.0.1:443"))))
	require.Equal(t, "skipped:not_included", explain(inScope(tlsMetadata("port.example.org", "10.0.0.1:443"))))
	require.Equal(t, "decrypted", explain(inScope(tlsMetadata("port.example.org", "10.0.0.1:8443"))))
	require.Equal(t, "skipped:excluded", explain(inScope(tlsMetadata("skip.example.com", "10.0.0.1:443"))))
	require.Equal(t, "skipped:builtin", explain(inScope(tlsMetadata("x.push.apple.com", "10.0.0.1:443"))))
	skipped := inScope(tlsMetadata("a.example.com", "10.0.0.1:443"))
	skipped.MITMOverride = C.MITMOverrideSkip
	require.Equal(t, "skipped:override_skip", explain(skipped))
	notTLS := inScope(tlsMetadata("a.example.com", "10.0.0.1:443"))
	notTLS.Protocol = "http"
	require.Equal(t, "skipped:not_tls", explain(notTLS))
	pinned := inScope(tlsMetadata("a.example.com", "10.0.0.1:443"))
	duration := time.Hour
	engine.skips.failPinning("a.example.com", pinKeyOf(pinned), "x", clock.now, duration)
	engine.skips.failPinning("a.example.com", pinKeyOf(pinned), "x", clock.now, duration)
	require.Equal(t, "skipped:pinned", explain(pinned))
	// Decide keeps its semantics: no state for the passing cases.
	require.Nil(t, engine.Decide(inScope(tlsMetadata("other.test", "10.0.0.1:443"))))
	require.Nil(t, engine.Decide(skipped))
	require.Nil(t, engine.Decide(withSource(tlsMetadata("b.example.com", "10.0.0.1:443"), "198.51.100.7")))
}

func TestExplainDisabledAndPending(t *testing.T) {
	engine := newTestEngine(t, context.Background(), policyOptions(t, []string{"a.test"}, func(options *option.MITMOptions) {
		options.Enabled = false
	}))
	status, reason := engine.Explain(tlsMetadata("a.test", "10.0.0.1:443"))
	require.Empty(t, status)
	require.Empty(t, reason)
}

func TestPinKeyShared(t *testing.T) {
	engine := newTestEngine(t, context.Background(), policyOptions(t, []string{"a.test"}, nil))
	require.True(t, engine.sharedClient(withSource(tlsMetadata("a.test", "10.0.0.1:443"), "127.0.0.1")))
	require.True(t, engine.sharedClient(tlsMetadata("a.test", "10.0.0.1:443")))
	require.False(t, engine.sharedClient(withSource(tlsMetadata("a.test", "10.0.0.1:443"), "203.0.113.9")))
	require.False(t, engine.sharedClient(withProcess(withSource(tlsMetadata("a.test", "10.0.0.1:443"), "127.0.0.1"), "/usr/bin/app")))
}

func TestSkipTableSweepsExpiredWithoutLookup(t *testing.T) {
	table := newSkipTable()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5; i++ {
		host := "h" + strconv.Itoa(i) + ".test"
		table.failPinning(host, pinKey{}, "x", now, time.Minute)
		table.failPinning(host, pinKey{}, "x", now, time.Minute)
	}
	require.Equal(t, int32(5), table.active.Load())
	// A lookup of another host before expiry sweeps nothing.
	require.False(t, table.lookup("other.test", pinKey{}, now.Add(time.Second)))
	require.Equal(t, int32(5), table.active.Load())
	// Past the expiry and the sweep interval, a lookup of an unrelated
	// host drops every expired item.
	later := now.Add(time.Minute + sweepInterval + time.Second)
	require.False(t, table.lookup("other.test", pinKey{}, later))
	require.Equal(t, int32(0), table.active.Load())
	require.Empty(t, table.hosts)
	require.Zero(t, table.size)
	// The miss path stays allocation-free.
	require.Zero(t, testing.AllocsPerRun(100, func() {
		table.lookup("other.test", pinKey{}, later)
		table.hostSkipped("other.test", later)
	}))
	// Live entries survive a sweep.
	table.failPinning("live.test", pinKey{}, "x", later, time.Hour)
	table.failPinning("live.test", pinKey{}, "x", later, time.Hour)
	require.False(t, table.lookup("other.test", pinKey{}, later.Add(2*sweepInterval)))
	require.Equal(t, int32(1), table.active.Load())
	require.True(t, table.lookup("live.test", pinKey{}, later.Add(2*sweepInterval)))
}
