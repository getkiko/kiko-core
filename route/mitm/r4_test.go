package mitm

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestScriptGuardExtraRanges(t *testing.T) {
	engine := newScriptClientEngine(t)
	for _, host := range []string{
		// Embedded IPv4 in transition prefixes.
		"64:ff9b:1::a00:1", // local-use NAT64
		"::5efe:10.0.0.1", "fe80::5efe:10.0.0.1", "::200:5efe:192.168.1.1",
		"2001:0:7f00:1:0:0:0:0", "2001:0:808:808:0:0:80ff:fffe", // Teredo with server 127.0.0.1; client 127.0.0.1
		// Names of the local network.
		"printer.local", "nas.lan", "router.home.arpa", "db.internal", "intranet", "x.localdomain", "localhost.localdomain", "host.local.",
		// Further special ranges.
		"100.64.0.1", "100.127.255.254", "192.0.0.8", "240.0.0.1",
	} {
		require.NotEmpty(t, engine.scriptHostRefused(host), "host %q", host)
	}
	for _, host := range []string{"100.63.255.255", "100.128.0.1", "8.8.8.8", "2606:4700::1111", "example.com", "198.18.0.1"} {
		require.Empty(t, engine.scriptHostRefused(host), "host %q", host)
	}
}

func TestInternalGuardPorts(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{}))
	engine.SetControlEndpoints("127.0.0.1:9090")
	engine.SetListenPorts(7890, 7891, 0, 70000)
	release := ProtectPort(45678)
	for _, tc := range []struct {
		host string
		port int
		deny bool
	}{
		{"127.0.0.1", 9090, true}, {"127.0.0.1", 7890, true}, {"localhost", 7891, true}, {"localhost.", 7890, true},
		{"::1", 7890, true}, {"::ffff:127.0.0.1", 7890, true}, {"0.0.0.0", 7890, true},
		{"::ffff:7f00:1", 9090, true}, {"::127.0.0.1", 9090, true}, {"64:ff9b::7f00:1", 9090, true},
		{"2002:7f00:1::", 7890, true}, {"foo.localhost", 7890, true},
		{"127.0.0.1", 45678, true}, {"127.0.0.1", 3000, false}, {"localhost", 3000, false},
		{"169.254.169.254", 80, true}, {"169.254.1.1", 1, true}, {"fe80::1", 80, true}, {"::ffff:169.254.169.254", 80, true},
		{"100.100.100.200", 80, true}, {"fd00:ec2::254", 80, true},
		{"10.0.0.1", 7890, false}, {"192.168.1.5", 80, false}, {"example.com", 7890, false}, {"8.8.8.8", 9090, false},
	} {
		require.Equal(t, tc.deny, engine.denyInternal(tc.host, tc.port), "%s:%d", tc.host, tc.port)
	}
	release()
	release()
	require.False(t, engine.denyInternal("127.0.0.1", 45678))
	// The ports of two holders stay protected until both release.
	first, second := ProtectPort(45679), ProtectPort(45679)
	first()
	require.True(t, engine.denyInternal("127.0.0.1", 45679))
	second()
	require.False(t, engine.denyInternal("127.0.0.1", 45679))
}

func TestInternalGuardOwnInterfaceAddress(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{}))
	engine.SetListenPorts(7890)
	own := netip.MustParseAddr("10.9.8.7")
	engine.local.snapshot.Store(&localSnapshot{addrs: map[netip.Addr]struct{}{own: {}}, at: engine.local.now()})
	require.True(t, engine.denyInternal("10.9.8.7", 7890))
	require.False(t, engine.denyInternal("10.9.8.7", 8080))
	require.False(t, engine.denyInternal("10.9.8.8", 7890))
}

func TestInternalRewriteProtectedPortsOption(t *testing.T) {
	ca := writeTestCA(t)
	rules := &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{
			{ID: "app", Pattern: `^https://example\.com/app`, Action: "header", Target: "http://127.0.0.1:41000/x"},
			{ID: "dev", Pattern: `^https://example\.com/dev`, Action: "header", Target: "http://127.0.0.1:41001/x"},
			{ID: "lan", Pattern: `^https://example\.com/lan`, Action: "header", Target: "http://192.168.1.2:41000/x"},
		},
		ProtectedPorts: []uint16{41000},
	}
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, rules))
	set := engine.rewriteSet()
	require.Nil(t, set.Plan("https", "example.com", "/app").Internal())
	require.NotNil(t, set.Plan("https", "example.com", "/dev").Internal())
	require.NotNil(t, set.Plan("https", "example.com", "/lan").Internal())
}
