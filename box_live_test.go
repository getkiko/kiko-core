package box_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const liveBaseConfig = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "local", "tag": "dns-local"},
      {"type": "udp", "tag": "dns-udp", "server": "127.0.0.1", "detour": "d1"}
    ],
    "rules": [
      {"domain": ["block.test"], "action": "predefined", "rcode": "NXDOMAIN"}
    ],
    "final": "dns-local"
  },
  "outbounds": [
    {"type": "direct", "tag": "d1", "connect_timeout": "5s"},
    {"type": "direct", "tag": "d2"},
    {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2"], "default": "d1"},
    {"type": "socks", "tag": "s1", "server": "127.0.0.1", "server_port": 1, "detour": "d1"}
  ],
  "route": {
    "rules": [
      {"domain": ["a.test"], "outbound": "d1"}
    ],
    "final": "d1"
  }
}`

func startLiveBox(t *testing.T, content string) (context.Context, *box.Box) {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })
	return ctx, instance
}

func applyLive(t *testing.T, ctx context.Context, content string) (adapter.LiveConfigResult, error) {
	applier := service.FromContext[adapter.LiveConfigApplier](ctx)
	require.NotNil(t, applier)
	return applier.ApplyLiveConfig(context.Background(), []byte(content), 1)
}

func ruleOutbound(rule adapter.Rule) string {
	if action, isRoute := rule.Action().(*R.RuleActionRoute); isRoute {
		return action.Outbound
	}
	return ""
}

func TestLiveApplyRouteRulesConcurrent(t *testing.T) {
	ctx, instance := startLiveBox(t, liveBaseConfig)
	build := func(target string) string {
		var rules []string
		for _, domain := range []string{"a.test", "b.test", "c.test", "d.test", "e.test"} {
			rules = append(rules, `{"domain": ["`+domain+`"], "outbound": "`+target+`"}`)
		}
		config := strings.Replace(liveBaseConfig, `{"domain": ["a.test"], "outbound": "d1"}`, strings.Join(rules, ","), 1)
		return strings.Replace(config, `"final": "d1"`, `"final": "`+target+`"`, 1)
	}
	var (
		stop     atomic.Bool
		failures atomic.Int64
		reads    atomic.Int64
		wg       sync.WaitGroup
	)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				rules := instance.Router().Rules()
				if len(rules) == 0 {
					failures.Add(1)
					continue
				}
				first := ruleOutbound(rules[0])
				for _, rule := range rules {
					if ruleOutbound(rule) != first {
						failures.Add(1)
					}
				}
				reads.Add(1)
			}
		}()
	}
	for i := range 20 {
		target := "d1"
		if i%2 == 0 {
			target = "d2"
		}
		result, err := applyLive(t, ctx, build(target))
		require.NoError(t, err)
		require.True(t, result.Applied, result.Reason)
	}
	stop.Store(true)
	wg.Wait()
	require.Zero(t, failures.Load())
	require.Positive(t, reads.Load())
	rules := instance.Router().Rules()
	require.Len(t, rules, 5)
	for _, rule := range rules {
		require.Equal(t, "d1", ruleOutbound(rule))
	}
	require.Equal(t, "d1", instance.Outbound().Default().Tag())
	result, err := applyLive(t, ctx, build("d2"))
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Equal(t, "d2", instance.Outbound().Default().Tag())
}

func TestLiveApplyDNSRules(t *testing.T) {
	ctx, _ := startLiveBox(t, liveBaseConfig)
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	exchange := func() int {
		message := new(mDNS.Msg)
		message.SetQuestion("block.test.", mDNS.TypeA)
		response, err := dnsRouter.Exchange(adapter.WithContext(context.Background(), &adapter.InboundContext{}), message, adapter.DNSQueryOptions{})
		require.NoError(t, err)
		return response.Rcode
	}
	require.Equal(t, mDNS.RcodeNameError, exchange())
	result, err := applyLive(t, ctx, strings.Replace(liveBaseConfig, `"rcode": "NXDOMAIN"`, `"rcode": "REFUSED"`, 1))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Equal(t, mDNS.RcodeRefused, exchange())
}

func TestLiveApplyOutboundReplaceKeepsSelection(t *testing.T) {
	ctx, instance := startLiveBox(t, liveBaseConfig)
	oldD1, _ := instance.Outbound().Outbound("d1")
	oldD2, _ := instance.Outbound().Outbound("d2")
	oldSelector, _ := instance.Outbound().Outbound("sel")
	oldSocks, _ := instance.Outbound().Outbound("s1")
	oldUDP, _ := service.FromContext[adapter.DNSTransportManager](ctx).Transport("dns-udp")
	require.True(t, oldSelector.(interface{ SelectOutbound(string) bool }).SelectOutbound("d2"))

	newConfig := strings.Replace(liveBaseConfig, `{"type": "direct", "tag": "d1", "connect_timeout": "5s"}`, `{"type": "direct", "tag": "d1", "connect_timeout": "3s"}`, 1)
	result, err := applyLive(t, ctx, newConfig)
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)

	newD1, _ := instance.Outbound().Outbound("d1")
	newD2, _ := instance.Outbound().Outbound("d2")
	newSelector, _ := instance.Outbound().Outbound("sel")
	newSocks, _ := instance.Outbound().Outbound("s1")
	require.NotSame(t, oldD1, newD1)
	require.Same(t, oldD2, newD2)
	require.NotSame(t, oldSelector, newSelector)
	require.Equal(t, "d2", newSelector.(adapter.OutboundGroup).Selected(N.NetworkTCP).Tag())
	// Detour users are rebuilt transitively.
	require.NotSame(t, oldSocks, newSocks)
	require.Len(t, instance.Outbound().Outbounds(), 4)
	newUDP, _ := service.FromContext[adapter.DNSTransportManager](ctx).Transport("dns-udp")
	require.Same(t, oldUDP, newUDP)

	// The rebuilt selector follows the new member objects.
	require.True(t, newSelector.(interface{ SelectOutbound(string) bool }).SelectOutbound("d1"))
	require.Equal(t, "d1", newSelector.(adapter.OutboundGroup).Selected(N.NetworkTCP).Tag())
}

func TestLiveApplyDetourChain(t *testing.T) {
	config := strings.Replace(liveBaseConfig,
		`{"type": "socks", "tag": "s1", "server": "127.0.0.1", "server_port": 1, "detour": "d1"}`,
		`{"type": "socks", "tag": "s1", "server": "127.0.0.1", "server_port": 1, "detour": "d1"},
    {"type": "socks", "tag": "s2", "server": "127.0.0.1", "server_port": 2, "detour": "s1"}`, 1)
	ctx, instance := startLiveBox(t, config)
	oldS2, _ := instance.Outbound().Outbound("s2")
	result, err := applyLive(t, ctx, strings.Replace(config, `{"type": "direct", "tag": "d1", "connect_timeout": "5s"}`, `{"type": "direct", "tag": "d1", "tcp_fast_open": true}`, 1))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	newS2, _ := instance.Outbound().Outbound("s2")
	require.NotSame(t, oldS2, newS2)
}

func TestLiveApplyInboundRequiresRestart(t *testing.T) {
	ctx, instance := startLiveBox(t, liveBaseConfig)
	oldD1, _ := instance.Outbound().Outbound("d1")
	newConfig := strings.Replace(liveBaseConfig, `"outbounds": [`, `"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
  "outbounds": [`, 1)
	newConfig = strings.Replace(newConfig, `{"type": "direct", "tag": "d1", "connect_timeout": "5s"}`, `{"type": "direct", "tag": "d1", "connect_timeout": "3s"}`, 1)
	result, err := applyLive(t, ctx, newConfig)
	require.NoError(t, err)
	require.False(t, result.Applied)
	require.True(t, result.RestartRequired)
	require.Contains(t, result.Reason, "inbounds")
	currentD1, _ := instance.Outbound().Outbound("d1")
	require.Same(t, oldD1, currentD1)
}

func TestLiveApplyRollbackOnBadOutbound(t *testing.T) {
	ctx, instance := startLiveBox(t, liveBaseConfig)
	oldD1, _ := instance.Outbound().Outbound("d1")
	oldRules := instance.Router().Rules()
	newConfig := strings.Replace(liveBaseConfig, `{"type": "direct", "tag": "d1", "connect_timeout": "5s"}`, `{"type": "direct", "tag": "d1", "connect_timeout": "3s"}`, 1)
	newConfig = strings.Replace(newConfig, `"outbounds": ["d1", "d2"]`, `"outbounds": ["d1", "missing"]`, 1)
	newConfig = strings.Replace(newConfig, `"outbound": "d1"}`, `"outbound": "d2"}`, 1)
	result, err := applyLive(t, ctx, newConfig)
	require.Error(t, err)
	require.False(t, result.Applied)
	currentD1, _ := instance.Outbound().Outbound("d1")
	require.Same(t, oldD1, currentD1)
	require.Equal(t, oldRules, instance.Router().Rules())
	require.Equal(t, "d1", ruleOutbound(instance.Router().Rules()[0]))
	// A valid configuration still applies after the failed attempt.
	result, err = applyLive(t, ctx, strings.Replace(liveBaseConfig, `"outbound": "d1"}`, `"outbound": "d2"}`, 1))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Equal(t, "d2", ruleOutbound(instance.Router().Rules()[0]))
}

const liveReplacedD1 = `{"type": "direct", "tag": "d1", "connect_timeout": "3s"}`

func replaceD1(config string) string {
	return strings.Replace(config, `{"type": "direct", "tag": "d1", "connect_timeout": "5s"}`, liveReplacedD1, 1)
}

func waitRetiring(t *testing.T, instance *box.Box, expected int64) {
	t.Helper()
	require.Eventually(t, func() bool { return instance.LiveRetiring() == expected }, 5*time.Second, 10*time.Millisecond)
}

func TestLiveApplyPinnedFlowKeepsRetiredOutbound(t *testing.T) {
	defer box.SetLiveRetireTiming(100*time.Millisecond, 20*time.Millisecond)()
	ctx, instance := startLiveBox(t, liveBaseConfig)
	result := instance.Router().PreMatch(adapter.InboundContext{
		Inbound:     "tun-in",
		InboundType: "tun",
		Network:     N.NetworkICMP,
		Source:      M.ParseSocksaddrHostPort("172.19.0.2", 0),
		Destination: M.ParseSocksaddrHostPort("1.1.1.1", 0),
	}, nil)
	if result.Action != adapter.PreMatchFlow || result.NewTracker == nil {
		t.Skip("direct ICMP flow forwarding is unavailable: ", result.Action)
	}
	oldD1, _ := instance.Outbound().Outbound("d1")
	require.Same(t, oldD1, result.Outbound)
	tracker := result.NewTracker()

	applied, err := applyLive(t, ctx, replaceD1(liveBaseConfig))
	require.NoError(t, err)
	require.True(t, applied.Applied, applied.Reason)
	require.EqualValues(t, 1, instance.LiveRetiring())
	time.Sleep(400 * time.Millisecond)
	// The flow still pins the replaced outbound past the grace period.
	require.EqualValues(t, 1, instance.LiveRetiring())
	tracker.CloseFlow(tun.FlowCloseFinished)
	waitRetiring(t, instance, 0)
}

func TestLiveApplyEndpointDialPinsRetiredOutbound(t *testing.T) {
	defer box.SetLiveRetireTiming(100*time.Millisecond, 20*time.Millisecond)()
	ctx, instance := startLiveBox(t, liveBaseConfig)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			defer conn.Close()
		}
	}()
	// Endpoints and detour users dial through a detour dialer.
	detour := dialer.NewDetour(instance.Outbound(), "d1", false)
	conn, err := detour.DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)

	applied, err := applyLive(t, ctx, replaceD1(liveBaseConfig))
	require.NoError(t, err)
	require.True(t, applied.Applied, applied.Reason)
	time.Sleep(400 * time.Millisecond)
	require.EqualValues(t, 1, instance.LiveRetiring())

	// A new dial resolves the replacement and does not pin the old object.
	newConn, err := detour.DialContext(context.Background(), N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)
	defer newConn.Close()
	require.NoError(t, conn.Close())
	waitRetiring(t, instance, 0)
}

func TestLiveApplyUnpinnedRetiresAfterGrace(t *testing.T) {
	defer box.SetLiveRetireTiming(100*time.Millisecond, 20*time.Millisecond)()
	ctx, instance := startLiveBox(t, liveBaseConfig)
	applied, err := applyLive(t, ctx, replaceD1(liveBaseConfig))
	require.NoError(t, err)
	require.True(t, applied.Applied, applied.Reason)
	require.EqualValues(t, 1, instance.LiveRetiring())
	waitRetiring(t, instance, 0)
}
