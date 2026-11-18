package box_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

const policyGroupConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "d1"},
    {"type": "direct", "tag": "d2"},
    {"type": "fallback", "tag": "fb", "outbounds": ["d1", "d2"], "url": "http://127.0.0.1:1/", "interval": "1m", "timeout": "1s", "max_failures": 2},
    {"type": "loadbalance", "tag": "lb", "outbounds": ["d1", "d2"], "strategy": "consistent_hashing", "url": "http://127.0.0.1:1/"},
    {"type": "smart", "tag": "sm", "outbounds": ["d1", "d2"], "url": "http://127.0.0.1:1/", "interrupt_exist_connections": true},
    {"type": "selector", "tag": "sel", "outbounds": ["fb", "lb", "sm"]}
  ],
  "route": {"final": "sel"}
}`

func TestPolicyGroupsLoadAndReport(t *testing.T) {
	_, instance := startLiveBox(t, policyGroupConfig)
	modes := map[string]string{"fb": C.GroupModeFallback, "lb": C.GroupModeLoadBalance, "sm": C.GroupModeSmart, "sel": C.GroupModeManual}
	for tag, mode := range modes {
		outbound, loaded := instance.Outbound().Outbound(tag)
		require.True(t, loaded, tag)
		status := outbound.(adapter.GroupStatusReporter).GroupStatus()
		require.Equal(t, mode, status.Mode, tag)
		require.Len(t, status.Members, len(outbound.(adapter.OutboundGroup).All()), tag)
		require.NotNil(t, outbound.(adapter.OutboundGroup).Selected(N.NetworkTCP), tag)
	}
	lb, _ := instance.Outbound().Outbound("lb")
	require.Equal(t, C.LoadBalanceConsistentHashing, lb.(adapter.GroupStatusReporter).GroupStatus().Strategy)
	require.Equal(t, "LoadBalance", C.ProxyDisplayName(lb.Type()))
	_, isManual := lb.(adapter.ManualSelectGroup)
	require.False(t, isManual)
}

func TestPolicyGroupsRejectForeignFields(t *testing.T) {
	ctx := include.Context(context.Background())
	_, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(strings.Replace(policyGroupConfig, `"max_failures": 2`, `"tolerance": 50`, 1)))
	require.Error(t, err)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(strings.Replace(policyGroupConfig, `"strategy": "consistent_hashing"`, `"strategy": "random"`, 1)))
	require.NoError(t, err)
	_, err = box.New(box.Options{Context: ctx, Options: options})
	require.ErrorContains(t, err, "unknown load balance strategy")
}

// A fallback group probes its members in the real core and leaves the
// first one when it cannot reach the test URL through it.
func TestFallbackLeavesUnreachableMember(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "dead", "server": "127.0.0.1", "server_port": 1},
    {"type": "direct", "tag": "d1"},
    {"type": "fallback", "tag": "fb", "outbounds": ["dead", "d1"], "url": "` + server.URL + `", "timeout": "2s"}
  ],
  "route": {"final": "fb"}
}`
	_, instance := startLiveBox(t, config)
	fallback, _ := instance.Outbound().Outbound("fb")
	group := fallback.(adapter.OutboundGroup)
	require.Eventually(t, func() bool {
		selected := group.Selected(N.NetworkTCP)
		return selected != nil && selected.Tag() == "d1"
	}, 10*time.Second, 50*time.Millisecond)
	states := map[string]adapter.GroupMemberState{}
	for _, member := range fallback.(adapter.GroupStatusReporter).GroupStatus().Members {
		states[member.Tag] = member.State
	}
	require.Equal(t, adapter.GroupMemberDown, states["dead"])
	require.Equal(t, adapter.GroupMemberUp, states["d1"])
}

func TestLiveApplyKeepsPolicyGroupSelection(t *testing.T) {
	ctx, instance := startLiveBox(t, policyGroupConfig)
	old, _ := instance.Outbound().Outbound("sm")
	// Once the members' states are settled, the replacement's own probes
	// change none of them.
	require.Eventually(t, func() bool {
		for _, member := range old.(adapter.GroupStatusReporter).GroupStatus().Members {
			if member.State != adapter.GroupMemberDown {
				return false
			}
		}
		return true
	}, 10*time.Second, 20*time.Millisecond)
	selected := old.(adapter.OutboundGroup).Selected(N.NetworkTCP).Tag()
	result, err := applyLive(t, ctx, strings.Replace(policyGroupConfig, `"interrupt_exist_connections": true`, `"interrupt_exist_connections": false`, 1))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	replaced, _ := instance.Outbound().Outbound("sm")
	require.NotSame(t, old, replaced)
	require.Equal(t, selected, replaced.(adapter.OutboundGroup).Selected(N.NetworkTCP).Tag())
}
