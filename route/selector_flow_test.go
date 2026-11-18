package route

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type selectorFlowManager struct {
	adapter.OutboundManager
	outbounds       map[string]adapter.Outbound
	defaultOutbound adapter.Outbound
}

func (m *selectorFlowManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}

func (m *selectorFlowManager) Default() adapter.Outbound { return m.defaultOutbound }

type selectorFlowOutbound struct {
	outbound.Adapter
	N.Dialer
	tun.Port
}

func (*selectorFlowOutbound) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

type selectorFlowHandle struct {
	tracker tun.FlowTracker
	closed  bool
}

func (f *selectorFlowHandle) CloseFlow() {
	if !f.closed {
		f.closed = true
		f.tracker.CloseFlow(tun.FlowCloseReset)
	}
}

func TestSelectorInterruptsPreMatchedFlows(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP} {
		for _, selectedGroup := range []string{"outer", "inner"} {
			for _, interruptExisting := range []bool{false, true} {
				for _, timing := range []string{"established", "before-tracker", "before-attach"} {
					t.Run(fmt.Sprintf("%s/%s/interrupt=%v/%s", network, selectedGroup, interruptExisting, timing), func(t *testing.T) {
						logger := log.NewNOPFactory().Logger()
						ctx := service.ContextWithDefaultRegistry(context.Background())
						manager := &selectorFlowManager{outbounds: make(map[string]adapter.Outbound)}
						service.MustRegister[adapter.OutboundManager](ctx, manager)
						scope := adapter.NewScope(ctx, logger)
						defer scope.Close()
						for _, tag := range []string{"a", "b"} {
							manager.outbounds[tag] = &selectorFlowOutbound{Adapter: outbound.NewAdapter("wireguard", tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, nil)}
						}
						for _, tag := range []string{"inner", "outer"} {
							members := []string{"a", "b"}
							if tag == "outer" {
								members[0] = "inner"
							}
							o, err := group.NewSelector(ctx, nil, logger, tag, option.SelectorOutboundOptions{Outbounds: members, InterruptExistConnections: interruptExisting})
							if err != nil {
								t.Fatal(err)
							}
							selector := o.(*group.Selector)
							manager.outbounds[tag] = selector
							if err = selector.Start(adapter.StartStateStart, scope); err != nil {
								t.Fatal(err)
							}
						}
						manager.defaultOutbound = manager.outbounds["outer"]
						traffic := trafficcontrol.NewManager(manager)
						if err := traffic.Start(adapter.StartStateInitialize, scope); err != nil {
							t.Fatal(err)
						}
						router := &Router{ctx: ctx, logger: logger, outbound: manager, trackers: []adapter.ConnectionTracker{traffic}}
						metadata := adapter.InboundContext{Network: network, Source: M.ParseSocksaddr("192.0.2.1:12345"), Destination: M.ParseSocksaddr("198.51.100.1:443")}
						result := router.preMatchFlow(ctx, &metadata, metadata.Destination, nil, "")
						if result.Action != adapter.PreMatchFlow || result.NewTracker == nil {
							t.Fatalf("expected fast flow, got %+v", result)
						}
						selector := manager.outbounds[selectedGroup].(*group.Selector)
						if !selector.SelectOutbound(selector.Selected(network).Tag()) {
							t.Fatal("select current failed")
						}
						if timing == "before-tracker" {
							selector.SelectOutbound("b")
						}
						handle := &selectorFlowHandle{tracker: result.NewTracker()}
						if timing == "before-attach" {
							selector.SelectOutbound("b")
						}
						handle.tracker.AttachFlow(handle)
						if timing == "established" && traffic.ConnectionsLen() != 1 {
							t.Fatal("flow was not registered with traffic monitor")
						}
						if timing == "established" {
							if !slices.Equal(traffic.Connections()[0].Chain, []string{"a", "inner", "outer"}) {
								t.Fatal("flow lost its selector chain")
							}
							selector.SelectOutbound("b")
						}
						if handle.closed != interruptExisting {
							t.Fatalf("pre-matched flow closed=%v, want %v", handle.closed, interruptExisting)
						}
						wantActive := 1
						if interruptExisting {
							wantActive = 0
						}
						if traffic.ConnectionsLen() != wantActive {
							t.Fatalf("active flows=%d, want %d", traffic.ConnectionsLen(), wantActive)
						}
						// A fresh verdict must follow the new selection and remain usable.
						fresh := router.preMatchFlow(ctx, &metadata, metadata.Destination, nil, "")
						freshHandle := &selectorFlowHandle{tracker: fresh.NewTracker()}
						freshHandle.tracker.AttachFlow(freshHandle)
						if freshHandle.closed {
							t.Fatal("new selection closed a fresh flow")
						}
						handle.CloseFlow()
						freshHandle.CloseFlow()
						if traffic.ConnectionsLen() != 0 {
							t.Fatal("natural close left active flow rows")
						}
					})
				}
			}
		}
	}
}
