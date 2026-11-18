package route

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// acquireChain pins each outbound of a resolved chain, the groups and the
// member they select, and returns a release safe to call more than once.
func acquireChain(manager any, chain []adapter.Outbound) func() {
	releases := make([]func(), 0, len(chain))
	for _, outbound := range chain {
		releases = append(releases, adapter.Acquire(manager, outbound))
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, release := range releases {
				release()
			}
		})
	}
}

// pinOnClose pins the outbound chain of a routed connection until onClose
// runs.
func pinOnClose(manager any, chain []adapter.Outbound, onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	release := acquireChain(manager, chain)
	return func(err error) {
		release()
		if onClose != nil {
			onClose(err)
		}
	}
}

var _ tun.FlowTracker = (*pinFlowTracker)(nil)

// pinFlowTracker pins the outbounds of a forwarded flow until the flow
// closes.
type pinFlowTracker struct {
	release func()
}

func newPinFlowTracker(manager any, chain []adapter.Outbound) *pinFlowTracker {
	return &pinFlowTracker{release: acquireChain(manager, chain)}
}

func (t *pinFlowTracker) AttachFlow(tun.FlowHandle) {}

func (t *pinFlowTracker) CountForward(int) {}

func (t *pinFlowTracker) CountReverse(int) {}

func (t *pinFlowTracker) FlowEstablished() {}

func (t *pinFlowTracker) CloseFlow(tun.FlowCloseReason) { t.release() }
