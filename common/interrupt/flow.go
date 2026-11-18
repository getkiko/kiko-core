package interrupt

import (
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/x/list"
)

func (t Token) NewFlowTracker(isExternal bool) tun.FlowTracker {
	return &flowTracker{token: t, isExternal: isExternal}
}

type flowTracker struct {
	token      Token
	isExternal bool
	element    *list.Element[*groupConnItem]
	handle     tun.FlowHandle
	closed     bool
}

func (t *flowTracker) AttachFlow(handle tun.FlowHandle) {
	g := t.token.group
	g.access.Lock()
	if t.closed {
		g.access.Unlock()
		return
	}
	t.handle = handle
	if t.token.interrupted(t.isExternal) {
		g.access.Unlock()
		handle.CloseFlow()
		return
	}
	t.element = g.connections.PushBack(&groupConnItem{t, t.isExternal})
	g.access.Unlock()
}

func (*flowTracker) CountForward(int) {}
func (*flowTracker) CountReverse(int) {}
func (*flowTracker) FlowEstablished() {}

func (t *flowTracker) CloseFlow(tun.FlowCloseReason) {
	g := t.token.group
	g.access.Lock()
	if t.element != nil {
		g.connections.Remove(t.element)
		t.element = nil
	}
	t.closed = true
	t.handle = nil
	g.access.Unlock()
}

func (t *flowTracker) Close() error {
	g := t.token.group
	g.access.Lock()
	handle := t.handle
	g.access.Unlock()
	if handle != nil {
		handle.CloseFlow()
	}
	return nil
}
