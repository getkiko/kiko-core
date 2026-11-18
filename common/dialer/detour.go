package dialer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type DirectDialer interface {
	IsEmpty() bool
}

type DetourDialer struct {
	outboundManager         adapter.OutboundManager
	detour                  string
	defaultOutbound         bool
	disableEmptyDirectCheck bool
	access                  sync.Mutex
	state                   atomic.Pointer[detourState]
}

type detourState struct {
	dialer     N.Dialer
	err        error
	generation uint64
}

func NewDetour(outboundManager adapter.OutboundManager, detour string, disableEmptyDirectCheck bool) N.Dialer {
	return &DetourDialer{
		outboundManager:         outboundManager,
		detour:                  detour,
		disableEmptyDirectCheck: disableEmptyDirectCheck,
	}
}

func NewDefaultOutboundDetour(outboundManager adapter.OutboundManager) N.Dialer {
	return &DetourDialer{
		outboundManager: outboundManager,
		defaultOutbound: true,
	}
}

func InitializeDetour(dialer N.Dialer) error {
	detourDialer, isDetour := common.Cast[*DetourDialer](dialer)
	if !isDetour {
		return nil
	}
	return common.Error(detourDialer.Dialer())
}

// Dialer resolves the detour once per outbound manager generation, so that
// outbounds replaced by a live configuration apply are picked up.
func (d *DetourDialer) Dialer() (N.Dialer, error) {
	var generation uint64
	if provider, isProvider := d.outboundManager.(adapter.GenerationProvider); isProvider {
		generation = provider.Generation()
	}
	state := d.state.Load()
	if state != nil && state.generation == generation {
		return state.dialer, state.err
	}
	d.access.Lock()
	defer d.access.Unlock()
	state = d.state.Load()
	if state != nil && state.generation == generation {
		return state.dialer, state.err
	}
	state = &detourState{generation: generation}
	state.dialer, state.err = d.init()
	d.state.Store(state)
	return state.dialer, state.err
}

func (d *DetourDialer) init() (N.Dialer, error) {
	var dialer adapter.Outbound
	if d.detour != "" {
		var loaded bool
		dialer, loaded = d.outboundManager.Outbound(d.detour)
		if !loaded {
			return nil, E.New("outbound detour not found: ", d.detour)
		}
	} else {
		dialer = d.outboundManager.Default()
	}
	if !d.defaultOutbound && !d.disableEmptyDirectCheck {
		if directDialer, isDirect := dialer.(DirectDialer); isDirect {
			if directDialer.IsEmpty() {
				return nil, E.New("detour to an empty direct outbound makes no sense")
			}
		}
	}
	return dialer, nil
}

func (d *DetourDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	if outbound, ok := dialer.(adapter.Outbound); ok {
		ctx = dnsmonitor.WithOutbound(ctx, outbound.Tag())
	}
	pinner, isPinner := d.outboundManager.(adapter.ObjectPinner)
	if !isPinner {
		conn, err := dialer.DialContext(ctx, network, destination)
		if err == nil {
			dnsmonitor.Remember(ctx, conn)
		}
		return conn, err
	}
	release := adapter.AcquireOutbound(pinner, dialer, N.NetworkName(network))
	conn, err := dialer.DialContext(ctx, network, destination)
	if err != nil {
		release()
		return nil, err
	}
	conn = newPinnedConn(conn, release)
	dnsmonitor.Remember(ctx, conn)
	return conn, nil
}

func (d *DetourDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	if outbound, ok := dialer.(adapter.Outbound); ok {
		ctx = dnsmonitor.WithOutbound(ctx, outbound.Tag())
	}
	pinner, isPinner := d.outboundManager.(adapter.ObjectPinner)
	if !isPinner {
		conn, err := dialer.ListenPacket(ctx, destination)
		if err == nil {
			dnsmonitor.Remember(ctx, conn)
		}
		return conn, err
	}
	release := adapter.AcquireOutbound(pinner, dialer, N.NetworkUDP)
	conn, err := dialer.ListenPacket(ctx, destination)
	if err != nil {
		release()
		return nil, err
	}
	conn = newPinnedPacketConn(conn, release)
	dnsmonitor.Remember(ctx, conn)
	return conn, nil
}

func (d *DetourDialer) Upstream() any {
	detour, _ := d.Dialer()
	return detour
}
