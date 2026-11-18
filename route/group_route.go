package route

import (
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// selectMember is the member group gives a connection of network: by the
// connection for a group choosing per connection, else its selection.
func selectMember(group adapter.OutboundGroup, network string, metadata *adapter.InboundContext, dryRun bool) adapter.Outbound {
	if contextual, isContextual := group.(adapter.ContextualOutboundGroup); isContextual {
		return contextual.SelectFor(network, metadata, dryRun)
	}
	return group.Selected(network)
}

// chainStillSelected reports whether each group on chain would still
// give the next outbound of chain to a new connection of network.
func chainStillSelected(chain []adapter.Outbound, network string) bool {
	for i := 0; i+1 < len(chain); i++ {
		group, isGroup := chain[i].(adapter.OutboundGroup)
		if !isGroup {
			return false
		}
		if contextual, isContextual := group.(adapter.ContextualOutboundGroup); isContextual {
			if !contextual.Eligible(network, chain[i+1]) {
				return false
			}
			continue
		}
		if group.Selected(network) != chain[i+1] {
			return false
		}
	}
	return true
}

// attachGroupConnection registers closer with group, by member for a
// group tracking connections per member.
func attachGroupConnection(group adapter.OutboundGroup, member adapter.Outbound, closer io.Closer) func() {
	if attacher, isAttacher := group.(adapter.MemberConnectionAttacher); isAttacher {
		return attacher.AttachMemberConnection(member, closer)
	}
	return group.AttachConnection(closer)
}

// reportGroupDial tells each group on the chain how dialing through its
// member went.
func reportGroupDial(metadata *adapter.InboundContext, network string, start time.Time, err error) {
	chain := metadata.OutboundChain
	if len(chain) < 2 {
		return
	}
	report := adapter.GroupDialReport{Network: network, Latency: time.Since(start), Err: err}
	for i := 0; i+1 < len(chain); i++ {
		if feedback, isFeedback := chain[i].(adapter.GroupFeedback); isFeedback {
			feedback.ReportDial(chain[i+1], metadata, report)
		}
	}
}

// meterGroupConn counts a routed TCP connection through groups that
// learn from how connections close, and reports to them when it closes;
// other connections are left as they are.
func meterGroupConn(metadata *adapter.InboundContext, remoteConn net.Conn, onClose N.CloseHandlerFunc) (net.Conn, N.CloseHandlerFunc) {
	meter, onClose := newGroupMeter(metadata, onClose)
	return meter.wrap(remoteConn), onClose
}

// newGroupMeter returns the meter of a routed TCP connection and onClose
// extended to report it, or a nil meter and onClose when no group on the
// chain learns from closes. Every connection the meter wraps adds to the
// same report.
func newGroupMeter(metadata *adapter.InboundContext, onClose N.CloseHandlerFunc) (*groupMeter, N.CloseHandlerFunc) {
	chain := metadata.OutboundChain
	var learners []int
	for i := 0; i+1 < len(chain); i++ {
		if _, learns := chain[i].(adapter.GroupCloseFeedback); learns {
			learners = append(learners, i)
		}
	}
	if len(learners) == 0 {
		return nil, onClose
	}
	meter := &groupMeter{start: time.Now()}
	metadataCopy := *metadata
	return meter, N.AppendClose(onClose, func(err error) {
		report := meter.report(err)
		for _, i := range learners {
			chain[i].(adapter.GroupCloseFeedback).ReportClose(chain[i+1], &metadataCopy, report)
		}
	})
}

// wrap counts conn into the meter; a nil meter returns conn.
func (m *groupMeter) wrap(conn net.Conn) net.Conn {
	if m == nil {
		return conn
	}
	return bufio.NewCounterConn(conn, []N.CountFunc{m.read}, []N.CountFunc{m.write})
}

type groupMeter struct {
	start      time.Time
	firstWrite atomic.Int64
	firstRead  atomic.Int64
	upload     atomic.Int64
	download   atomic.Int64
}

func (m *groupMeter) write(n int64) {
	if n > 0 {
		m.firstWrite.CompareAndSwap(0, time.Now().UnixNano())
		m.upload.Add(n)
	}
}

func (m *groupMeter) read(n int64) {
	if n > 0 {
		m.firstRead.CompareAndSwap(0, time.Now().UnixNano())
		m.download.Add(n)
	}
}

func (m *groupMeter) report(err error) adapter.GroupCloseReport {
	report := adapter.GroupCloseReport{
		Duration: time.Since(m.start),
		Upload:   m.upload.Load(),
		Download: m.download.Load(),
		Err:      err,
	}
	if read := m.firstRead.Load(); read != 0 {
		from := m.start.UnixNano()
		if write := m.firstWrite.Load(); write != 0 && write < read {
			from = write
		}
		report.FirstByte = max(time.Duration(read-from), time.Millisecond)
	}
	return report
}
