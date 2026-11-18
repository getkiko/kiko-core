package adapter

import (
	"io"
	"time"

	"github.com/sagernet/sing-tun"
)

// ContextualOutboundGroup is a group that chooses its member per
// connection, as a load balance group by destination.
type ContextualOutboundGroup interface {
	OutboundGroup
	// SelectFor chooses the member of a new connection described by
	// metadata, nil when unknown. dryRun leaves the group's state (the
	// round robin position, sticky sessions) as it was.
	SelectFor(network string, metadata *InboundContext, dryRun bool) Outbound
	// Eligible reports whether member may still carry a new connection
	// of network, which a forwarded flow checks after taking trackers.
	Eligible(network string, member Outbound) bool
}

// ManualSelectGroup is a group whose member is chosen by the user.
type ManualSelectGroup interface {
	OutboundGroup
	SelectOutbound(tag string) bool
}

// GroupDialReport is the outcome of dialing a routed connection through
// a group's member.
type GroupDialReport struct {
	Network string
	Latency time.Duration
	Err     error
}

// GroupCloseReport is how a routed TCP connection through a group's
// member went, reported when it closes.
type GroupCloseReport struct {
	// FirstByte is the time from the first upstream write to the first
	// downstream byte, 0 without any downstream byte.
	FirstByte        time.Duration
	Duration         time.Duration
	Upload, Download int64
	Err              error
}

// GroupFeedback takes the outcomes of the routed connections through a
// group, which the router reports for each group on the chain with the
// next outbound of the chain as member.
type GroupFeedback interface {
	ReportDial(member Outbound, metadata *InboundContext, report GroupDialReport)
}

// GroupCloseFeedback is a group that also learns from how connections
// close; the router meters connections only through such groups.
type GroupCloseFeedback interface {
	GroupFeedback
	ReportClose(member Outbound, metadata *InboundContext, report GroupCloseReport)
}

// MemberConnectionAttacher is a group that tracks connections per member,
// so that it can interrupt those of one member only.
type MemberConnectionAttacher interface {
	AttachMemberConnection(member Outbound, closer io.Closer) (detach func())
}

// MemberFlowTrackerOutbound is a group that tracks forwarded flows per
// member, so that it can interrupt those of one member only. The factory
// is nil for a member it does not track.
type MemberFlowTrackerOutbound interface {
	MemberFlowTrackerFactory(member Outbound) func() tun.FlowTracker
}

// StatefulGroup is a group that keeps its runtime state (the current
// member, sticky sessions) when a live apply replaces it.
type StatefulGroup interface {
	InheritGroupState(old Outbound)
}

type GroupMemberState uint8

const (
	GroupMemberUnknown GroupMemberState = iota
	GroupMemberUp
	GroupMemberSuspect
	GroupMemberDown
)

// GroupStatus is what clients are told of a group.
type GroupStatus struct {
	// Mode is one of manual, fastest, fallback, loadbalance, smart.
	Mode     string
	Strategy string
	Members  []GroupMemberStatus
}

type GroupMemberStatus struct {
	Tag   string
	State GroupMemberState
	// Active is whether the member is in use: the current member, or for
	// a load balance group, in rotation.
	Active bool
	// SuccessRate is the decayed rate of successful connections, -1
	// without data.
	SuccessRate float32
	// Latency is the decayed time to first byte of connections in ms, 0
	// without data.
	Latency uint16
	// Score is a smart group's cost of the member, lower is better, 0
	// without one.
	Score float32
}

// GroupStatusReporter is a group that reports its mode and members.
type GroupStatusReporter interface {
	GroupStatus() GroupStatus
}
