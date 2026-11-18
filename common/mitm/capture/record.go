// Package capture keeps decrypted HTTP exchanges in a bounded in-memory ring
// and serves them to subscribers with the instance/seq/floor poll protocol of
// the DNS monitor.
package capture

import (
	"github.com/sagernet/sing-box/common/mitm/flow"
)

// State is the lifecycle of a record.
type State uint8

const (
	StateInProgress State = iota
	StateComplete
	StateFailed
	// StateUpgraded is an exchange that switched protocol (101). Its bytes
	// after the switch are not captured, so it counts as finished for
	// eviction.
	StateUpgraded
)

func (s State) String() string {
	switch s {
	case StateComplete:
		return "complete"
	case StateFailed:
		return "failed"
	case StateUpgraded:
		return "upgraded"
	default:
		return "in_progress"
	}
}

// Record describes one exchange. Snapshots share their slices and Connection
// with the stored record; none of them is modified after it is set.
type Record struct {
	// ID is unique within an Instance.
	ID       string
	Instance string
	// Seq is the sequence of the latest change; CreatedSeq of the creation.
	Seq        uint64
	CreatedSeq uint64

	ConnectionID string
	RequestIndex uint32
	Connection   *flow.ConnectionInfo

	Method    string
	Scheme    string
	Authority string
	Host      string
	Path      string // with query
	URL       string
	Proto     string // "http/1.1" or "h2"
	Status    int
	Interim   []int // 1xx codes seen before the final response

	RequestHeaders   []flow.Header
	ResponseHeaders  []flow.Header
	RequestTrailers  []flow.Header
	ResponseTrailers []flow.Header

	// RequestBytes and ResponseBytes are the body bytes that passed, saved or
	// not. They are final once the matching body is done.
	RequestBytes  int64
	ResponseBytes int64

	// *BodySaved reports that body capture was on for the exchange;
	// *BodyStored is the number of bytes kept; *BodyTruncated that fewer
	// bytes than passed are kept.
	RequestBodySaved      bool
	ResponseBodySaved     bool
	RequestBodyStored     int64
	ResponseBodyStored    int64
	RequestBodyTruncated  bool
	ResponseBodyTruncated bool
	// BodyDropped means the memory budget stopped saving a body.
	BodyDropped bool

	RequestEncoding  string
	ResponseEncoding string

	Timing flow.Timing
	State  State
	Error  string

	// Unverified means the upstream certificate was not verified.
	Unverified bool
	// Rewritten means a rule changed the exchange.
	Rewritten bool
	// Rewrites lists the rewrite hits in the order they ran. Snapshots share
	// the slice; it is never modified in place.
	Rewrites []flow.RewriteHit
}

// EventKind tells what happened to a record since the cursor.
type EventKind uint8

const (
	EventNew EventKind = iota + 1
	EventUpdate
	EventDone
)

func (k EventKind) String() string {
	switch k {
	case EventNew:
		return "new"
	case EventUpdate:
		return "update"
	case EventDone:
		return "done"
	}
	return ""
}

// Event carries the latest metadata snapshot of a record.
type Event struct {
	Kind   EventKind
	Record Record
}

// Stats summarizes the store.
type Stats struct {
	Records     int
	InProgress  int
	Bytes       int64
	MaxMemory   int64
	MaxRecords  int
	Total       uint64
	Evicted     uint64
	BodyDropped uint64
}

// View is the answer to Poll.
type View struct {
	Instance string
	// Seq is the cursor to resume from.
	Seq   uint64
	Floor uint64
	// Reset means Events is a fresh snapshot that replaces the client's list.
	Reset bool
	// Gap is a Reset caused by eviction or Clear while the instance matched.
	Gap bool
	// More means the batch was cut and an immediate Poll(Seq) continues it.
	More   bool
	Events []Event
	Stats  Stats
}

// Filter selects records for List.
type Filter struct {
	Search       string
	Host         string
	ConnectionID string
	Limit        int
	// Before is the numeric ID the page starts below (exclusive).
	Before uint64
}

// ListResult is a page of records, newest first.
type ListResult struct {
	Instance   string
	Records    []Record
	NextBefore uint64
	Stats      Stats
}
