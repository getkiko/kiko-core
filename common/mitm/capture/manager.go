package capture

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing/service"

	crand "crypto/rand"
	"encoding/hex"
)

// Options configure the store. Zero values take the defaults.
type Options struct {
	Enabled    bool
	Body       bool
	MaxBody    int64
	MaxMemory  int64
	MaxRecords int
}

const (
	defaultMaxBody    = 512 << 10
	defaultMaxMemory  = 64 << 20
	defaultMaxRecords = 5000

	// recordBaseSize estimates a record without strings and headers.
	recordBaseSize = 768
	headerOverhead = 32
	pollLimit      = 500
	maxListLimit   = 500
	logFactor      = 2
	minLog         = 2048
)

var (
	ErrNotFound = errors.New("record not found")
	// ErrReset means the instance changed; the client must reload.
	ErrReset = errors.New("capture instance changed")
	// ErrRange means a body request had a negative offset or length.
	ErrRange = errors.New("invalid body range")
)

func normalize(o Options) Options {
	if o.MaxBody <= 0 {
		o.MaxBody = defaultMaxBody
	}
	if o.MaxMemory <= 0 {
		o.MaxMemory = defaultMaxMemory
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = defaultMaxRecords
	}
	return o
}

// logEntry names a change by record number, so that the log keeps no evicted
// record alive.
type logEntry struct {
	seq     uint64
	ordinal uint64
}

type entry struct {
	rec        Record
	ordinal    uint64
	prev, next *entry
	size       int64
	req, resp  bodyStore
	finished   bool
	evicted    bool
}

// Manager is the capture store. Writers hold one short lock per event; slow
// readers never block them.
type Manager struct {
	mu       sync.Mutex
	opts     Options
	instance string
	seq      uint64
	floor    uint64
	ordinal  uint64
	bytes    int64
	count    int
	pending  int

	head, tail *entry
	byID       map[uint64]*entry

	// finishedQueue lists finished entries in finishing order; entries
	// evicted by other means are skipped lazily.
	finishedQueue []*entry
	finishedHead  int

	log      []logEntry
	logStart int
	logLen   int

	total       uint64
	evicted     uint64
	bodyDropped uint64

	subMu sync.Mutex
	subs  map[chan struct{}]struct{}
}

// New returns a store.
func New(options Options) *Manager {
	options = normalize(options)
	m := &Manager{
		opts:     options,
		instance: newInstance(),
		byID:     make(map[uint64]*entry),
		subs:     make(map[chan struct{}]struct{}),
	}
	m.resizeLogLocked()
	return m
}

func newInstance() string {
	var b [12]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// FromContext returns the store registered in ctx.
func FromContext(ctx context.Context) *Manager { return service.PtrFromContext[Manager](ctx) }

// Instance identifies this store until the process restarts.
func (m *Manager) Instance() string { return m.instance }

// Options returns the settings in effect.
func (m *Manager) Options() Options {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opts
}

// SetOptions applies new settings to future exchanges and trims the store.
func (m *Manager) SetOptions(options Options) {
	options = normalize(options)
	m.mu.Lock()
	defer m.mu.Unlock()
	resize := options.MaxRecords != m.opts.MaxRecords
	m.opts = options
	if resize {
		m.resizeLogLocked()
		m.seq++
		m.floor = m.seq
	}
	m.enforceLocked()
	m.notifyLocked()
}

// Observer returns the store as an Observer, or nil while capture is off.
func (m *Manager) Observer() flow.Observer {
	m.mu.Lock()
	enabled := m.opts.Enabled
	m.mu.Unlock()
	if !enabled {
		return nil
	}
	return m
}

func (m *Manager) resizeLogLocked() {
	size := m.opts.MaxRecords * logFactor
	if size < minLog {
		size = minLog
	}
	m.log = make([]logEntry, size)
	m.logStart, m.logLen = 0, 0
}

// Subscribe returns a channel that receives a token after changes. Tokens
// coalesce: a slow reader sees one pending token and catches up with Poll.
func (m *Manager) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	m.subMu.Lock()
	m.subs[ch] = struct{}{}
	m.subMu.Unlock()
	ch <- struct{}{}
	return ch, func() {
		m.subMu.Lock()
		delete(m.subs, ch)
		m.subMu.Unlock()
	}
}

// Subscribers returns the number of active subscriptions.
func (m *Manager) Subscribers() int {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	return len(m.subs)
}

func (m *Manager) notifyLocked() {
	m.subMu.Lock()
	for ch := range m.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	m.subMu.Unlock()
}

// touchLocked records a change of e and wakes subscribers.
func (m *Manager) touchLocked(e *entry) {
	m.seq++
	e.rec.Seq = m.seq
	capacity := len(m.log)
	if m.logLen == capacity {
		old := m.log[m.logStart]
		if oe := m.byID[old.ordinal]; oe != nil && oe.rec.Seq == old.seq && old.seq > m.floor {
			m.floor = old.seq
		}
		m.log[m.logStart] = logEntry{m.seq, e.ordinal}
		m.logStart = (m.logStart + 1) % capacity
	} else {
		m.log[(m.logStart+m.logLen)%capacity] = logEntry{m.seq, e.ordinal}
		m.logLen++
	}
	m.notifyLocked()
}

func (m *Manager) addSizeLocked(e *entry, delta int64) {
	e.size += delta
	m.bytes += delta
}

// enforceLocked evicts the oldest finished records until the count and the
// byte budget hold. Records in progress stay.
func (m *Manager) enforceLocked() {
	for (m.count > m.opts.MaxRecords || m.bytes > m.opts.MaxMemory) && m.evictOldestFinishedLocked() {
	}
}

func (m *Manager) evictOldestFinishedLocked() bool {
	for m.finishedHead < len(m.finishedQueue) {
		e := m.finishedQueue[m.finishedHead]
		m.finishedQueue[m.finishedHead] = nil
		m.finishedHead++
		if m.finishedHead > 1024 && m.finishedHead*2 > len(m.finishedQueue) {
			m.finishedQueue = append(m.finishedQueue[:0], m.finishedQueue[m.finishedHead:]...)
			m.finishedHead = 0
		}
		if e.evicted {
			continue
		}
		m.removeLocked(e)
		m.evicted++
		if e.rec.Seq > m.floor {
			m.floor = e.rec.Seq
		}
		return true
	}
	return false
}

func (m *Manager) removeLocked(e *entry) {
	e.evicted = true
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		m.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		m.tail = e.prev
	}
	e.prev, e.next = nil, nil
	delete(m.byID, e.ordinal)
	m.bytes -= e.size
	m.count--
	e.req.chunks, e.resp.chunks = nil, nil
}

func (m *Manager) markFinishedLocked(e *entry) {
	if e.finished || e.evicted {
		return
	}
	e.finished = true
	m.pending--
	m.finishedQueue = append(m.finishedQueue, e)
}

// Stats returns the current counters.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statsLocked()
}

func (m *Manager) statsLocked() Stats {
	return Stats{
		Records:     m.count,
		InProgress:  m.pending,
		Bytes:       m.bytes,
		MaxMemory:   m.opts.MaxMemory,
		MaxRecords:  m.opts.MaxRecords,
		Total:       m.total,
		Evicted:     m.evicted,
		BodyDropped: m.bodyDropped,
	}
}

// Poll returns the changes after the cursor. A client starts with an empty
// instance; Reset then carries a snapshot of the newest records.
func (m *Manager) Poll(instance string, after uint64) View {
	m.mu.Lock()
	defer m.mu.Unlock()
	view := View{Instance: m.instance, Seq: m.seq, Floor: m.floor, Stats: m.statsLocked()}
	view.Reset = instance != m.instance || after < m.floor || after > m.seq
	view.Gap = instance == m.instance && after < m.floor
	if view.Reset {
		var events []Event
		for e := m.tail; e != nil && len(events) < pollLimit; e = e.prev {
			events = append(events, Event{Kind: snapshotKind(e), Record: e.rec})
		}
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
		view.Events = events
		return view
	}
	if after == m.seq {
		return view
	}
	capacity := len(m.log)
	first := m.logLen
	for first > 0 && m.log[(m.logStart+first-1)%capacity].seq > after {
		first--
	}
	for i := first; i < m.logLen; i++ {
		item := m.log[(m.logStart+i)%capacity]
		e := m.byID[item.ordinal]
		if e == nil || e.rec.Seq != item.seq {
			continue
		}
		if len(view.Events) == pollLimit {
			view.More = true
			break
		}
		kind := EventUpdate
		switch {
		case e.finished:
			kind = EventDone
		case e.rec.CreatedSeq > after:
			kind = EventNew
		}
		view.Events = append(view.Events, Event{Kind: kind, Record: e.rec})
		view.Seq = item.seq
	}
	return view
}

func snapshotKind(e *entry) EventKind {
	if e.finished {
		return EventDone
	}
	return EventNew
}

// Get returns the record with the numeric id.
func (m *Manager) Get(id string) (Record, bool) {
	ordinal, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return Record{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.byID[ordinal]
	if e == nil {
		return Record{}, false
	}
	return e.rec, true
}

// List returns records newest first.
func (m *Manager) List(filter Filter) ListResult {
	limit := filter.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = maxListLimit
	}
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	host := strings.ToLower(strings.TrimSpace(filter.Host))
	m.mu.Lock()
	defer m.mu.Unlock()
	result := ListResult{Instance: m.instance, Stats: m.statsLocked(), Records: make([]Record, 0, 16)}
	for e := m.tail; e != nil; e = e.prev {
		if filter.Before != 0 && e.ordinal >= filter.Before {
			continue
		}
		if filter.ConnectionID != "" && e.rec.ConnectionID != filter.ConnectionID {
			continue
		}
		if host != "" && e.rec.Host != host && !strings.HasSuffix(e.rec.Host, "."+host) {
			continue
		}
		if search != "" && !matchSearch(&e.rec, search) {
			continue
		}
		if len(result.Records) == limit {
			break
		}
		result.Records = append(result.Records, e.rec)
		result.NextBefore = e.ordinal
	}
	return result
}

func matchSearch(r *Record, search string) bool {
	return strings.Contains(strings.ToLower(r.URL), search) ||
		strings.Contains(strings.ToLower(r.Method), search) ||
		strconv.Itoa(r.Status) == search ||
		(r.Connection != nil && strings.Contains(strings.ToLower(r.Connection.ProcessName), search))
}

// Clear drops finished records. Records in progress stay, the instance is
// unchanged and the floor moves up so that clients reload.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for e := m.head; e != nil; {
		next := e.next
		if e.finished {
			m.removeLocked(e)
		}
		e = next
	}
	m.finishedQueue = m.finishedQueue[:0]
	m.finishedHead = 0
	m.logStart, m.logLen = 0, 0
	m.seq++
	m.floor = m.seq
	m.notifyLocked()
}

// NewExchange implements flow.Observer.
func (m *Manager) NewExchange(conn *flow.ConnectionInfo) flow.Exchange {
	now := time.Now()
	m.mu.Lock()
	options := m.opts
	if !options.Enabled {
		m.mu.Unlock()
		return flow.NopExchange{}
	}
	m.ordinal++
	m.total++
	x := &exchange{m: m, e: &entry{ordinal: m.ordinal}}
	e := x.e
	e.rec = Record{
		ID:                strconv.FormatUint(m.ordinal, 10),
		Instance:          m.instance,
		Connection:        conn,
		RequestBodySaved:  options.Body,
		ResponseBodySaved: options.Body,
	}
	e.rec.Timing.Start = now
	if conn != nil {
		e.rec.ConnectionID = conn.ID
		e.rec.RequestIndex = conn.NextRequest()
		e.rec.Unverified = conn.Unverified
	}
	x.req = bodyRec{x: x, side: flow.Request}
	x.resp = bodyRec{x: x, side: flow.Response}
	if options.Body {
		x.req.tee.Sink, x.req.tee.Limit = &x.req, options.MaxBody
		x.resp.tee.Sink, x.resp.tee.Limit = &x.resp, options.MaxBody
	}
	e.size = recordBaseSize
	m.bytes += recordBaseSize
	m.count++
	m.pending++
	m.byID[e.ordinal] = e
	e.prev = m.tail
	if m.tail != nil {
		m.tail.next = e
	} else {
		m.head = e
	}
	m.tail = e
	m.touchLocked(e)
	e.rec.CreatedSeq = e.rec.Seq
	m.enforceLocked()
	m.mu.Unlock()
	return x
}

func hostOf(authority string) string {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func headersSize(headers []flow.Header) int64 {
	var size int64
	for i := range headers {
		size += int64(len(headers[i].Name) + len(headers[i].Value) + headerOverhead)
	}
	return size
}

// hitsSize is the memory a rewrite hit list holds in a record.
func hitsSize(hits []flow.RewriteHit) int64 {
	var size int64
	for i := range hits {
		size += int64(len(hits[i].Rule)+len(hits[i].Target)+len(hits[i].Kind)+len(hits[i].Action)+len(hits[i].Side)) + headerOverhead
		for j := range hits[i].Changes {
			c := &hits[i].Changes[j]
			size += int64(len(c.Name)+len(c.Before)+len(c.After)+len(c.Op)) + headerOverhead
		}
		if run := hits[i].Run; run != nil {
			size += int64(len(run.Phase)+len(run.Error)+len(run.Reason)) + headerOverhead
			for j := range run.Logs {
				size += int64(len(run.Logs[j].Level)+len(run.Logs[j].Message)) + headerOverhead
			}
		}
	}
	return size
}
