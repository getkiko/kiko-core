package dnsmonitor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/service"
)

type Options struct {
	Entries     int
	Bytes       int
	Age         time.Duration
	CaptureWire bool
}

type Stats struct {
	Total     uint64 `json:"total,string"`
	Pending   int    `json:"pending"`
	Retained  int    `json:"retained"`
	Bytes     int    `json:"bytes"`
	Dropped   uint64 `json:"dropped,string"`
	Evicted   uint64 `json:"evicted,string"`
	Errors    uint64 `json:"errors,string"`
	Timeouts  uint64 `json:"timeouts,string"`
	CacheHits uint64 `json:"cache_hits,string"`
}

type Filter struct {
	Search, Status, Resolver string
	Limit                    int
	Before                   uint64
}

type View struct {
	Instance   string  `json:"instance"`
	Seq        uint64  `json:"seq,string"`
	Reset      bool    `json:"reset,omitempty"`
	Gap        bool    `json:"gap,omitempty"`
	Queries    []Query `json:"queries"`
	Stats      Stats   `json:"stats"`
	NextBefore uint64  `json:"next_before,string,omitempty"`
}

// Manager stores bounded traces. The observer only updates a trace and attempts
// a nonblocking wakeup. JSON encoding and stream I/O run on the reader side.
type Manager struct {
	mu          sync.Mutex
	options     Options
	instance    string
	seq         uint64
	floor       uint64
	ids         atomic.Uint64
	queries     map[string]*Trace
	sizes       map[string]int
	stats       Stats
	wake        chan struct{}
	done        chan struct{}
	once        sync.Once
	connMu      sync.Mutex
	connections map[any]*Connection
	flights     sync.Map
}

func New(options Options) *Manager {
	if options.Entries <= 0 {
		options.Entries = 5000
	}
	if options.Entries > 50000 {
		options.Entries = 50000
	}
	if options.Bytes <= 0 {
		options.Bytes = 32 << 20
	}
	if options.Bytes > 256<<20 {
		options.Bytes = 256 << 20
	}
	if options.Age <= 0 {
		options.Age = 10 * time.Minute
	}
	m := &Manager{options: options, instance: newInstance(), queries: make(map[string]*Trace), sizes: make(map[string]int), wake: make(chan struct{}, 1), done: make(chan struct{}), connections: make(map[any]*Connection)}
	go m.run()
	return m
}

func newInstance() string                      { var b [12]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func FromContext(ctx context.Context) *Manager { return service.PtrFromContext[Manager](ctx) }
func (m *Manager) nextID() string              { return strconv.FormatUint(m.ids.Add(1), 10) }
func (m *Manager) Close() error                { m.once.Do(func() { close(m.done) }); return nil }
func (m *Manager) notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}
func (m *Manager) Done() <-chan struct{} { return m.done }

func (m *Manager) run() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.flush()
		case <-m.wake: /* coalesce until next tick */
		}
	}
}

func (m *Manager) flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, t := range m.queries {
		t.mu.Lock()
		if t.dirty {
			m.seq++
			t.q.Seq = m.seq
			t.dirty = false
			t.mu.Unlock()
			encoded, _ := json.Marshal(t.copy(false))
			t.mu.Lock()
			m.stats.Bytes += len(encoded) - m.sizes[id]
			m.sizes[id] = len(encoded)
		}
		// A missing completion is surfaced as capture incompleteness. DNS
		// timeouts retain their actual resolver-provided context deadline.
		if t.q.Status == "pending" && now.Sub(t.q.StartedAt) > 5*time.Minute {
			t.q.Incomplete = true
		}
		t.mu.Unlock()
	}
	m.trimLocked(now)
}

func (m *Manager) trimLocked(now time.Time) {
	type item struct {
		id       string
		seq      uint64
		finished *time.Time
	}
	items := make([]item, 0, len(m.queries))
	for id, t := range m.queries {
		t.mu.Lock()
		items = append(items, item{id, t.q.Seq, t.q.FinishedAt})
		t.mu.Unlock()
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	for _, v := range items {
		if v.finished == nil {
			continue
		}
		if len(m.queries) <= m.options.Entries && m.stats.Bytes <= m.options.Bytes && now.Sub(*v.finished) <= m.options.Age {
			continue
		}
		m.evictLocked(v.id)
	}
	m.stats.Retained = len(m.queries)
}

func (m *Manager) evictLocked(id string) {
	t := m.queries[id]
	if t == nil {
		return
	}
	t.mu.Lock()
	seq := t.q.Seq
	t.mu.Unlock()
	delete(m.queries, id)
	m.stats.Bytes -= m.sizes[id]
	delete(m.sizes, id)
	m.stats.Evicted++
	if seq > m.floor {
		m.floor = seq
	}
	if seq == 0 {
		m.seq++
		m.floor = m.seq
	}
}

func (m *Manager) Get(id string) (Query, bool) {
	m.flush()
	m.mu.Lock()
	t, ok := m.queries[id]
	m.mu.Unlock()
	if !ok {
		return Query{}, false
	}
	return t.copy(false), true
}

func (m *Manager) List(f Filter) View {
	m.flush()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked(f, "", 0, false)
}

// Poll resumes from an instance/sequence cursor. Coalesced revisions carry the
// latest state; evictions and instance changes request a bounded fresh snapshot.
func (m *Manager) Poll(instance string, after uint64) View {
	m.flush()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked(Filter{Limit: 500}, instance, after, true)
}

func (m *Manager) viewLocked(f Filter, instance string, after uint64, stream bool) View {
	v := View{Instance: m.instance, Seq: m.seq, Stats: m.stats, Queries: make([]Query, 0)}
	v.Reset = stream && (instance != m.instance || after < m.floor || after > m.seq)
	v.Gap = stream && instance == m.instance && after < m.floor
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 500
	}
	for _, t := range m.queries {
		q := t.copy(true)
		if stream && !v.Reset && q.Seq <= after {
			continue
		}
		if f.Before > 0 && q.Seq >= f.Before {
			continue
		}
		if matches(q, f) {
			v.Queries = append(v.Queries, q)
		}
	}
	sort.Slice(v.Queries, func(i, j int) bool {
		if stream && !v.Reset {
			return v.Queries[i].Seq < v.Queries[j].Seq
		}
		return v.Queries[i].Seq > v.Queries[j].Seq
	})
	if len(v.Queries) > f.Limit {
		v.Queries = v.Queries[:f.Limit]
		if stream && !v.Reset {
			v.Seq = v.Queries[len(v.Queries)-1].Seq
		}
	}
	if len(v.Queries) > 0 {
		v.NextBefore = v.Queries[len(v.Queries)-1].Seq
	}
	return v
}

func (m *Manager) Clear() View {
	m.mu.Lock()
	for id, t := range m.queries {
		t.mu.Lock()
		done := t.q.FinishedAt != nil
		t.mu.Unlock()
		if done {
			delete(m.queries, id)
			delete(m.sizes, id)
		}
	}
	m.instance = newInstance()
	m.floor = 0
	m.stats.Bytes = 0
	for _, t := range m.queries {
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
	}
	m.mu.Unlock()
	return m.Poll("", 0)
}

func (m *Manager) Instance() string { m.mu.Lock(); defer m.mu.Unlock(); return m.instance }
