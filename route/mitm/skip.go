package mitm

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	// ReasonPinned is the skip reason of a connection to a host that
	// rejected the generated certificate repeatedly.
	ReasonPinned = "pinned"

	// DefaultPinningSkipDuration is how long a pinned pair passes through.
	DefaultPinningSkipDuration = 30 * time.Minute

	skipSourceAuto = "auto"

	// pinningThreshold is the number of consecutive failures that put a key
	// into the skip table.
	pinningThreshold = 2

	// pendingWindow is how long a single failure counts as the first of two
	// consecutive ones.
	pendingWindow = 10 * time.Minute

	maxSkipEntries    = 1024
	maxPendingKeys    = 2048
	maxFailureRecords = 200

	// sweepInterval is the shortest time between two sweeps of expired items.
	sweepInterval = 30 * time.Second
)

// pinKey identifies the client of a connection: its process when known,
// otherwise its source address.
type pinKey struct {
	process string
	source  netip.Addr
}

func pinKeyOf(metadata *adapter.InboundContext) pinKey {
	if owner := metadata.ProcessInfo; owner != nil && owner.ProcessPath != "" {
		return pinKey{process: owner.ProcessPath}
	}
	return pinKey{source: metadata.Source.Addr.Unmap().WithZone("")}
}

// sharedClient reports whether the client is indistinguishable from other
// apps on this machine: no process is known and the source is a local
// address, so that its pin key would be shared by all of them.
func (e *Engine) sharedClient(metadata *adapter.InboundContext) bool {
	if owner := metadata.ProcessInfo; owner != nil && owner.ProcessPath != "" {
		return false
	}
	source := metadata.Source.Addr
	if !source.IsValid() {
		return true
	}
	return e.local.contains(source.Unmap().WithZone(""))
}

type pendingKey struct {
	host string
	key  pinKey
}

type pendingState struct {
	count int
	at    time.Time
}

type skipItem struct {
	key    pinKey
	until  time.Time
	source string
	reason string
}

type failureRecord struct {
	count     int
	lastError string
	at        time.Time
}

// skipTable holds the (client, host) pairs that pass through, the
// consecutive failure counts that lead there and a bounded log of failed
// hosts. A lookup that finds nothing takes no lock when the table is empty
// and never allocates.
type skipTable struct {
	mu     sync.RWMutex
	hosts  map[string][]skipItem
	size   int
	active atomic.Int32 // number of skip items
	// lastSweep is the unix nano time of the last sweep of expired items.
	lastSweep atomic.Int64
	pending   map[pendingKey]pendingState
	// pendingCount mirrors len(pending) so that a success without prior
	// failures takes no lock.
	pendingCount atomic.Int32
	failures     map[string]*failureRecord
}

func newSkipTable() *skipTable {
	return &skipTable{
		hosts:    make(map[string][]skipItem),
		pending:  make(map[pendingKey]pendingState),
		failures: make(map[string]*failureRecord),
	}
}

// lookup reports whether the pair is skipped at now.
func (t *skipTable) lookup(host string, key pinKey, now time.Time) bool {
	if t.active.Load() == 0 {
		return false
	}
	t.sweep(now)
	hit, expired := false, false
	t.mu.RLock()
	for i := range t.hosts[host] {
		item := &t.hosts[host][i]
		if !item.until.After(now) {
			expired = true
		} else if item.key == key {
			hit = true
		}
	}
	t.mu.RUnlock()
	if expired {
		t.purge(host, now)
	}
	return hit
}

// hostSkipped reports whether any client of the host is skipped at now.
func (t *skipTable) hostSkipped(host string, now time.Time) bool {
	if t.active.Load() == 0 {
		return false
	}
	t.sweep(now)
	hit, expired := false, false
	t.mu.RLock()
	for _, item := range t.hosts[host] {
		if item.until.After(now) {
			hit = true
		} else {
			expired = true
		}
	}
	t.mu.RUnlock()
	if expired {
		t.purge(host, now)
	}
	return hit
}

// sweep drops the expired items of every host, at most once per
// sweepInterval, so that a table whose hosts are never looked up again
// returns to empty. It takes the write lock only when it runs.
func (t *skipTable) sweep(now time.Time) {
	last := t.lastSweep.Load()
	at := now.UnixNano()
	if at-last < int64(sweepInterval) && at >= last {
		return
	}
	if !t.lastSweep.CompareAndSwap(last, at) {
		return
	}
	t.mu.Lock()
	for host := range t.hosts {
		t.purgeLocked(host, now)
	}
	t.mu.Unlock()
}

// purge drops the expired items of a host.
func (t *skipTable) purge(host string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(host, now)
}

func (t *skipTable) purgeLocked(host string, now time.Time) {
	items := t.hosts[host]
	kept := items[:0]
	for _, item := range items {
		if item.until.After(now) {
			kept = append(kept, item)
		}
	}
	removed := len(items) - len(kept)
	if removed == 0 {
		return
	}
	t.size = max(t.size-removed, 0)
	t.active.Store(int32(t.size))
	if len(kept) == 0 {
		delete(t.hosts, host)
		return
	}
	t.hosts[host] = kept
}

// observe records a failed decryption of a host without counting it
// towards the skip table.
func (t *skipTable) observe(host string, message string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observeLocked(host, message, now)
}

func (t *skipTable) observeLocked(host string, message string, now time.Time) {
	record := t.failures[host]
	if record == nil {
		if len(t.failures) >= maxFailureRecords {
			t.evictOldestFailureLocked()
		}
		record = &failureRecord{}
		t.failures[host] = record
	}
	record.count++
	record.lastError = message
	record.at = now
}

func (t *skipTable) evictOldestFailureLocked() {
	var (
		oldest     string
		oldestTime time.Time
		found      bool
	)
	for host, record := range t.failures {
		if !found || record.at.Before(oldestTime) {
			oldest, oldestTime, found = host, record.at, true
		}
	}
	if found {
		delete(t.failures, oldest)
	}
}

// failPinning counts a certificate rejection by the client. The second
// consecutive one adds the pair to the skip table for duration and
// reports true.
func (t *skipTable) failPinning(host string, key pinKey, message string, now time.Time, duration time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observeLocked(host, message, now)
	pending := pendingKey{host: host, key: key}
	state := t.pending[pending]
	if state.count == 0 && len(t.pending) >= maxPendingKeys {
		for other := range t.pending {
			delete(t.pending, other)
			break
		}
	}
	if state.count > 0 && now.Sub(state.at) > pendingWindow {
		state.count = 0
	}
	state.count++
	state.at = now
	if state.count < pinningThreshold {
		t.pending[pending] = state
		t.pendingCount.Store(int32(len(t.pending)))
		return false
	}
	delete(t.pending, pending)
	t.pendingCount.Store(int32(len(t.pending)))
	t.addLocked(host, skipItem{key: key, until: now.Add(duration), source: skipSourceAuto, reason: ReasonPinned}, now)
	return true
}

func (t *skipTable) addLocked(host string, item skipItem, now time.Time) {
	items := t.hosts[host]
	for i := range items {
		if items[i].key == item.key {
			items[i] = item
			return
		}
	}
	if t.size >= maxSkipEntries {
		t.makeRoomLocked(now)
		// makeRoomLocked compacts and replaces host slices in place.
		items = t.hosts[host]
	}
	t.hosts[host] = append(items, item)
	t.size++
	t.active.Store(int32(t.size))
}

// makeRoomLocked drops expired items, or the one expiring first.
func (t *skipTable) makeRoomLocked(now time.Time) {
	for host := range t.hosts {
		t.purgeLocked(host, now)
	}
	if t.size < maxSkipEntries {
		return
	}
	var (
		oldestHost string
		oldestAt   time.Time
		oldestAny  bool
	)
	for host, items := range t.hosts {
		for _, item := range items {
			if !oldestAny || item.until.Before(oldestAt) {
				oldestHost, oldestAt, oldestAny = host, item.until, true
			}
		}
	}
	if !oldestAny {
		return
	}
	items := t.hosts[oldestHost]
	for i, item := range items {
		if item.until.Equal(oldestAt) {
			items = append(items[:i], items[i+1:]...)
			break
		}
	}
	t.size = max(t.size-1, 0)
	t.active.Store(int32(t.size))
	if len(items) == 0 {
		delete(t.hosts, oldestHost)
	} else {
		t.hosts[oldestHost] = items
	}
}

// succeed resets the consecutive failures of a pair.
func (t *skipTable) succeed(host string, key pinKey) {
	if t.pendingCount.Load() == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, pendingKey{host: host, key: key})
	t.pendingCount.Store(int32(len(t.pending)))
}

// clear removes the skip items, pending counts and failure records of a
// host, or of every host when host is empty.
func (t *skipTable) clear(host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := false
	if host == "" {
		removed = len(t.hosts) > 0 || len(t.pending) > 0 || len(t.failures) > 0
		clear(t.hosts)
		clear(t.pending)
		clear(t.failures)
		t.size = 0
	} else {
		if items, loaded := t.hosts[host]; loaded {
			t.size -= len(items)
			delete(t.hosts, host)
			removed = true
		}
		for key := range t.pending {
			if key.host == host {
				delete(t.pending, key)
				removed = true
			}
		}
		if _, loaded := t.failures[host]; loaded {
			delete(t.failures, host)
			removed = true
		}
	}
	t.active.Store(int32(t.size))
	t.pendingCount.Store(int32(len(t.pending)))
	return removed
}

// snapshot lists the live skip items (by host) and the failed hosts (newest
// first).
func (t *skipTable) snapshot(now time.Time) ([]adapter.MITMSkipEntry, []adapter.MITMFailure) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var skip []adapter.MITMSkipEntry
	for host, items := range t.hosts {
		for _, item := range items {
			if item.until.After(now) {
				skip = append(skip, adapter.MITMSkipEntry{Host: host, Source: item.source, Until: item.until, Reason: item.reason})
			}
		}
	}
	sort.Slice(skip, func(i, j int) bool {
		if skip[i].Host != skip[j].Host {
			return skip[i].Host < skip[j].Host
		}
		return skip[i].Until.Before(skip[j].Until)
	})
	var failures []adapter.MITMFailure
	for host, record := range t.failures {
		failures = append(failures, adapter.MITMFailure{Host: host, Count: record.count, LastError: record.lastError, At: record.at})
	}
	sort.Slice(failures, func(i, j int) bool {
		if !failures[i].At.Equal(failures[j].At) {
			return failures[i].At.After(failures[j].At)
		}
		return failures[i].Host < failures[j].Host
	})
	return skip, failures
}
