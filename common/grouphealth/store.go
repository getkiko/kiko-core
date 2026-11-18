// Package grouphealth keeps what policy groups learn of their members:
// a health state per member, from probes and from routed connections,
// and the decayed connection statistics a smart group scores members by.
//
// Members are keyed by their real tag, so groups sharing a node share
// what is known of it. A failed connection only makes a member suspect;
// a probe decides whether it is down.
package grouphealth

import (
	"math"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	// failureWindow is how long consecutive failures count together.
	failureWindow = time.Minute
	// successHalfLife and latencyHalfLife decay connection outcomes and
	// times to first byte; throughputHalfLife bulk transfer rates.
	successHalfLife    = 10 * time.Minute
	latencyHalfLife    = 10 * time.Minute
	throughputHalfLife = 30 * time.Minute
	// penaltyTau decays recent failures.
	penaltyTau = time.Minute
	// maxDestinations bounds the failed destinations remembered.
	maxDestinations = 4
)

var (
	sharedAccess sync.Mutex
	shared       *Store
)

// Owner holds the store of an instance; its URL test history
// (*urltest.HistoryStorage) is one, so that the store lives and goes
// with the instance.
type Owner interface {
	GroupHealth() *Store
}

// For is the store of the instance whose URL test history is key; a key
// without one (nil) shares a store of its own.
func For(key any) *Store {
	if owner, isOwner := key.(Owner); isOwner {
		if store := owner.GroupHealth(); store != nil {
			return store
		}
	}
	sharedAccess.Lock()
	defer sharedAccess.Unlock()
	if shared == nil {
		shared = NewStore()
	}
	return shared
}

type Store struct {
	access    sync.Mutex
	members   map[string]*member
	now       func() time.Time
	listeners map[*listener]struct{}
}

// listener is told of each probe that changes the state of a member,
// by its real tag, so that every group with that member reconsiders it
// whichever group or URL test probed it.
type listener struct {
	changed func(tag string, state adapter.GroupMemberState)
}

// Subscribe calls changed, outside the store's lock, after each probe
// that changes a member's state; the returned func unsubscribes.
func (s *Store) Subscribe(changed func(tag string, state adapter.GroupMemberState)) (unsubscribe func()) {
	l := &listener{changed: changed}
	s.access.Lock()
	if s.listeners == nil {
		s.listeners = map[*listener]struct{}{}
	}
	s.listeners[l] = struct{}{}
	s.access.Unlock()
	return func() {
		s.access.Lock()
		delete(s.listeners, l)
		s.access.Unlock()
	}
}

func NewStore() *Store {
	return &Store{members: map[string]*member{}, now: time.Now}
}

// SetClock replaces the store's clock, for tests.
func (s *Store) SetClock(now func() time.Time) {
	s.access.Lock()
	s.now = now
	s.access.Unlock()
}

type member struct {
	state     adapter.GroupMemberState
	failures  int
	failedAt  time.Time
	failedTo  []string
	downSince time.Time
	probedAt  time.Time
	success   decayed
	latency   decayed
	rate      decayed
	penalty   float64
	penaltyAt time.Time
}

func (s *Store) member(tag string) *member {
	m := s.members[tag]
	if m == nil {
		m = &member{}
		s.members[tag] = m
	}
	return m
}

// ObserveProbe records a probe of tag; it reports whether the state
// changed, which it tells the store's listeners.
func (s *Store) ObserveProbe(tag string, err error) bool {
	s.access.Lock()
	now := s.now()
	m := s.member(tag)
	old := m.state
	m.probedAt = now
	if err == nil {
		m.state, m.failures, m.failedTo, m.downSince = adapter.GroupMemberUp, 0, nil, time.Time{}
	} else {
		if m.state != adapter.GroupMemberDown {
			m.downSince = now
		}
		m.state = adapter.GroupMemberDown
	}
	state := m.state
	changed := old != state
	var listeners []*listener
	if changed {
		for listener := range s.listeners {
			listeners = append(listeners, listener)
		}
	}
	s.access.Unlock()
	for _, listener := range listeners {
		listener.changed(tag, state)
	}
	return changed
}

// ObserveDial records a routed connection to destination through tag.
// It reports whether the caller should confirm the member's state with
// a probe: it just became suspect, or a connection went through it
// while a probe at least failureWindow ago found it down. maxFailures
// is the group's threshold.
func (s *Store) ObserveDial(tag, destination string, maxFailures int, err error) (confirm bool) {
	s.access.Lock()
	defer s.access.Unlock()
	now := s.now()
	m := s.member(tag)
	if err == nil {
		m.failures, m.failedTo = 0, nil
		switch m.state {
		case adapter.GroupMemberUnknown, adapter.GroupMemberSuspect:
			m.state = adapter.GroupMemberUp
		case adapter.GroupMemberDown:
			// Nothing else probes a down member of a manual group, and
			// a policy group's recovery probes end: a member still in
			// use is probed again, at most once a window.
			if now.Sub(m.probedAt) >= failureWindow {
				m.probedAt = now
				return true
			}
		}
		return false
	}
	if now.Sub(m.failedAt) > failureWindow {
		m.failures, m.failedTo = 0, nil
	}
	m.failures++
	m.failedAt = now
	if destination != "" && !contains(m.failedTo, destination) && len(m.failedTo) < maxDestinations {
		m.failedTo = append(m.failedTo, destination)
	}
	if maxFailures <= 0 {
		maxFailures = 3
	}
	destinations := min(2, maxFailures)
	if m.state == adapter.GroupMemberDown || m.state == adapter.GroupMemberSuspect {
		return false
	}
	if m.failures >= maxFailures && len(m.failedTo) >= destinations {
		m.state = adapter.GroupMemberSuspect
		return true
	}
	return false
}

// ObserveOutcome records how a routed TCP connection through tag went,
// for scoring: success, its time to first byte, and the downstream rate
// of a bulk transfer in bytes per second (0 for none).
func (s *Store) ObserveOutcome(tag string, success bool, firstByte time.Duration, rate float64) {
	s.access.Lock()
	defer s.access.Unlock()
	now := s.now()
	m := s.member(tag)
	if success {
		m.success.add(now, 1, successHalfLife)
		if firstByte > 0 {
			m.latency.add(now, float64(firstByte)/float64(time.Millisecond), latencyHalfLife)
		}
		if rate > 0 {
			m.rate.add(now, rate, throughputHalfLife)
		}
		return
	}
	m.success.add(now, 0, successHalfLife)
	m.penalty = m.penaltyNow(now) + 1
	m.penaltyAt = now
}

func (m *member) penaltyNow(now time.Time) float64 {
	if m.penaltyAt.IsZero() {
		return 0
	}
	return m.penalty * math.Exp(-now.Sub(m.penaltyAt).Seconds()/penaltyTau.Seconds())
}

// State is the health state of tag.
func (s *Store) State(tag string) adapter.GroupMemberState {
	s.access.Lock()
	defer s.access.Unlock()
	if m := s.members[tag]; m != nil {
		return m.state
	}
	return adapter.GroupMemberUnknown
}

// DownSince is when tag went down, zero while it is not.
func (s *Store) DownSince(tag string) time.Time {
	s.access.Lock()
	defer s.access.Unlock()
	if m := s.members[tag]; m != nil && m.state == adapter.GroupMemberDown {
		return m.downSince
	}
	return time.Time{}
}

// Forget resets every member to unknown, as when the network changes.
func (s *Store) Forget() {
	s.access.Lock()
	defer s.access.Unlock()
	for _, m := range s.members {
		m.state, m.failures, m.failedTo, m.downSince = adapter.GroupMemberUnknown, 0, nil, time.Time{}
	}
}

// Stats are the decayed connection statistics of a member.
type Stats struct {
	State adapter.GroupMemberState
	// Success is the success rate and SuccessWeight how much it rests on.
	Success       float64
	SuccessWeight float64
	// Latency is the time to first byte in ms and LatencyWeight how much
	// it rests on.
	Latency       float64
	LatencyWeight float64
	// Rate is the bulk download rate in bytes per second, 0 without one.
	Rate float64
	// Penalty is the decayed count of recent failures.
	Penalty float64
}

func (s *Store) Stats(tag string) Stats {
	s.access.Lock()
	defer s.access.Unlock()
	m := s.members[tag]
	if m == nil {
		return Stats{Success: -1}
	}
	now := s.now()
	stats := Stats{State: m.state, Success: -1, Penalty: m.penaltyNow(now)}
	if v, w := m.success.at(now, successHalfLife); w > 0 {
		stats.Success, stats.SuccessWeight = v, w
	}
	if v, w := m.latency.at(now, latencyHalfLife); w > 0 {
		stats.Latency, stats.LatencyWeight = v, w
	}
	if v, w := m.rate.at(now, throughputHalfLife); w > 0.5 {
		stats.Rate = v
	}
	return stats
}

func contains(list []string, value string) bool {
	for _, it := range list {
		if it == value {
			return true
		}
	}
	return false
}

// decayed is an exponentially time-decayed mean: num and den decay by
// half every half-life.
type decayed struct {
	num, den float64
	updated  time.Time
}

func (d *decayed) decay(now time.Time, halfLife time.Duration) {
	if !d.updated.IsZero() && now.After(d.updated) {
		f := math.Exp2(-now.Sub(d.updated).Seconds() / halfLife.Seconds())
		d.num *= f
		d.den *= f
	}
	d.updated = now
}

func (d *decayed) add(now time.Time, value float64, halfLife time.Duration) {
	d.decay(now, halfLife)
	d.num += value
	d.den++
}

// at is the mean as of now and its weight.
func (d decayed) at(now time.Time, halfLife time.Duration) (float64, float64) {
	d.decay(now, halfLife)
	if d.den <= 0 {
		return 0, 0
	}
	return d.num / d.den, d.den
}
