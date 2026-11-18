package script

import (
	"context"
	"hash/fnv"
	"sync"
	"time"
)

// Scheduler tuning.
const (
	// cronGrace is how late a tick may start. A tick that is later (the machine slept, the
	// process was stopped) is not run: missed ticks are not caught up.
	cronGrace = 30 * time.Second
	// cronMaxSleep bounds one wait of the scheduler loop, so that a jump of the wall clock is
	// noticed.
	cronMaxSleep = 30 * time.Second
	// cronJitter is the exclusive upper bound of the per-script delay after the scheduled
	// minute starts, which spreads scripts that share a schedule.
	cronJitter = time.Second
)

// cronClock is the time source of the scheduler; tests replace it.
type cronClock interface {
	Now() time.Time
	NewTimer(d time.Duration) cronTimer
}

type cronTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTimer(d time.Duration) cronTimer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.Timer.C }

type cronEntry struct {
	sc     *Script
	next   time.Time
	jitter time.Duration
}

// scheduler runs the cron scripts of the active set. One goroutine sleeps until the earliest
// tick and starts each due script in a goroutine of its own.
type scheduler struct {
	m     *Manager
	clock cronClock

	mu      sync.Mutex
	entries map[string]*cronEntry
	stopped bool

	wake chan struct{}
	quit chan struct{}
	done chan struct{}

	// runCtx is the context of the runs the scheduler starts; canceling it ends them.
	runCtx    context.Context
	runCancel context.CancelFunc
}

func newScheduler(m *Manager, clock cronClock) *scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	s := &scheduler{
		m: m, clock: clock, entries: map[string]*cronEntry{},
		wake: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{}),
		runCtx: ctx, runCancel: cancel,
	}
	go s.loop()
	return s
}

func cronJitterOf(tag string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	return time.Duration(h.Sum32()%1000) * time.Millisecond % cronJitter
}

// update rebuilds the entries for set. Scripts that did not change keep their next tick;
// the others are scheduled from now.
func (s *scheduler) update(set *Set) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	entries := make(map[string]*cronEntry, len(s.entries))
	for _, sc := range set.scripts {
		if sc.cron == nil {
			continue
		}
		e := &cronEntry{sc: sc, jitter: cronJitterOf(sc.cfg.Tag)}
		if old := s.entries[sc.cfg.Tag]; old != nil && old.sc.state == sc.state && !old.next.IsZero() {
			e.next = old.next
		} else {
			e.next = sc.cron.Next(now)
		}
		sc.state.setNextRun(e.next)
		entries[sc.cfg.Tag] = e
	}
	for tag, old := range s.entries {
		if cur := entries[tag]; cur == nil || cur.sc.state != old.sc.state {
			old.sc.state.setNextRun(time.Time{})
		}
	}
	s.entries = entries
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// stop ends the loop; cancelRuns also cancels the runs in flight.
func (s *scheduler) stop(cancelRuns bool) {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.quit)
		for _, e := range s.entries {
			e.sc.state.setNextRun(time.Time{})
		}
		s.entries = map[string]*cronEntry{}
	}
	s.mu.Unlock()
	if cancelRuns {
		s.runCancel()
	}
}

func (s *scheduler) loop() {
	defer close(s.done)
	// Round(0) drops the monotonic reading: a wall-clock jump must show in the comparison.
	last := s.clock.Now().Round(0)
	for {
		now := s.clock.Now().Round(0)
		wait := s.tick(now, now.Before(last.Add(-time.Second)))
		last = now
		timer := s.clock.NewTimer(wait)
		select {
		case <-timer.C():
		case <-s.wake:
			timer.Stop()
		case <-s.quit:
			timer.Stop()
			return
		}
	}
}

// tick starts the scripts that are due at now and returns how long to sleep. When the clock
// went backwards every schedule is recomputed from now.
func (s *scheduler) tick(now time.Time, rewound bool) time.Duration {
	wait := cronMaxSleep
	var fire []*Script
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return cronMaxSleep
	}
	for _, e := range s.entries {
		if rewound {
			e.next = e.sc.cron.Next(now)
			e.sc.state.setNextRun(e.next)
		}
		if e.next.IsZero() {
			continue
		}
		due := e.next.Add(e.jitter)
		if now.Before(due) {
			wait = min(wait, due.Sub(now))
			continue
		}
		if now.Sub(due) <= cronGrace {
			fire = append(fire, e.sc)
		}
		e.next = e.sc.cron.Next(now)
		e.sc.state.setNextRun(e.next)
		if !e.next.IsZero() {
			wait = min(wait, e.next.Add(e.jitter).Sub(now))
		}
	}
	ctx := s.runCtx
	s.mu.Unlock()
	for _, sc := range fire {
		go s.m.runCron(ctx, sc)
	}
	return max(wait, time.Millisecond)
}

func (st *scriptState) setNextRun(t time.Time) {
	st.mu.Lock()
	st.nextRun = t
	st.mu.Unlock()
}

// runCron runs a cron script on its schedule.
func (m *Manager) runCron(ctx context.Context, sc *Script) {
	st := sc.state
	now := time.Now()
	st.mu.Lock()
	paused := now.Before(st.pausedUntil)
	if paused {
		st.skipped++
	}
	st.mu.Unlock()
	var res *Result
	if paused {
		res = &Result{Tag: sc.cfg.Tag, Phase: sc.cfg.Type, Action: ActionPaused, Reason: "paused", Error: "paused after repeated failures"}
	} else {
		res = m.runExclusive(ctx, sc)
	}
	if hook := m.OnRun; hook != nil {
		hook(res)
	}
}

// runExclusive runs a cron script unless a previous run of it is still going (a skipped run
// with reason busy).
func (m *Manager) runExclusive(ctx context.Context, sc *Script) *Result {
	st := sc.state
	if !st.running.CompareAndSwap(false, true) {
		// A skipped run is not a run: only the skip is counted.
		st.mu.Lock()
		st.skipped++
		st.mu.Unlock()
		return &Result{Tag: sc.cfg.Tag, Phase: sc.cfg.Type, Action: ActionSkipped, Reason: SkipBusy}
	}
	defer st.running.Store(false)
	res := m.execute(ctx, sc, nil, runOptions{})
	m.record(sc, res)
	return res
}

// StartSchedule lets cron scripts run. The host calls it once everything they use (store,
// $httpClient) is attached; until then, and after Close, a swapped-in set is not scheduled.
func (m *Manager) StartSchedule() {
	m.schedMu.Lock()
	m.started = true
	m.schedMu.Unlock()
	m.syncSchedule(m.current.Load(), false)
}

// syncSchedule brings the scheduler in line with set. closing is set by Close and a swap to
// nil: the scheduler stops and the runs it started are canceled.
func (m *Manager) syncSchedule(set *Set, closing bool) {
	m.schedMu.Lock()
	defer m.schedMu.Unlock()
	if closing || !set.hasCron() {
		if m.sched != nil {
			m.sched.stop(closing)
			m.sched = nil
		}
		return
	}
	if m.closed || !m.started {
		// Before StartSchedule and after Close the set may still be swapped, but nothing runs on a schedule.
		return
	}
	if m.sched == nil {
		clock := m.cronClock
		if clock == nil {
			clock = realClock{}
		}
		m.sched = newScheduler(m, clock)
	}
	m.sched.update(set)
}

func (s *Set) hasCron() bool {
	if s == nil {
		return false
	}
	for _, sc := range s.scripts {
		if sc.cron != nil {
			return true
		}
	}
	return false
}
