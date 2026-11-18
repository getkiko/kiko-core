package script

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manual cronClock.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c     *fakeClock
	at    time.Time
	ch    chan time.Time
	fired bool
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) cronTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	c := t.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, x := range c.timers {
		if x == t {
			c.timers = append(c.timers[:i], c.timers[i+1:]...)
			return true
		}
	}
	return false
}

// Advance moves the clock and fires the timers that are due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var keep []*fakeTimer
	for _, t := range c.timers {
		if !t.at.After(c.now) {
			t.ch <- c.now
		} else {
			keep = append(keep, t)
		}
	}
	c.timers = keep
	c.mu.Unlock()
}

func (c *fakeClock) sleepers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// settle waits until the scheduler loop sleeps again.
func (c *fakeClock) settle(t testing.TB) {
	t.Helper()
	waitFor(t, func() bool { return c.sleepers() == 1 })
}

var clockStart = time.Date(2026, 11, 4, 10, 0, 30, 0, time.UTC)

func cronManager(t testing.TB, clock *fakeClock) *Manager {
	t.Helper()
	m := NewManager(ManagerOptions{})
	m.cronClock = clock
	m.StartSchedule()
	t.Cleanup(m.Close)
	return m
}

func cronCfg(tag, expr, src string) Config {
	return Config{Tag: tag, Type: PhaseCron, Cron: expr, Source: src}
}

func statusOf(m *Manager, tag string) Status {
	for _, st := range m.Current().Status() {
		if st.Tag == tag {
			return st
		}
	}
	return Status{}
}

func waitRuns(t testing.TB, m *Manager, tag string, n uint64) {
	t.Helper()
	waitFor(t, func() bool { return statusOf(m, tag).Runs >= n })
}

func TestCronSchedulerFires(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	var mu sync.Mutex
	var results []*Result
	m.OnRun = func(res *Result) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}
	logger := &testLogger{}
	m.SetLogger(logger)
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `console.log('tick ' + $script.type); $done({n: 1})`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	st := statusOf(m, "c")
	if st.Cron != "* * * * *" || st.Type != PhaseCron || !st.NextRun.Equal(time.Date(2026, 11, 4, 10, 1, 0, 0, time.UTC)) {
		t.Fatalf("%+v", st)
	}
	clock.Advance(20 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if statusOf(m, "c").Runs != 0 {
		t.Fatal("ran before its minute")
	}
	// Within a second after the minute starts the run has begun.
	clock.Advance(10*time.Second + time.Second)
	waitRuns(t, m, "c", 1)
	clock.settle(t)
	st = statusOf(m, "c")
	if st.Runs != 1 || st.Errors != 0 || !st.NextRun.Equal(time.Date(2026, 11, 4, 10, 2, 0, 0, time.UTC)) {
		t.Fatalf("%+v", st)
	}
	logger.mu.Lock()
	if len(logger.entries) != 1 || logger.entries[0].Message != "tick cron" || logger.entries[0].Phase != PhaseCron {
		t.Fatalf("%+v", logger.entries)
	}
	logger.mu.Unlock()
	mu.Lock()
	if len(results) != 1 || results[0].Tag != "c" || results[0].Action != ActionNone || results[0].Output != `{"n":1}` {
		t.Fatalf("%+v", results)
	}
	mu.Unlock()
	clock.Advance(time.Minute)
	waitRuns(t, m, "c", 2)
	clock.settle(t)
}

func TestCronSchedulerNotifiesLikeOtherScripts(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	notifier := &testNotifier{}
	m.SetNotifier(notifier)
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `$notification.post('t', 's', 'b'); $done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	clock.Advance(31 * time.Second)
	waitRuns(t, m, "c", 1)
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if len(notifier.n) != 1 || notifier.n[0].Script != "c" || notifier.n[0].Title != "t" {
		t.Fatalf("%+v", notifier.n)
	}
}

func TestCronSchedulerNoCatchUp(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	// The machine slept for ten minutes: the missed ticks are dropped.
	clock.Advance(10 * time.Minute)
	waitFor(t, func() bool { return statusOf(m, "c").NextRun.Equal(time.Date(2026, 11, 4, 10, 11, 0, 0, time.UTC)) })
	clock.settle(t)
	time.Sleep(50 * time.Millisecond)
	if st := statusOf(m, "c"); st.Runs != 0 {
		t.Fatalf("caught up: %+v", st)
	}
	// A tick that is a few seconds late still runs, once.
	clock.Advance(40 * time.Second)
	waitRuns(t, m, "c", 1)
	clock.settle(t)
	time.Sleep(50 * time.Millisecond)
	if st := statusOf(m, "c"); st.Runs != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestCronSchedulerSkipsWhileBusy(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	release := make(chan struct{})
	m.SetHTTPClient(&fakeHTTP{handler: func(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return &HTTPResponse{Status: 200}, nil
	}})
	var mu sync.Mutex
	var results []*Result
	m.OnRun = func(res *Result) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `$httpClient.get('https://a.example/', function () { $done() })`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	clock.Advance(31 * time.Second)
	clock.settle(t)
	waitFor(t, func() bool { return m.Current().Lookup("c").state.running.Load() })
	clock.Advance(time.Minute)
	waitFor(t, func() bool { return statusOf(m, "c").Skipped == 1 })
	clock.settle(t)
	// A manual run while the scheduled one is going is skipped as well.
	res, err := m.RunGeneric(context.Background(), "c", "")
	if err != nil || res.Action != ActionSkipped || res.Reason != SkipBusy {
		t.Fatalf("%+v %v", res, err)
	}
	mu.Lock()
	if len(results) != 1 || results[0].Action != ActionSkipped || results[0].Reason != SkipBusy {
		t.Fatalf("%+v", results)
	}
	mu.Unlock()
	close(release)
	waitFor(t, func() bool { return !m.Current().Lookup("c").state.running.Load() })
	// Only the original run counts; the busy skips add to Skipped alone.
	if st := statusOf(m, "c"); st.Runs != 1 || st.Skipped != 2 {
		t.Fatalf("%+v", st)
	}
	// And the next tick runs again.
	clock.settle(t)
	clock.Advance(time.Minute)
	waitFor(t, func() bool { return statusOf(m, "c").Runs >= 2 })
	if st := statusOf(m, "c"); st.Skipped != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestCronManualRunKeepsSchedule(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	if err := m.Apply([]Config{cronCfg("c", "*/10 * * * *", `$done({manual: $argument})`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	next := statusOf(m, "c").NextRun
	if !next.Equal(time.Date(2026, 11, 4, 10, 10, 0, 0, time.UTC)) {
		t.Fatal(next)
	}
	res, err := m.RunGeneric(context.Background(), "c", "hi")
	if err != nil || res.Action != ActionNone || res.Output != `{"manual":"hi"}` {
		t.Fatalf("%+v %v", res, err)
	}
	if st := statusOf(m, "c"); st.Runs != 1 || !st.NextRun.Equal(next) {
		t.Fatalf("%+v", st)
	}
	// The scheduled tick still happens.
	clock.Advance(9*time.Minute + 31*time.Second)
	waitRuns(t, m, "c", 2)
}

func TestCronSwapRebuildsSchedule(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	if err := m.Apply([]Config{cronCfg("a", "*/10 * * * *", `$done()`), cronCfg("gone", "* * * * *", `$done()`), genericCfg("g", `$done()`, 0)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	oldGone := m.Current().Lookup("gone")
	at := func(h, mi int) time.Time { return time.Date(2026, 11, 4, h, mi, 0, 0, time.UTC) }
	if !statusOf(m, "a").NextRun.Equal(at(10, 10)) || !statusOf(m, "gone").NextRun.Equal(at(10, 1)) || !statusOf(m, "g").NextRun.IsZero() {
		t.Fatalf("%+v", m.Current().Status())
	}
	// An unchanged script keeps its history and its next tick; a new one is scheduled from
	// now; a removed one loses its tick.
	clock.Advance(31 * time.Second)
	waitFor(t, func() bool { return statusOf(m, "gone").Runs >= 1 })
	clock.settle(t)
	if err := m.Apply([]Config{cronCfg("a", "*/10 * * * *", `$done()`), cronCfg("b", "0 12 * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	if st := statusOf(m, "a"); !st.NextRun.Equal(at(10, 10)) {
		t.Fatalf("%+v", st)
	}
	if st := statusOf(m, "b"); !st.NextRun.Equal(at(12, 0)) {
		t.Fatalf("%+v", st)
	}
	if statusOf(m, "gone").Tag != "" {
		t.Fatal("removed script still listed")
	}
	oldGone.state.mu.Lock()
	cleared := oldGone.state.nextRun.IsZero()
	oldGone.state.mu.Unlock()
	if !cleared {
		t.Fatal("removed script keeps a next tick")
	}
	// A changed schedule is rescheduled from now.
	if err := m.Apply([]Config{cronCfg("a", "0 * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	if st := statusOf(m, "a"); st.Cron != "0 * * * *" || !st.NextRun.Equal(at(11, 0)) {
		t.Fatalf("%+v", st)
	}
	// A disabled script is not scheduled.
	off := cronCfg("a", "0 * * * *", `$done()`)
	off.Disabled = true
	if err := m.Apply([]Config{off}); err != nil {
		t.Fatal(err)
	}
	if m.sched != nil {
		t.Fatal("scheduler still runs without cron scripts")
	}
	// Scripts of another type only: no scheduler either.
	if err := m.Apply([]Config{genericCfg("g", `$done()`, 0)}); err != nil {
		t.Fatal(err)
	}
	if m.sched != nil {
		t.Fatal("scheduler still runs without cron scripts")
	}
	// Back again.
	if err := m.Apply([]Config{cronCfg("a", "0 * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	if st := statusOf(m, "a"); !st.NextRun.Equal(at(11, 0)) {
		t.Fatalf("%+v", st)
	}
}

func TestCronSwapKeepsRunningHistory(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	cfg := cronCfg("a", "* * * * *", `$done()`)
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	clock.Advance(31 * time.Second)
	waitRuns(t, m, "a", 1)
	clock.settle(t)
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	if st := statusOf(m, "a"); st.Runs != 1 || !st.NextRun.Equal(time.Date(2026, 11, 4, 10, 2, 0, 0, time.UTC)) {
		t.Fatalf("%+v", st)
	}
}

func TestCronCloseStopsScheduler(t *testing.T) {
	base := runtime.NumGoroutine()
	clock := newFakeClock(clockStart)
	m := NewManager(ManagerOptions{})
	m.cronClock = clock
	m.StartSchedule()
	m.SetHTTPClient(&fakeHTTP{handler: block})
	var mu sync.Mutex
	var results []*Result
	m.OnRun = func(res *Result) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}
	if err := m.Apply([]Config{
		cronCfg("fast", "* * * * *", `$done()`),
		cronCfg("slow", "* * * * *", `$httpClient.get('https://a.example/', function () { $done() })`),
	}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	clock.Advance(31 * time.Second)
	waitRuns(t, m, "fast", 1)
	waitFor(t, func() bool { return m.Current().Lookup("slow").state.running.Load() })
	old := m.Current()
	m.Close()
	// The run in flight is canceled, the scheduler goroutine is gone.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range results {
			if r.Tag == "slow" && r.Action == ActionSkipped && r.Reason == ReasonCanceled {
				return true
			}
		}
		return false
	})
	waitFor(t, func() bool { return !old.Lookup("slow").state.running.Load() })
	if clock.sleepers() != 0 {
		t.Fatal("scheduler timer still armed")
	}
	clock.Advance(10 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if st := statusOf(m, "fast"); st.Tag != "" {
		t.Fatalf("%+v", st)
	}
	if !old.Lookup("fast").state.nextRunZero() {
		t.Fatal("next run kept after Close")
	}
	waitGoroutines(t, base)
	// After Close the set can still be swapped, but no scheduler starts.
	if err := m.Apply([]Config{cronCfg("fast", "* * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	if m.Current().Lookup("fast") == nil || m.sched != nil {
		t.Fatal("scheduler restarted after Close")
	}
	clock.Advance(10 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if clock.sleepers() != 0 || statusOf(m, "fast").Runs != 0 {
		t.Fatal("ran after Close")
	}
	m.Close()
	waitGoroutines(t, base)
}

func (st *scriptState) nextRunZero() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.nextRun.IsZero()
}

func TestCronSchedulerPaused(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	var mu sync.Mutex
	var results []*Result
	m.OnRun = func(res *Result) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	st := m.Current().Lookup("c").state
	st.mu.Lock()
	st.pausedUntil = time.Now().Add(time.Hour)
	st.mu.Unlock()
	clock.Advance(31 * time.Second)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(results) == 1
	})
	if results[0].Action != ActionPaused {
		t.Fatalf("%+v", results[0])
	}
	if got := statusOf(m, "c"); got.Runs != 0 || got.Skipped != 1 || !got.Paused {
		t.Fatalf("%+v", got)
	}
}

func TestCronFailureAccounting(t *testing.T) {
	clock := newFakeClock(clockStart)
	m := cronManager(t, clock)
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `throw new Error('bad')`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	clock.Advance(31 * time.Second)
	waitRuns(t, m, "c", 1)
	if st := statusOf(m, "c"); st.Errors != 1 || st.LastError == "" {
		t.Fatalf("%+v", st)
	}
}

func TestCronTimeZoneIsTheLocationOfTheClock(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip(err)
	}
	clock := newFakeClock(time.Date(2026, 3, 8, 1, 50, 0, 0, ny))
	m := cronManager(t, clock)
	if err := m.Apply([]Config{cronCfg("c", "30 2 * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	// 02:30 does not exist on 2026-03-08 in New York: the next tick is the day after.
	want := time.Date(2026, 3, 9, 2, 30, 0, 0, ny)
	if st := statusOf(m, "c"); !st.NextRun.Equal(want) {
		t.Fatalf("%+v want %s", st, want)
	}
}

func TestCronEvaluateAndRunGeneric(t *testing.T) {
	m := newTestManager(t)
	res, err := m.Evaluate(context.Background(), Config{Type: PhaseCron, Source: `$done({type: $script.type})`}, nil, nil)
	if err != nil || res.Action != ActionNone || res.Output != `{"type":"cron"}` {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = m.Evaluate(context.Background(), Config{Type: PhaseCron, Cron: "not a cron", Source: `$done({})`}, nil, nil)
	if err != nil || res.Action != ActionNone {
		t.Fatalf("%+v %v", res, err)
	}
	if err := m.Apply([]Config{cronCfg("c", "@daily", `$done({t: $script.type})`), httpConfig("h", PhaseRequest, `$done()`)}); err != nil {
		t.Fatal(err)
	}
	res, err = m.RunGeneric(context.Background(), "c", "")
	if err != nil || res.Output != `{"t":"cron"}` {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := m.RunGeneric(context.Background(), "h", ""); err == nil {
		t.Fatal("http script ran as generic")
	}
}

func TestCronValidateConfig(t *testing.T) {
	bad := map[string]Config{
		"no cron":       {Tag: "a", Type: PhaseCron, Source: "1"},
		"blank":         {Tag: "a", Type: PhaseCron, Cron: "  ", Source: "1"},
		"bad cron":      {Tag: "a", Type: PhaseCron, Cron: "* * * *", Source: "1"},
		"pattern":       {Tag: "a", Type: PhaseCron, Cron: "* * * * *", Pattern: ".*", Source: "1"},
		"long timeout":  {Tag: "a", Type: PhaseCron, Cron: "* * * * *", Source: "1", Timeout: 61 * time.Second},
		"cron on http":  {Tag: "a", Type: PhaseRequest, Pattern: ".*", Cron: "* * * * *", Source: "1"},
		"cron on gener": {Tag: "a", Type: PhaseGeneric, Cron: "* * * * *", Source: "1"},
	}
	for name, cfg := range bad {
		if _, err := compileSet([]Config{cfg}, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	set, err := compileSet([]Config{{Tag: "a", Type: PhaseCron, Cron: "@hourly", Source: "1", Timeout: time.Minute}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.HasHTTP() || len(set.request) != 0 || len(set.resp) != 0 || set.AppliesToPlain() || set.Len() != 1 {
		t.Fatalf("%+v", set)
	}
	if got := set.Lookup("a").Config().Timeout; got != time.Minute {
		t.Fatal(got)
	}
	set, err = compileSet([]Config{{Tag: "a", Type: PhaseCron, Cron: "@hourly", Source: "1"}}, nil)
	if err != nil || set.Lookup("a").Config().Timeout != DefaultGenericTimeout {
		t.Fatalf("%v", err)
	}
}

func TestCronJitterBelowOneSecond(t *testing.T) {
	for _, tag := range []string{"a", "b", "daily-report", "x.y_z-1", ""} {
		if j := cronJitterOf(tag); j < 0 || j >= time.Second {
			t.Errorf("%q: %s", tag, j)
		}
	}
}

// Set moves the clock to t (also backwards) and fires every timer, as a wall-clock step
// followed by the loop's own wake-up would.
func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	timers := c.timers
	c.timers = nil
	c.mu.Unlock()
	for _, tm := range timers {
		tm.ch <- t
	}
}

func TestCronSchedulerWallClockRewind(t *testing.T) {
	// Times without a monotonic reading, as the real clock yields once it is stripped.
	clock := newFakeClock(time.Unix(clockStart.Unix(), 0).UTC())
	m := cronManager(t, clock)
	if err := m.Apply([]Config{cronCfg("c", "0 * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	clock.settle(t)
	if st := statusOf(m, "c"); !st.NextRun.Equal(time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", st)
	}
	// The clock is set back by three hours: the schedule is recomputed from the new time.
	back := time.Date(2026, 11, 4, 7, 20, 0, 0, time.UTC)
	clock.Set(back)
	waitFor(t, func() bool { return statusOf(m, "c").NextRun.Equal(time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)) })
	clock.settle(t)
	if statusOf(m, "c").Runs != 0 {
		t.Fatal("ran after a rewind")
	}
}

func TestCronLoopStripsMonotonicReading(t *testing.T) {
	now := time.Now()
	if now.Round(0) == now {
		t.Skip("no monotonic reading")
	}
	if !now.Round(0).Before(now.Add(time.Hour).Round(0)) {
		t.Fatal("stripped times do not compare by wall clock")
	}
}

func TestCronNotScheduledBeforeStart(t *testing.T) {
	base := runtime.NumGoroutine()
	clock := newFakeClock(clockStart)
	m := NewManager(ManagerOptions{})
	m.cronClock = clock
	if err := m.Apply([]Config{cronCfg("c", "* * * * *", `$done()`)}); err != nil {
		t.Fatal(err)
	}
	if m.sched != nil || clock.sleepers() != 0 || !statusOf(m, "c").NextRun.IsZero() {
		t.Fatal("scheduled before StartSchedule")
	}
	clock.Advance(5 * time.Minute)
	time.Sleep(30 * time.Millisecond)
	if statusOf(m, "c").Runs != 0 {
		t.Fatal("ran before StartSchedule")
	}
	waitGoroutines(t, base)
	m.StartSchedule()
	clock.settle(t)
	if st := statusOf(m, "c"); st.NextRun.IsZero() {
		t.Fatalf("%+v", st)
	}
	clock.Advance(time.Minute)
	waitRuns(t, m, "c", 1)
	// A Close before Start leaves nothing running either.
	m2 := NewManager(ManagerOptions{})
	m2.cronClock = clock
	_ = m2.Apply([]Config{cronCfg("c", "* * * * *", `$done()`)})
	m2.Close()
	m2.StartSchedule()
	if m2.sched != nil {
		t.Fatal("scheduler started after Close")
	}
	m.Close()
	waitGoroutines(t, base)
}
