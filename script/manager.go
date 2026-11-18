package script

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"regexp/syntax"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sync/semaphore"
)

// Script is one compiled script.
type Script struct {
	cfg     Config
	re      *regexp.Regexp
	program *goja.Program
	pool    *pool
	hash    string
	state   *scriptState
	// cron is the parsed schedule of a cron script.
	cron *CronSchedule
}

// Tag returns the script's tag.
func (s *Script) Tag() string { return s.cfg.Tag }

// Config returns the script's configuration.
func (s *Script) Config() Config { return s.cfg }

// Phase returns the script type.
func (s *Script) Phase() Phase { return s.cfg.Type }

// RequiresBody reports whether the script needs the message body.
func (s *Script) RequiresBody() bool { return s.cfg.RequiresBody }

// MaxSize returns the body size above which the script does not get the body.
func (s *Script) MaxSize() int64 { return s.cfg.MaxSize }

// scriptState is the run history of a script. It survives a reload that leaves the script
// unchanged.
type scriptState struct {
	mu          sync.Mutex
	failures    []time.Time
	pausedUntil time.Time
	runs        uint64
	errors      uint64
	timeouts    uint64
	limits      uint64
	skipped     uint64
	lastError   string
	lastRun     time.Time
	lastDur     time.Duration
	notifyAt    time.Time
	notified    int
	nextRun     time.Time
	// ruleFails counts consecutive failed rule or dns runs; ruleBlocked is when the breaker
	// of rulescript.go lets the script run again.
	ruleFails   int
	ruleBlocked time.Time
	// ruleSlow counts consecutive successful runs that took more than half of the script's
	// timeout; RuleSlowFailures of them trip the same breaker (a script that answers just
	// inside its limit delays every query as much as one that times out).
	ruleSlow int
	// liveCharge is the allocation charge of the calls of this script that are running.
	liveCharge atomic.Int64
	// storeAt and storeWrites are the window of allowStoreWrite.
	storeAt     time.Time
	storeWrites int
	// running is set while a cron script runs, so that a tick or a manual run does not overlap.
	running atomic.Bool
}

// allowNotification applies the per-script rate limit of notifications.
func (st *scriptState) allowNotification(now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if now.Sub(st.notifyAt) > time.Minute {
		st.notifyAt, st.notified = now, 0
	}
	if st.notified >= maxNotifyRate {
		return false
	}
	st.notified++
	return true
}

// MaxStoreWritesPerMinute is the most $persistentStore writes (and removals) one script may
// make per minute: every write of the persistent store is a synchronous, fsynced database
// commit, which a loop must not turn into a stream of disk flushes.
const MaxStoreWritesPerMinute = 600

// allowStoreWrite applies the per-script rate limit of store writes.
func (st *scriptState) allowStoreWrite(now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if now.Sub(st.storeAt) > time.Minute {
		st.storeAt, st.storeWrites = now, 0
	}
	if st.storeWrites >= MaxStoreWritesPerMinute {
		return false
	}
	st.storeWrites++
	return true
}

// Status is the run history of a script.
type Status struct {
	Tag         string
	Type        Phase
	Runs        uint64
	Errors      uint64
	Timeouts    uint64
	Limits      uint64
	Skipped     uint64
	Paused      bool
	PausedUntil time.Time
	LastError   string
	LastRun     time.Time
	LastRunTime time.Duration
	IdleVMs     int
	// Cron is the schedule of a cron script and NextRun its next tick (zero when the
	// scheduler is not running or the expression never fires); both are empty for other types.
	Cron    string
	NextRun time.Time
}

// Set is the compiled set of scripts; it is immutable apart from run history.
type Set struct {
	plain   bool
	scripts []*Script
	byTag   map[string]*Script
	request []*Script
	resp    []*Script
}

// Empty reports whether the set has no script.
func (s *Set) Empty() bool { return s == nil || len(s.scripts) == 0 }

// Len returns the number of enabled scripts.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.scripts)
}

// AppliesToPlain reports whether some http script can match an http:// URL.
func (s *Set) AppliesToPlain() bool { return s != nil && s.plain }

// HasHTTP reports whether any http-request or http-response script exists.
func (s *Set) HasHTTP() bool {
	return s != nil && (len(s.request) > 0 || len(s.resp) > 0)
}

// Lookup returns the script with tag.
func (s *Set) Lookup(tag string) *Script {
	if s == nil {
		return nil
	}
	return s.byTag[tag]
}

// Scripts returns all scripts in configuration order.
func (s *Set) Scripts() []*Script {
	if s == nil {
		return nil
	}
	return s.scripts
}

// Match returns the scripts of phase whose pattern matches url, in configuration order.
func (s *Set) Match(phase Phase, url string) []*Script {
	if s == nil {
		return nil
	}
	list := s.request
	if phase == PhaseResponse {
		list = s.resp
	}
	var out []*Script
	for _, sc := range list {
		if sc.re.MatchString(url) {
			out = append(out, sc)
		}
	}
	return out
}

// Close drops the idle VMs of the set. Calls in flight finish normally.
func (s *Set) Close() {
	if s == nil {
		return
	}
	for _, sc := range s.scripts {
		sc.pool.close()
	}
}

// Status returns the run history of every script.
func (s *Set) Status() []Status {
	if s == nil {
		return nil
	}
	out := make([]Status, 0, len(s.scripts))
	now := time.Now()
	for _, sc := range s.scripts {
		st := sc.state
		st.mu.Lock()
		item := Status{
			Tag: sc.cfg.Tag, Type: sc.cfg.Type, Runs: st.runs, Errors: st.errors, Timeouts: st.timeouts,
			Limits: st.limits, Skipped: st.skipped, Paused: now.Before(st.pausedUntil), PausedUntil: st.pausedUntil,
			LastError: st.lastError, LastRun: st.lastRun, LastRunTime: st.lastDur,
		}
		if sc.cfg.Type == PhaseCron {
			item.Cron, item.NextRun = sc.cfg.Cron, st.nextRun
		}
		st.mu.Unlock()
		item.IdleVMs = sc.pool.idleCount()
		out = append(out, item)
	}
	return out
}

// ManagerOptions configure a Manager.
type ManagerOptions struct {
	Store    Store
	Notifier Notifier
	Logger   Logger
	// Slots is the most scripts running at once (default 2 x GOMAXPROCS).
	Slots int
}

// Manager owns the current script set, the host interfaces and the concurrency bound.
type Manager struct {
	current atomic.Pointer[Set]
	mu      sync.Mutex // serializes Compile+Swap
	slots   chan struct{}
	memory  *MemoryStore

	storeV    atomic.Pointer[storeBox]
	notifierV atomic.Pointer[notifierBox]
	loggerV   atomic.Pointer[loggerBox]
	httpV     atomic.Pointer[httpBox]

	// OnPause, when set, is called once when a script is auto-paused.
	OnPause func(tag string, until time.Time)
	// OnRun, when set, is called with the result of every scheduled cron run (including
	// skipped and paused ones), from the goroutine of the run.
	OnRun func(res *Result)

	schedMu   sync.Mutex
	sched     *scheduler
	closed    bool      // set by Close; the scheduler does not restart
	started   bool      // set by StartSchedule; cron scripts do not run before
	cronClock cronClock // tests
	httpSlots chan struct{}
	// httpMemory is the response-byte budget of the in-flight $httpClient requests.
	httpMemory *semaphore.Weighted
	// liveCharge is the allocation charge of all running calls.
	liveCharge atomic.Int64

	// Rule and dns scripts: own slots, the cache of outcomes, and a context that ends with
	// Close, so that no run outlives the manager.
	ruleSlots  chan struct{}
	ruleCache  *ruleCache
	life       context.Context
	lifeCancel context.CancelFunc
	clock      func() time.Time // tests
}

type (
	storeBox    struct{ Store }
	notifierBox struct{ Notifier }
	loggerBox   struct{ Logger }
	httpBox     struct{ HTTPClient }
)

// NewManager creates a manager with an empty set. A missing Store becomes an in-memory one.
func NewManager(opts ManagerOptions) *Manager {
	n := opts.Slots
	if n <= 0 {
		n = 2 * runtime.GOMAXPROCS(0)
	}
	m := &Manager{slots: make(chan struct{}, n), memory: NewMemoryStore(), httpSlots: make(chan struct{}, MaxHTTPConcurrent), httpMemory: semaphore.NewWeighted(MaxHTTPMemory)}
	m.ruleSlots = make(chan struct{}, n)
	m.ruleCache = newRuleCache()
	m.life, m.lifeCancel = context.WithCancel(context.Background())
	m.current.Store(&Set{byTag: map[string]*Script{}})
	m.SetStore(opts.Store)
	m.SetNotifier(opts.Notifier)
	m.SetLogger(opts.Logger)
	return m
}

// SetStore replaces the persistent store; nil selects the in-memory one.
func (m *Manager) SetStore(s Store) {
	if s == nil {
		m.storeV.Store(nil)
		return
	}
	m.storeV.Store(&storeBox{s})
}

// SetNotifier replaces the notification sink.
func (m *Manager) SetNotifier(n Notifier) {
	if n == nil {
		m.notifierV.Store(nil)
		return
	}
	m.notifierV.Store(&notifierBox{n})
}

// SetLogger replaces the console log sink.
func (m *Manager) SetLogger(l Logger) {
	if l == nil {
		m.loggerV.Store(nil)
		return
	}
	m.loggerV.Store(&loggerBox{l})
}

// SetHTTPClient attaches the host's $httpClient implementation; nil makes $httpClient fail
// with "not available".
func (m *Manager) SetHTTPClient(c HTTPClient) {
	if c == nil {
		m.httpV.Store(nil)
		return
	}
	m.httpV.Store(&httpBox{c})
}

func (m *Manager) httpClient() HTTPClient {
	if b := m.httpV.Load(); b != nil {
		return b.HTTPClient
	}
	return nil
}

func (m *Manager) store() Store {
	if b := m.storeV.Load(); b != nil {
		return b.Store
	}
	return m.memory
}

func (m *Manager) notifier() Notifier {
	if b := m.notifierV.Load(); b != nil {
		return b.Notifier
	}
	return nil
}

func (m *Manager) logger() Logger {
	if b := m.loggerV.Load(); b != nil {
		return b.Logger
	}
	return nil
}

// Current returns the active set; never nil.
func (m *Manager) Current() *Set { return m.current.Load() }

// Compile validates and compiles configs against the current set (whose run history carries
// over to unchanged scripts). It has no effect until Swap.
func (m *Manager) Compile(configs []Config) (*Set, error) {
	return compileSet(configs, m.current.Load())
}

// Swap makes set the active set and returns the previous one, whose idle VMs are released.
// Calls in flight finish on the set they started with.
func (m *Manager) Swap(set *Set) *Set {
	closing := set == nil
	if closing {
		set = &Set{byTag: map[string]*Script{}}
	}
	old := m.current.Swap(set)
	if old != set {
		old.Close()
	}
	m.syncSchedule(set, closing)
	return old
}

// Apply compiles and swaps in one step.
func (m *Manager) Apply(configs []Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, err := m.Compile(configs)
	if err != nil {
		return err
	}
	m.Swap(set)
	return nil
}

// Close releases the active set.
func (m *Manager) Close() {
	m.schedMu.Lock()
	m.closed = true
	m.schedMu.Unlock()
	m.lifeCancel()
	m.ruleCache.clear()
	m.Swap(nil)
}

func compileSet(configs []Config, previous *Set) (*Set, error) {
	set := &Set{byTag: map[string]*Script{}}
	for _, cfg := range configs {
		if cfg.Disabled {
			continue
		}
		if err := validateConfig(&cfg); err != nil {
			return nil, E.Cause(err, "script ", cfg.Tag)
		}
		if _, dup := set.byTag[cfg.Tag]; dup {
			return nil, E.New("script ", cfg.Tag, ": duplicate tag")
		}
		sc := &Script{cfg: cfg, pool: &pool{}}
		if cfg.Type == PhaseRequest || cfg.Type == PhaseResponse {
			re, err := regexp.Compile(cfg.Pattern)
			if err != nil {
				return nil, E.Cause(err, "script ", cfg.Tag, ": invalid pattern")
			}
			sc.re = re
			if !anchoredHTTPS(re, cfg.Pattern) {
				set.plain = true
			}
		}
		name := cfg.SourceName
		if name == "" {
			name = cfg.Tag + ".js"
		}
		program, err := compileProgram(name, wrapSource(cfg.Type, cfg.Source))
		if err != nil {
			return nil, E.Cause(err, "script ", cfg.Tag, ": compile")
		}
		sc.program = program
		if cfg.Type == PhaseCron {
			if sc.cron, err = ParseCron(cfg.Cron); err != nil {
				return nil, E.Cause(err, "script ", cfg.Tag, ": invalid cron")
			}
		}
		sum := sha256.Sum256([]byte(strings.Join([]string{
			cfg.Source, cfg.Argument, cfg.Pattern, string(cfg.Type), strconv.FormatBool(cfg.RequiresBody),
			strconv.FormatBool(cfg.BinaryBody), strconv.FormatInt(cfg.MaxSize, 10), cfg.Timeout.String(), cfg.Cron,
		}, "\x00")))
		sc.hash = hex.EncodeToString(sum[:8])
		sc.state = &scriptState{}
		if previous != nil {
			if old := previous.byTag[cfg.Tag]; old != nil && old.hash == sc.hash {
				sc.state = old.state
			}
		}
		set.scripts = append(set.scripts, sc)
		set.byTag[cfg.Tag] = sc
		switch cfg.Type {
		case PhaseRequest:
			set.request = append(set.request, sc)
		case PhaseResponse:
			set.resp = append(set.resp, sc)
		}
	}
	return set, nil
}

// wrapSource puts the script in a function scope on a single line, so that line numbers in
// errors match the file, top-level let/const can be declared again in the next call, and
// "return" works at the top level.
func wrapSource(phase Phase, src string) string {
	if phase == PhaseRule || phase == PhaseDNS {
		return "(function($request,$response,$argument,$script,$domain){" + src + "\n})"
	}
	return "(function($request,$response,$argument,$script){" + src + "\n})"
}

// Run executes an http-request or http-response script. It never fails: every outcome is a
// Result, and a failed script leaves the message to the caller unchanged.
func (m *Manager) Run(ctx context.Context, sc *Script, in *Input) *Result {
	return m.runWith(ctx, sc, in, runOptions{})
}

// runWith is Run with execution options.
func (m *Manager) runWith(ctx context.Context, sc *Script, in *Input, opts runOptions) *Result {
	st := sc.state
	now := time.Now()
	st.mu.Lock()
	paused := now.Before(st.pausedUntil)
	if paused {
		st.skipped++
	}
	st.mu.Unlock()
	if paused {
		return &Result{Tag: sc.cfg.Tag, Phase: sc.cfg.Type, Action: ActionPaused, Reason: "paused", Error: "paused after repeated failures"}
	}
	res := m.execute(ctx, sc, in, opts)
	m.record(sc, res)
	return res
}

// RunGeneric executes a generic or cron script by tag (argument overrides the configured one
// when not empty). A manual run of a cron script does not move its schedule; it is skipped
// with reason busy while a scheduled or manual run of it is still going.
func (m *Manager) RunGeneric(ctx context.Context, tag string, argument string) (*Result, error) {
	sc := m.current.Load().Lookup(tag)
	if sc == nil {
		return nil, E.New("unknown script: ", tag)
	}
	if sc.cfg.Type != PhaseGeneric && sc.cfg.Type != PhaseCron {
		return nil, E.New("script ", tag, " is not a generic script")
	}
	if argument != "" {
		clone := *sc
		clone.cfg.Argument = argument
		sc = &clone
	}
	if sc.cfg.Type == PhaseCron {
		return m.runExclusive(ctx, sc), nil
	}
	res := m.execute(ctx, sc, nil, runOptions{})
	m.record(sc, res)
	return res, nil
}

// Evaluate compiles and runs cfg once without touching the active set, its pools, its
// history or the persistent store: $persistentStore uses store (a fresh in-memory one when
// nil) and notifications are returned in the result.
func (m *Manager) Evaluate(ctx context.Context, cfg Config, in *Input, store Store) (*Result, error) {
	cfg.Disabled = false
	if cfg.Tag == "" {
		cfg.Tag = "eval"
	}
	if cfg.Type == "" {
		cfg.Type = PhaseGeneric
	}
	if cfg.Type == PhaseRequest || cfg.Type == PhaseResponse {
		if cfg.Pattern == "" {
			cfg.Pattern = ".*"
		}
	}
	if cfg.Type == PhaseCron {
		// A dry run needs no schedule; a placeholder keeps the config valid.
		cfg.Pattern = ""
		if ValidCron(cfg.Cron) != nil {
			cfg.Cron = "* * * * *"
		}
	}
	set, err := compileSet([]Config{cfg}, nil)
	if err != nil {
		return nil, err
	}
	defer set.Close()
	if store == nil {
		store = NewMemoryStore()
	}
	if in == nil {
		in = &Input{}
	}
	if cfg.Type == PhaseRequest && in.Request == nil {
		in.Request = &Request{}
	}
	if cfg.Type == PhaseResponse {
		if in.Request == nil {
			in.Request = &Request{}
		}
		if in.Response == nil {
			in.Response = &Response{Status: 200}
		}
	}
	return m.execute(ctx, set.scripts[0], in, runOptions{dry: true, store: store}), nil
}

func (m *Manager) record(sc *Script, res *Result) {
	st := sc.state
	now := time.Now()
	st.mu.Lock()
	st.runs++
	st.lastRun, st.lastDur = now, res.Duration
	failed := false
	switch res.Action {
	case ActionError:
		st.errors++
		failed = true
	case ActionTimeout:
		st.timeouts++
		failed = true
	case ActionLimit:
		st.limits++
		failed = true
	case ActionSkipped:
		st.skipped++
	}
	var pausedUntil time.Time
	if failed {
		st.lastError = res.Error
		cut := now.Add(-PauseWindow)
		kept := st.failures[:0]
		for _, t := range st.failures {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		st.failures = append(kept, now)
		if len(st.failures) > PauseFailures {
			st.pausedUntil = now.Add(PauseDuration)
			st.failures = nil
			pausedUntil = st.pausedUntil
		}
	}
	st.mu.Unlock()
	if !pausedUntil.IsZero() {
		if l := m.logger(); l != nil {
			l.Log(LogEntry{Script: sc.cfg.Tag, Phase: sc.cfg.Type, LogLine: LogLine{Level: "error", Message: "paused for 5 minutes after repeated failures", Time: now}})
		}
		if m.OnPause != nil {
			m.OnPause(sc.cfg.Tag, pausedUntil)
		}
	}
}

// anchoredHTTPS reports whether every match of re starts with "https://" at the beginning
// of the URL.
func anchoredHTTPS(re *regexp.Regexp, pattern string) bool {
	prefix, _ := re.LiteralPrefix()
	if !strings.HasPrefix(prefix, "https://") {
		return false
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return false
	}
	return prog.StartCond()&syntax.EmptyBeginText != 0
}

// CompileTimeout bounds how long compiling one script may take. CheckSource keeps known slow
// shapes out; this bounds the rest. A compile that overruns is abandoned (its goroutine ends
// when goja returns) and the script is refused.
var CompileTimeout = 5 * time.Second

// compileSlots bounds the compiles running at once, abandoned ones included, so that sources
// built to compile slowly cannot pile up goroutines that each burn a core. While the slots
// are taken a new compile waits CompileBusyWait and is then refused.
var (
	compileSlots    = make(chan struct{}, 2)
	CompileBusyWait = 2 * time.Second
)

// compileDirect is the size under which a source compiles inline: even a worst-case chain
// of that size takes well under a second.
const compileDirect = 8 << 10

func compileProgram(name, src string) (*goja.Program, error) {
	if len(src) < compileDirect {
		return goja.Compile(name, src, false)
	}
	wait := time.NewTimer(CompileBusyWait)
	select {
	case compileSlots <- struct{}{}:
		wait.Stop()
	case <-wait.C:
		return nil, E.New("script compiler is busy")
	}
	type result struct {
		program *goja.Program
		err     error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-compileSlots }()
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: E.New("compile panic: ", r)}
			}
		}()
		p, err := goja.Compile(name, src, false)
		done <- result{p, err}
	}()
	timer := time.NewTimer(CompileTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.program, r.err
	case <-timer.C:
		return nil, E.New("compile took longer than ", CompileTimeout)
	}
}

// Store returns the store scripts use: the attached one, or the in-memory fallback.
func (m *Manager) Store() Store { return m.store() }
