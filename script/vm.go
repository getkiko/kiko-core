package script

import (
	"container/heap"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/dop251/goja"
)

func init() {
	// goja runs every RegExp on regexp2, a backtracking engine. A pattern like (a+)+b must not
	// hold a worker for longer than this; the match then throws a RangeError in the script.
	regexp2.DefaultMatchTimeout = 1500 * time.Millisecond
}

// Interrupt reasons.
type interruptReason string

const (
	reasonTimeout interruptReason = "timeout"
	reasonLimit   interruptReason = "limit"
	reasonCancel  interruptReason = "canceled"
)

const (
	maxTimers      = 1000
	maxTimerDelay  = 10 * time.Minute
	maxVMUses      = 500
	sampleInterval = 25 * time.Millisecond
	// volumeLimit is the emergency threshold of the allocation backstop: the bytes the whole
	// process allocates while one call executes (see vmEntry.check). Single large allocations
	// are charged exactly and never rely on it.
	volumeLimit = 8 * AllocationLimit
)

var (
	preludeProgram *goja.Program
	preludeOnce    sync.Once
)

func prelude() *goja.Program {
	preludeOnce.Do(func() {
		p, err := goja.Compile("prelude", preludeSource, false)
		if err != nil {
			panic("script prelude: " + err.Error())
		}
		preludeProgram = p
	})
	return preludeProgram
}

type timerItem struct {
	id       int
	due      time.Time
	seq      int
	fn       goja.Callable
	args     []goja.Value
	interval time.Duration
	removed  bool
}

type timerHeap []*timerItem

func (h timerHeap) Len() int { return len(h) }
func (h timerHeap) Less(i, j int) bool {
	if h[i].due.Equal(h[j].due) {
		return h[i].seq < h[j].seq
	}
	return h[i].due.Before(h[j].due)
}
func (h timerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *timerHeap) Push(x any)   { *h = append(*h, x.(*timerItem)) }
func (h *timerHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// callState is the state of one script call.
type callState struct {
	m      *Manager
	sc     *Script
	cfg    *Config
	dry    bool
	store  Store
	res    *Result
	phase  Phase
	in     *Input
	start  time.Time
	logger Logger

	mu       sync.Mutex
	finished bool
	reason   interruptReason
	stop     chan struct{}
	active   bool
	// ctx is the context of the call; http is the $httpClient state (nil until the first call).
	ctx      context.Context
	http     *httpState
	deadline time.Time
	base     uint64
	sampler  *time.Timer

	done     bool
	logs     []LogLine
	logBytes int
	timers   timerHeap
	byID     map[int]*timerItem
	nextID   int
	seq      int
	charged  int64
	shared   int64 // part of charged counted in the live totals
	notified int
	notifyAt time.Time
	inputStr string // text form of the body handed to the script
}

func (cs *callState) interrupt(rt *goja.Runtime, reason interruptReason) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.finished || cs.reason != "" {
		return
	}
	cs.reason = reason
	close(cs.stop)
	rt.Interrupt(string(reason))
}

func (cs *callState) interrupted() interruptReason {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.reason
}

func (cs *callState) finish() {
	cs.mu.Lock()
	cs.finished = true
	if cs.sampler != nil {
		cs.sampler.Stop()
	}
	cs.mu.Unlock()
}

// armSampler starts the periodic allocation check of the call.
func (cs *callState) armSampler(e *vmEntry) {
	var tick func()
	tick = func() {
		e.check(cs)
		cs.mu.Lock()
		if !cs.finished {
			cs.sampler = time.AfterFunc(sampleInterval, tick)
		}
		cs.mu.Unlock()
	}
	cs.mu.Lock()
	cs.sampler = time.AfterFunc(sampleInterval, tick)
	cs.mu.Unlock()
}

// charge accounts n bytes of a large allocation. It returns false once the call is over
// its allowance.
func (cs *callState) charge(n int64) bool {
	if n <= 0 {
		return true
	}
	cs.charged += n
	if cs.charged > AllocationLimit {
		return false
	}
	return cs.chargeShared(n)
}

// chargeShared adds n to the live charge of the script (all its concurrent calls) and of the
// manager (all scripts). The totals are released when the call ends. A call that pushes
// either total over its limit fails, so one script that runs many calls at once is stopped
// by its own limit before it can take the memory of the others.
func (cs *callState) chargeShared(n int64) bool {
	if cs.sc == nil || cs.sc.state == nil || cs.m == nil {
		return true
	}
	cs.shared += n
	script := cs.sc.state.liveCharge.Add(n)
	total := cs.m.liveCharge.Add(n)
	return script <= ScriptAllocationLimit && total <= GlobalAllocationLimit
}

// releaseShared gives the call's share of the live charges back.
func (cs *callState) releaseShared() {
	if cs.shared == 0 || cs.sc == nil || cs.sc.state == nil || cs.m == nil {
		return
	}
	cs.sc.state.liveCharge.Add(-cs.shared)
	cs.m.liveCharge.Add(-cs.shared)
	cs.shared = 0
}

// vmEntry is one runtime of a script's pool.
type vmEntry struct {
	rt          *goja.Runtime
	cs          *callState
	api         map[string]goja.Value
	baseline    map[string]struct{}
	getNames    goja.Callable
	fingerprint goja.Callable
	stringify   goja.Callable
	uses        int
	idleAt      time.Time
	timer       *time.Timer
}

var allocSample = sync.Pool{New: func() any {
	return &[]metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
}}

func heapAllocs() uint64 {
	p := allocSample.Get().(*[]metrics.Sample)
	metrics.Read(*p)
	var v uint64
	if (*p)[0].Value.Kind() == metrics.KindUint64 {
		v = (*p)[0].Value.Uint64()
	}
	allocSample.Put(p)
	return v
}

// setActive marks whether the VM is executing (as opposed to waiting for a timer); the
// allocation backstop counts only the executing stretches.
func (cs *callState) setActive(active bool) {
	cs.mu.Lock()
	cs.active = active
	if active {
		cs.base = heapAllocs()
	}
	cs.mu.Unlock()
}

// check is the allocation backstop: the explicit charges catch single large allocations;
// this catches growth that goes through no hook (array push, object churn, rope flattening).
func (e *vmEntry) check(cs *callState) {
	cs.mu.Lock()
	over := cs.active && !cs.finished && heapAllocs()-cs.base > volumeLimit
	cs.mu.Unlock()
	if over {
		cs.interrupt(e.rt, reasonLimit)
	}
}

func newEntry(m *Manager, sc *Script) (*vmEntry, error) {
	rt := goja.New()
	rt.SetMaxCallStackSize(CallStackLimit)
	e := &vmEntry{rt: rt, api: map[string]goja.Value{}}
	global := rt.GlobalObject()
	natives := rt.NewObject()
	setNative := func(name string, fn func(goja.FunctionCall) goja.Value) {
		_ = natives.Set(name, fn)
	}
	setNative("log", func(call goja.FunctionCall) goja.Value {
		e.log(call.Argument(0).String(), call.Argument(1).String())
		return goja.Undefined()
	})
	setNative("encode", func(call goja.FunctionCall) goja.Value {
		b := []byte(call.Argument(0).String())
		if cs := e.cs; cs != nil && !cs.charge(int64(len(b))) {
			e.overLimit()
		}
		return e.newUint8Array(b)
	})
	setNative("decode", func(call goja.FunctionCall) goja.Value {
		b, ok := bytesOf(call.Argument(0))
		if !ok {
			panic(rt.NewTypeError("TextDecoder.decode needs an ArrayBuffer or a typed array"))
		}
		return rt.ToValue(strings.ToValidUTF8(string(b), "�"))
	})
	setNative("atob", func(call goja.FunctionCall) goja.Value {
		s := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' {
				return -1
			}
			return r
		}, call.Argument(0).String())
		s = strings.TrimRight(s, "=")
		b, err := base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			panic(rt.NewTypeError("The string to be decoded is not correctly encoded."))
		}
		out := make([]rune, len(b))
		for i, c := range b {
			out[i] = rune(c)
		}
		return rt.ToValue(string(out))
	})
	setNative("btoa", func(call goja.FunctionCall) goja.Value {
		in := call.Argument(0).String()
		b := make([]byte, 0, len(in))
		for _, r := range in {
			if r > 255 {
				panic(rt.NewTypeError("The string to be encoded contains characters outside of the Latin1 range."))
			}
			b = append(b, byte(r))
		}
		return rt.ToValue(base64.StdEncoding.EncodeToString(b))
	})
	timer := func(repeat bool) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			cs := e.cs
			fn, ok := goja.AssertFunction(call.Argument(0))
			if !ok {
				panic(rt.NewTypeError("callback must be a function"))
			}
			if cs == nil || len(cs.byID) >= maxTimers {
				panic(rt.NewTypeError("too many timers"))
			}
			delay := time.Duration(call.Argument(1).ToInteger()) * time.Millisecond
			if delay < 0 {
				delay = 0
			}
			if delay > maxTimerDelay {
				delay = maxTimerDelay
			}
			item := &timerItem{fn: fn, due: time.Now().Add(delay)}
			if repeat {
				item.interval = max(delay, time.Millisecond)
			}
			if len(call.Arguments) > 2 {
				item.args = append(item.args, call.Arguments[2:]...)
			}
			cs.nextID++
			cs.seq++
			item.id, item.seq = cs.nextID, cs.seq
			cs.byID[item.id] = item
			heap.Push(&cs.timers, item)
			return rt.ToValue(item.id)
		}
	}
	setNative("setTimeout", timer(false))
	setNative("setInterval", timer(true))
	clear := func(call goja.FunctionCall) goja.Value {
		if cs := e.cs; cs != nil {
			if item := cs.byID[int(call.Argument(0).ToInteger())]; item != nil {
				item.removed = true
				delete(cs.byID, item.id)
			}
		}
		return goja.Undefined()
	}
	setNative("clearTimeout", clear)
	setNative("clearInterval", clear)
	_ = natives.Set("maxArray", MaxArrayLength)
	setNative("checkSource", func(call goja.FunctionCall) goja.Value {
		if err := CheckSource(call.Argument(0).String(), EvalLimits); err != nil {
			panic(rt.NewTypeError(err.Error()))
		}
		return goja.Undefined()
	})
	// limit wraps a constructor of memory-backed objects so that the requested size is charged
	// before the allocation happens.
	setNative("limit", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		orig := call.Argument(1).ToObject(rt)
		construct, _ := goja.AssertConstructor(orig)
		elem := elementSize(name)
		return rt.ToValue(func(c goja.ConstructorCall) *goja.Object {
			if name == "Array" {
				if len(c.Arguments) == 1 {
					if _, isObj := c.Argument(0).(*goja.Object); !isObj {
						if n := c.Argument(0).ToInteger(); n > MaxArrayLength {
							e.overLimit()
						}
					}
				}
			} else if cs := e.cs; cs != nil && len(c.Arguments) > 0 {
				if first := c.Argument(0); first != nil && !goja.IsUndefined(first) {
					if _, isObj := first.(*goja.Object); !isObj {
						n := first.ToInteger()
						if n > 0 && (n > AllocationLimit || !cs.charge(n*elem)) {
							e.overLimit()
						}
					} else if length := first.ToObject(rt).Get("length"); length != nil && !goja.IsUndefined(length) {
						if n := length.ToInteger(); n > 0 && !cs.charge(n*elem) {
							e.overLimit()
						}
					}
				}
			}
			obj, err := construct(c.NewTarget, c.Arguments...)
			if err != nil {
				var ex *goja.Exception
				if errors.As(err, &ex) {
					panic(ex.Value())
				}
				panic(err)
			}
			return obj
		})
	})
	e.installHTTPNatives(setNative)
	e.installUtilsNatives(setNative)
	pre, err := rt.RunProgram(prelude())
	if err != nil {
		return nil, err
	}
	call, ok := goja.AssertFunction(pre)
	if !ok {
		return nil, errors.New("script prelude is not a function")
	}
	names, err := call(goja.Undefined(), natives, global)
	if err != nil {
		return nil, err
	}
	e.getNames, ok = goja.AssertFunction(names)
	if !ok {
		return nil, errors.New("script prelude: no name lister")
	}
	e.installStringLimits()
	e.installAPI(m, sc)
	e.baseline = map[string]struct{}{}
	e.eachGlobalName(func(name string) { e.baseline[name] = struct{}{} })
	for _, name := range []string{"console", "TextEncoder", "TextDecoder", "atob", "btoa", "setTimeout", "clearTimeout", "setInterval", "clearInterval", "setImmediate", "$httpClient", "$utils", "$persistentStore", "$notification", "$environment", "$done", "ArrayBuffer", "Uint8Array", "JSON", "Math", "Date", "Promise", "Object", "Array", "String", "RegExp", "Error"} {
		if v := global.Get(name); v != nil {
			e.api[name] = v
		}
	}
	if st, ok := goja.AssertFunction(rt.Get("JSON").ToObject(rt).Get("stringify")); ok {
		e.stringify = st
	} else {
		return nil, errors.New("JSON.stringify is missing")
	}
	fp, err := rt.RunProgram(fingerprintProgram())
	if err != nil {
		return nil, err
	}
	build, ok := goja.AssertFunction(fp)
	if !ok {
		return nil, errors.New("script fingerprint is not a function")
	}
	check, err := build(goja.Undefined(), global)
	if err != nil {
		return nil, err
	}
	if e.fingerprint, ok = goja.AssertFunction(check); !ok {
		return nil, errors.New("script fingerprint check is not a function")
	}
	return e, nil
}

var (
	fingerprintProg *goja.Program
	fingerprintOnce sync.Once
)

func fingerprintProgram() *goja.Program {
	fingerprintOnce.Do(func() {
		p, err := goja.Compile("fingerprint", fingerprintSource, false)
		if err != nil {
			panic("script fingerprint: " + err.Error())
		}
		fingerprintProg = p
	})
	return fingerprintProg
}

// intact reports whether the last call left the built-ins and the global object as they
// were; a VM that fails the check is not reused.
func (e *vmEntry) intact() bool {
	ok, err := e.fingerprint(goja.Undefined())
	return err == nil && ok.ToBoolean()
}

func elementSize(name string) int64 {
	switch name {
	case "Int16Array", "Uint16Array":
		return 2
	case "Int32Array", "Uint32Array", "Float32Array":
		return 4
	case "Float64Array":
		return 8
	case "Array":
		return 16
	}
	return 1
}

func (e *vmEntry) overLimit() {
	if cs := e.cs; cs != nil {
		cs.interrupt(e.rt, reasonLimit)
	}
	panic(e.rt.NewTypeError("allocation limit exceeded"))
}

// installStringLimits makes the string builders that can produce huge results charge the
// call before they run.
func (e *vmEntry) installStringLimits() {
	rt := e.rt
	proto := rt.Get("String").ToObject(rt).Get("prototype").ToObject(rt)
	wrap := func(name string, size func(this goja.Value, args []goja.Value) int64) {
		orig, ok := goja.AssertFunction(proto.Get(name))
		if !ok {
			return
		}
		_ = proto.Set(name, func(call goja.FunctionCall) goja.Value {
			if cs := e.cs; cs != nil {
				if n := size(call.This, call.Arguments); n > 0 && (n > AllocationLimit || !cs.charge(n)) {
					e.overLimit()
				}
			}
			v, err := orig(call.This, call.Arguments...)
			if err != nil {
				e.rethrow(err)
			}
			return v
		})
	}
	wrap("repeat", func(this goja.Value, args []goja.Value) int64 {
		if len(args) == 0 {
			return 0
		}
		n := args[0].ToInteger()
		if n <= 0 {
			return 0
		}
		length := int64(len(this.String()))
		if length > 0 && n > (AllocationLimit*2)/length {
			return AllocationLimit + 1
		}
		return length * n
	})
	pad := func(this goja.Value, args []goja.Value) int64 {
		if len(args) == 0 {
			return 0
		}
		return args[0].ToInteger()
	}
	wrap("padStart", pad)
	wrap("padEnd", pad)
	// split and replace can multiply their input; the expected size is checked against the
	// allowance before they run and the real size is charged after.
	wrapResult := func(name string, estimate func(this goja.Value, args []goja.Value) int64) {
		orig, ok := goja.AssertFunction(proto.Get(name))
		if !ok {
			return
		}
		_ = proto.Set(name, func(call goja.FunctionCall) goja.Value {
			cs := e.cs
			if cs != nil {
				if n := estimate(call.This, call.Arguments); n > AllocationLimit {
					e.overLimit()
				}
			}
			v, err := orig(call.This, call.Arguments...)
			if err != nil {
				e.rethrow(err)
			}
			if cs != nil {
				if obj, isObj := v.(*goja.Object); isObj {
					if n := obj.Get("length").ToInteger(); n > 0 && !cs.charge(n*16) {
						e.overLimit()
					}
				} else if s, isString := v.Export().(string); isString && !cs.charge(int64(len(s))) {
					e.overLimit()
				}
			}
			return v
		})
	}
	wrapResult("split", func(this goja.Value, args []goja.Value) int64 {
		length := int64(len(this.String()))
		if len(args) > 0 {
			if sep, ok := plainString(args[0]); ok && sep != "" {
				return (int64(strings.Count(this.String(), sep)) + 1) * 16
			}
		}
		return length * 16
	})
	replace := func(this goja.Value, args []goja.Value) int64 {
		if len(args) < 2 {
			return 0
		}
		repl, ok := plainString(args[1])
		if !ok {
			return 0
		}
		return (int64(len(this.String())) + 1) * int64(len(repl))
	}
	wrapResult("replace", replace)
	wrapResult("replaceAll", replace)
	// Regular expression operations that collect every match build one object per match
	// (about 100 bytes each): on a big string they are refused, on a smaller one the expected
	// size is charged first.
	wrapRegex := func(name string, collects func(args []goja.Value) bool) {
		orig, ok := goja.AssertFunction(proto.Get(name))
		if !ok {
			return
		}
		_ = proto.Set(name, func(call goja.FunctionCall) goja.Value {
			if cs := e.cs; cs != nil && collects(call.Arguments) {
				n := int64(len(call.This.String()))
				if n > RegexInputLimit || !cs.charge(n*regexMatchCost) {
					e.overLimit()
				}
			}
			v, err := orig(call.This, call.Arguments...)
			if err != nil {
				e.rethrow(err)
			}
			return v
		})
	}
	isRegexp := func(v goja.Value) (*goja.Object, bool) {
		obj, ok := v.(*goja.Object)
		if !ok || obj.ClassName() != "RegExp" {
			return nil, false
		}
		return obj, true
	}
	globalRegexp := func(args []goja.Value) bool {
		if len(args) == 0 {
			return false
		}
		obj, ok := isRegexp(args[0])
		return ok && obj.Get("global").ToBoolean()
	}
	wrapRegex("match", globalRegexp)
	wrapRegex("matchAll", func(args []goja.Value) bool { return len(args) > 0 })
	wrapRegex("split", func(args []goja.Value) bool {
		if len(args) == 0 {
			return false
		}
		_, ok := isRegexp(args[0])
		return ok
	})
	replaceCollects := func(args []goja.Value) bool {
		if len(args) < 2 {
			return false
		}
		if _, isFn := goja.AssertFunction(args[1]); !isFn {
			return false
		}
		_, ok := isRegexp(args[0])
		return ok
	}
	wrapRegex("replace", replaceCollects)
	wrapRegex("replaceAll", replaceCollects)
	wrap("concat", func(this goja.Value, args []goja.Value) int64 {
		n := int64(len(this.String()))
		for _, a := range args {
			n += int64(len(a.String()))
		}
		return n
	})
	arrayProto := rt.Get("Array").ToObject(rt).Get("prototype").ToObject(rt)
	if fill, ok := goja.AssertFunction(arrayProto.Get("fill")); ok {
		_ = arrayProto.Set("fill", func(call goja.FunctionCall) goja.Value {
			if cs := e.cs; cs != nil {
				if obj, isObj := call.This.(*goja.Object); isObj {
					if n := obj.Get("length").ToInteger(); n > 0 && (n > AllocationLimit/16 || !cs.charge(n*16)) {
						e.overLimit()
					}
				}
			}
			v, err := fill(call.This, call.Arguments...)
			if err != nil {
				e.rethrow(err)
			}
			return v
		})
	}
	jsonObj := rt.Get("JSON").ToObject(rt)
	if parse, ok := goja.AssertFunction(jsonObj.Get("parse")); ok {
		_ = jsonObj.Set("parse", func(call goja.FunctionCall) goja.Value {
			text := call.Argument(0).String()
			if jsonDepth(text) > maxJSONDepth {
				panic(rt.NewTypeError("JSON.parse: nesting too deep"))
			}
			if cs := e.cs; cs != nil && !cs.charge(int64(len(text))*3) {
				e.overLimit()
			}
			v, err := parse(call.This, call.Arguments...)
			if err != nil {
				e.rethrow(err)
			}
			return v
		})
	}
	origJoin, ok := goja.AssertFunction(arrayProto.Get("join"))
	if ok {
		_ = arrayProto.Set("join", func(call goja.FunctionCall) goja.Value {
			if cs := e.cs; cs != nil {
				// A sparse array of huge length joined by a separator is the classic blow-up.
				if obj, isObj := call.This.(*goja.Object); isObj {
					length := obj.Get("length").ToInteger()
					sep := int64(1)
					if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) {
						sep = int64(len(call.Arguments[0].String()))
					}
					if length > 1 && sep > 0 && (length-1) > AllocationLimit/sep {
						e.overLimit()
					}
				}
			}
			v, err := origJoin(call.This, call.Arguments...)
			if err != nil {
				e.rethrow(err)
			}
			return v
		})
	}
}

// maxJSONDepth bounds the nesting JSON.parse accepts: goja parses recursively, and a body
// of a few MiB of "[" would otherwise exhaust the Go stack of the whole process.
const maxJSONDepth = 1000

func jsonDepth(text string) int {
	depth, deepest := 0, 0
	inString := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '[', '{':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case ']', '}':
			depth--
		}
	}
	return deepest
}

func (e *vmEntry) rethrow(err error) {
	var ex *goja.Exception
	if errors.As(err, &ex) {
		panic(ex.Value())
	}
	panic(err)
}

func (e *vmEntry) log(level, message string) {
	cs := e.cs
	if cs == nil {
		return
	}
	switch level {
	case "log", "info", "warn", "error":
	default:
		level = "log"
	}
	if len(cs.logs) >= maxLogLines {
		return
	}
	if len(message) > maxLogLine {
		message = message[:maxLogLine]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
		message += "..."
	}
	line := LogLine{Level: level, Message: message, Time: time.Now()}
	cs.logs = append(cs.logs, line)
	if cs.logger != nil && !cs.dry {
		cs.logger.Log(LogEntry{Script: cs.cfg.Tag, Phase: cs.cfg.Type, LogLine: line})
	}
}

func (e *vmEntry) newUint8Array(b []byte) goja.Value {
	rt := e.rt
	buf := rt.NewArrayBuffer(b)
	arr, err := rt.New(rt.Get("Uint8Array"), rt.ToValue(buf))
	if err != nil {
		panic(rt.NewTypeError("cannot create Uint8Array"))
	}
	return arr
}

var (
	byteSliceType   = reflect.TypeOf([]byte(nil))
	arrayBufferType = reflect.TypeOf(goja.ArrayBuffer{})
)

// bytesOf reads the bytes of an ArrayBuffer or a typed array.
func bytesOf(v goja.Value) ([]byte, bool) {
	if _, isObj := v.(*goja.Object); !isObj {
		return nil, false
	}
	// Only buffers are exported; Export of an array or object recurses.
	if t := v.ExportType(); t != byteSliceType && t != arrayBufferType {
		return nil, false
	}
	switch x := v.Export().(type) {
	case []byte:
		return x, true
	case goja.ArrayBuffer:
		return x.Bytes(), true
	}
	return nil, false
}

// eachGlobalName calls fn with the name of every own property of the global object. It reads
// the list through the object API: no exported copy is built.
func (e *vmEntry) eachGlobalName(fn func(name string)) {
	v, err := e.getNames(goja.Undefined())
	if err != nil {
		return
	}
	list, ok := v.(*goja.Object)
	if !ok {
		return
	}
	n := int(list.Get("length").ToInteger())
	for i := 0; i < n; i++ {
		if item, ok := list.Get(strconv.Itoa(i)).(goja.String); ok {
			fn(item.String())
		}
	}
}

// cleanup removes the globals a call defined and restores the API objects, so that one call
// cannot leave anything for the next.
func (e *vmEntry) cleanup() {
	global := e.rt.GlobalObject()
	e.eachGlobalName(func(name string) {
		if _, ok := e.baseline[name]; !ok {
			_ = global.Delete(name)
		}
	})
	for name, v := range e.api {
		if cur := global.Get(name); cur == nil || !cur.SameAs(v) {
			_ = global.Set(name, v)
		}
	}
	e.cs = nil
}

// PoolStats returns the idle VMs of a script's pool, for tests.
type pool struct {
	mu     sync.Mutex
	idle   []*vmEntry
	closed bool
	timer  *time.Timer
}

func (p *pool) get() *vmEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.idle); n > 0 {
		e := p.idle[n-1]
		p.idle = p.idle[:n-1]
		return e
	}
	return nil
}

func (p *pool) put(e *vmEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.idle) >= PoolSize {
		return
	}
	e.idleAt = time.Now()
	p.idle = append(p.idle, e)
	if p.timer == nil {
		p.timer = time.AfterFunc(PoolIdle, p.prune)
	}
}

func (p *pool) prune() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timer = nil
	if p.closed {
		return
	}
	keep := p.idle[:0]
	var next time.Duration
	for _, e := range p.idle {
		if age := time.Since(e.idleAt); age < PoolIdle {
			keep = append(keep, e)
			if d := PoolIdle - age; next == 0 || d < next {
				next = d
			}
		}
	}
	for i := len(keep); i < len(p.idle); i++ {
		p.idle[i] = nil
	}
	p.idle = keep
	if next > 0 {
		p.timer = time.AfterFunc(next, p.prune)
	}
}

func (p *pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.idle = nil
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

func (p *pool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

type runOptions struct {
	dry   bool
	store Store
	// slots and wait replace the shared concurrency bound and WaitLimit (rule and dns
	// scripts, which run on the connection path and must not queue behind http scripts).
	slots chan struct{}
	wait  time.Duration
}

// execute runs sc once. It never panics.
func (m *Manager) execute(ctx context.Context, sc *Script, in *Input, opts runOptions) (res *Result) {
	cfg := &sc.cfg
	res = &Result{Tag: cfg.Tag, Phase: cfg.Type, Action: ActionNone}
	begin := time.Now()
	defer func() {
		res.Duration = time.Since(begin)
		if r := recover(); r != nil {
			res.Action = ActionError
			res.Error = fmt.Sprint("panic: ", r)
		}
	}()
	// A slot: the process-wide bound on concurrent scripts. It is given back while the call
	// only waits for a timer.
	slots, waitLimit := m.slots, WaitLimit
	if opts.slots != nil {
		slots, waitLimit = opts.slots, opts.wait
	}
	wait := time.NewTimer(waitLimit)
	select {
	case slots <- struct{}{}:
		wait.Stop()
	case <-wait.C:
		res.Action, res.Reason = ActionSkipped, SkipBusy
		return res
	case <-ctx.Done():
		wait.Stop()
		res.Action, res.Reason = ActionSkipped, SkipBusy
		return res
	}
	holding := true
	defer func() {
		if holding {
			<-slots
		}
	}()

	e := sc.pool.get()
	if e == nil {
		var err error
		if e, err = newEntry(m, sc); err != nil {
			res.Action, res.Error = ActionError, "cannot start the script runtime: "+err.Error()
			return res
		}
	}
	cs := &callState{
		m: m, sc: sc, cfg: cfg, res: res, phase: cfg.Type, in: in, dry: opts.dry, start: begin,
		stop: make(chan struct{}), byID: map[int]*timerItem{}, logger: m.logger(), ctx: ctx,
	}
	if opts.dry {
		cs.store = opts.store
	} else {
		cs.store = m.store()
	}
	healthy := false
	e.cs = cs
	defer func() {
		cs.cancelHTTP()
		cs.finish()
		cs.releaseShared()
		e.rt.ClearInterrupt()
		e.cleanup()
		e.uses++
		if healthy && e.uses < maxVMUses && e.intact() {
			sc.pool.put(e)
		}
	}()
	args := e.callArgs(cs)
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cs.deadline = time.Now().Add(timeout)
	deadline := time.AfterFunc(timeout, func() { cs.interrupt(e.rt, reasonTimeout) })
	defer deadline.Stop()
	stopCtx := context.AfterFunc(ctx, func() { cs.interrupt(e.rt, reasonCancel) })
	defer stopCtx()
	cs.armSampler(e)
	cs.setActive(true)
	var failure *failure
	entry, err := e.rt.RunProgram(sc.program)
	if err == nil {
		if run, ok := goja.AssertFunction(entry); ok {
			_, err = run(goja.Undefined(), args...)
		} else {
			err = errors.New("script wrapper is not a function")
		}
	}
	failure = e.classify(cs, err)
	// The event loop: timers and $httpClient answers until $done, the end of the work, or the
	// deadline.
	for failure == nil && !cs.done {
		for cs.timers.Len() > 0 && cs.timers[0].removed {
			heap.Pop(&cs.timers)
		}
		cs.setActive(false)
		hs := cs.http
		var answer *httpItem
		fromHost := false
		var timer *timerItem
		if hs != nil && len(hs.ready) > 0 {
			answer = hs.ready[0]
			hs.ready[0] = nil
			hs.ready = hs.ready[1:]
		} else {
			if cs.timers.Len() > 0 {
				timer = cs.timers[0]
			}
			waiting := hs != nil && hs.pending > 0
			if timer == nil && !waiting {
				break
			}
			if waiting {
				select {
				case answer = <-hs.done:
					fromHost = true
				default:
				}
			}
			if answer == nil {
				d := time.Duration(-1)
				if timer != nil {
					d = time.Until(timer.due)
				}
				if timer == nil || d > 0 {
					<-slots
					holding = false
					var timerC <-chan time.Time
					var t *time.Timer
					if timer != nil {
						t = time.NewTimer(d)
						timerC = t.C
					}
					var doneC <-chan *httpItem
					if waiting {
						doneC = hs.done
					}
					select {
					case <-timerC:
					case answer = <-doneC:
						fromHost = answer != nil
					case <-cs.stop:
					}
					if t != nil {
						t.Stop()
					}
					select {
					case slots <- struct{}{}:
						holding = true
					case <-cs.stop:
					}
				}
			}
		}
		if r := cs.interrupted(); r != "" {
			failure = e.classify(cs, &goja.InterruptedError{})
			break
		}
		cs.setActive(true)
		if answer != nil {
			err = e.runHTTPCallback(cs, answer, fromHost)
			failure = e.classify(cs, err)
			continue
		}
		item := heap.Pop(&cs.timers).(*timerItem)
		if item.interval > 0 {
			item.due = time.Now().Add(item.interval)
			cs.seq++
			item.seq = cs.seq
			heap.Push(&cs.timers, item)
		} else {
			delete(cs.byID, item.id)
		}
		_, err = item.fn(goja.Undefined(), item.args...)
		failure = e.classify(cs, err)
	}
	cs.cancelHTTP()
	cs.setActive(false)
	if failure == nil && !cs.done {
		if r := cs.interrupted(); r != "" {
			failure = e.classify(cs, &goja.InterruptedError{})
		}
	}
	res.Logs = cs.logs
	if failure != nil && !cs.done {
		res.Action, res.Error, res.Reason = failure.action, failure.text, failure.reason
		res.URL, res.Headers, res.HeadersChanged, res.Body, res.BodyChanged, res.Status, res.Response = "", nil, false, nil, false, 0, nil
		healthy = failure.action == ActionError
		return res
	}
	healthy = true
	if cs.interrupted() != "" {
		healthy = false
	}
	return res
}

type failure struct {
	action Action
	text   string
	reason string
}

// classify turns an error from the VM into a failure; nil for no error. A failure after
// $done was called does not undo the result.
func (e *vmEntry) classify(cs *callState, err error) *failure {
	if err == nil {
		return nil
	}
	var interrupted *goja.InterruptedError
	if errors.As(err, &interrupted) {
		switch cs.interrupted() {
		case reasonLimit:
			return &failure{ActionLimit, fmt.Sprintf("allocation limit exceeded (%d MiB)", AllocationLimit>>20), ""}
		case reasonCancel:
			return &failure{ActionSkipped, "canceled", ReasonCanceled}
		default:
			return &failure{ActionTimeout, fmt.Sprintf("timed out after %s", cs.timeout()), ""}
		}
	}
	var overflow *goja.StackOverflowError
	if errors.As(err, &overflow) {
		return &failure{ActionLimit, "call stack limit exceeded", ""}
	}
	// An error that surfaces while the call is interrupted is the interrupt's doing.
	switch cs.interrupted() {
	case reasonCancel:
		return &failure{ActionSkipped, "canceled", ReasonCanceled}
	case reasonTimeout:
		return &failure{ActionTimeout, fmt.Sprintf("timed out after %s", cs.timeout()), ""}
	}
	text := err.Error()
	if len(text) > maxErrorText {
		text = text[:maxErrorText] + "..."
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	if cs.interrupted() == reasonLimit {
		return &failure{ActionLimit, fmt.Sprintf("allocation limit exceeded (%d MiB)", AllocationLimit>>20), ""}
	}
	return &failure{ActionError, text, ""}
}

func (cs *callState) timeout() time.Duration {
	if cs.cfg.Timeout > 0 {
		return cs.cfg.Timeout
	}
	return DefaultTimeout
}
