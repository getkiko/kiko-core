package body

import (
	"io"
	"sync/atomic"
	"time"
)

// Collection outcomes besides completion.
const (
	// CollectSize: the body is longer than the limit.
	CollectSize = "size"
	// CollectTimeout: the body did not end within the time limit.
	CollectTimeout = "timeout"
	// CollectBusy: grow refused more memory.
	CollectBusy = "busy"
)

const collectChunk = 32 << 10

// CollectResult is the outcome of Collect.
type CollectResult struct {
	// Data is everything read when Complete; otherwise the bytes read so far.
	Data []byte
	// Complete reports that the source ended within the limits.
	Complete bool
	// Reason is CollectSize or CollectTimeout when the source did not end in time.
	Reason string
	// Err is a read error of the source other than io.EOF (Data holds what came before it).
	Err error
	// Rest, set when the source is neither complete nor failed, yields the bytes of Data
	// followed by the remainder of the source, so that it can be forwarded as if nothing
	// had been read. The source must not be used otherwise any more.
	Rest io.Reader
}

type collected struct {
	n   int
	err error
}

// Collect reads src into memory until it ends, holds more than limit bytes or timeout passed.
// A read that is in flight when the time runs out is not abandoned: its result is delivered
// first by Rest. The source is read on a helper goroutine that never outlives the call except
// for such a pending read.
//
// grow, when not nil, is asked for every chunk read (before it is kept); returning false
// stops the collection with CollectBusy.
func Collect(src io.Reader, limit int64, timeout time.Duration, grow func(n int) bool) CollectResult {
	scratch := make([]byte, collectChunk)
	results := make(chan collected, 1)
	next := make(chan struct{})
	quit := make(chan struct{})
	go func() {
		for {
			n, err := src.Read(scratch)
			results <- collected{n, err}
			if err != nil {
				return
			}
			select {
			case <-next:
			case <-quit:
				return
			}
		}
	}()
	var timer <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timer = t.C
	}
	var data []byte
	for {
		select {
		case c := <-results:
			if c.n > 0 && grow != nil && !grow(c.n) {
				close(quit)
				data = append(data, scratch[:c.n]...)
				return CollectResult{Data: data, Reason: CollectBusy, Rest: &Replay{data: data, src: src, pending: pendingError(c.err)}}
			}
			data = append(data, scratch[:c.n]...)
			if c.err != nil {
				close(quit)
				if c.err == io.EOF {
					if int64(len(data)) > limit {
						return CollectResult{Data: data, Reason: CollectSize, Rest: &Replay{data: data, src: src}}
					}
					return CollectResult{Data: data, Complete: true}
				}
				return CollectResult{Data: data, Err: c.err}
			}
			if int64(len(data)) > limit {
				close(quit)
				return CollectResult{Data: data, Reason: CollectSize, Rest: &Replay{data: data, src: src}}
			}
			next <- struct{}{}
		case <-timer:
			close(quit)
			return CollectResult{Data: data, Reason: CollectTimeout, Rest: &Replay{data: data, src: src, pending: results, scratch: scratch}}
		}
	}
}

// Replay yields buffered bytes, then the result of a read that was still in flight, then the
// rest of its source.
type Replay struct {
	data    []byte
	pending chan collected
	scratch []byte
	hold    []byte // bytes of the pending read not yet delivered
	err     error  // sticky error of the pending read
	src     io.Reader
}

func (r *Replay) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	if r.pending != nil {
		c := <-r.pending
		r.pending = nil
		r.hold = r.scratch[:c.n]
		r.err = c.err
	}
	if len(r.hold) > 0 {
		n := copy(p, r.hold)
		r.hold = r.hold[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	return r.src.Read(p)
}

// Budget bounds the memory held by messages buffered at the same time.
type Budget struct {
	used  atomic.Int64
	limit int64
}

// NewBudget returns a Budget of limit bytes.
func NewBudget(limit int64) *Budget { return &Budget{limit: limit} }

// Acquire takes n bytes and reports whether they were available.
func (b *Budget) Acquire(n int64) bool {
	for {
		used := b.used.Load()
		if used+n > b.limit {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

// Release returns n bytes taken by Acquire.
func (b *Budget) Release(n int64) { b.used.Add(-n) }

// Used is the number of bytes currently taken.
func (b *Budget) Used() int64 { return b.used.Load() }

// BufferingLimit is the process-wide budget of messages buffered for body rules: room for two
// messages of the largest max_body_size (32 MiB), each costing three copies.
const BufferingLimit = 192 << 20

// Buffering is the process-wide budget of messages buffered for body rules.
var Buffering = NewBudget(BufferingLimit)

// pendingError returns a channel holding the (already delivered) read error, or nil.
func pendingError(err error) chan collected {
	if err == nil {
		return nil
	}
	c := make(chan collected, 1)
	c <- collected{err: err}
	return c
}
