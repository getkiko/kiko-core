package rewrite

import (
	"io"
	"time"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/flow"
)

// BufferTimeout bounds how long a body is buffered for body rules before it is passed
// through. It is a variable so tests can shorten it.
var BufferTimeout = 5 * time.Second

// Held is the outcome of Hold.
type Held struct {
	// Hits are the records of the selected body rules (edits, or skipped with a reason).
	Hits []flow.RewriteHit
	// Complete reports that Data is the whole body as received (or rewritten, when Changed);
	// otherwise Replay, when not nil, yields the body from its first byte and Data is nil.
	Complete bool
	Changed  bool
	Data     []byte
	Replay   io.Reader
}

// Hold buffers a message body for the body rules of the plan. It returns nil when no body
// rule selects the message. src yields the body without its framing; length is the declared
// length (-1 when unknown); streaming forces the message to pass untouched. Buffering is
// bounded by maxBody, BufferTimeout and the process-wide budget (body.Buffering); the budget
// taken is added to *reserved and returned by the caller. before, when not nil, runs right
// before the first read of src.
//
// A body that is too long, too slow or beyond the budget is not an error: the result is
// not Complete and its records say why. An error means src failed.
func (p *Plan) Hold(scope, contentType, encoding string, src io.Reader, length int64, streaming bool, maxBody int64, reserved *int64, before func()) (*Held, error) {
	if !p.NeedsBody(scope, contentType) {
		return nil, nil
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBodySize
	}
	skip := func(reason string) *Held {
		return &Held{Hits: p.SkipHits(scope, contentType, reason)}
	}
	if streaming {
		return skip(SkipStream), nil
	}
	if length >= 0 && length > maxBody {
		return skip(SkipSize), nil
	}
	if before != nil {
		before()
	}
	// Budget is taken as bytes arrive (one copy while reading, two more for the decoded and
	// the rewritten form) and given back at once when the body turns into a passthrough.
	var taken int64
	grow := func(n int) bool {
		if !body.Buffering.Acquire(int64(n)) {
			return false
		}
		taken += int64(n)
		return true
	}
	res := body.Collect(src, maxBody, BufferTimeout, grow)
	if res.Err != nil {
		body.Buffering.Release(taken)
		return nil, res.Err
	}
	if !res.Complete {
		body.Buffering.Release(taken)
		reason := SkipSize
		switch res.Reason {
		case body.CollectTimeout:
			reason = SkipTimeout
		case body.CollectBusy:
			reason = SkipBusy
		}
		held := skip(reason)
		held.Replay = res.Rest
		return held, nil
	}
	if length >= 0 && int64(len(res.Data)) != length {
		body.Buffering.Release(taken)
		return nil, io.ErrUnexpectedEOF
	}
	// Two more copies (decoded, rewritten), and the slack of the append-grown buffer.
	if extra := 2*int64(len(res.Data)) + int64(cap(res.Data)-len(res.Data)); !body.Buffering.Acquire(extra) {
		body.Buffering.Release(taken)
		held := skip(SkipBusy)
		held.Complete, held.Data = true, res.Data
		return held, nil
	} else {
		taken += extra
	}
	*reserved += taken
	result := p.ApplyBody(scope, contentType, encoding, res.Data, maxBody)
	return &Held{Hits: result.Hits, Complete: true, Changed: result.Changed, Data: result.Data}, nil
}

// ReleaseHold returns the budget taken by Hold calls.
func ReleaseHold(reserved *int64) {
	if *reserved != 0 {
		body.Buffering.Release(*reserved)
		*reserved = 0
	}
}
