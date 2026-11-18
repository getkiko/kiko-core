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
	// Reason is why the body rules did not run (one of the Skip* constants); empty when the
	// body was collected within every limit. A body that is Complete but was too costly for
	// the budget carries SkipBusy.
	Reason  string
	Changed bool
	Data    []byte
	Replay  io.Reader
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
	return p.HoldFor(scope, contentType, encoding, src, length, streaming, maxBody, 0, reserved, before, false)
}

// HoldFor is Hold for a caller that needs the body beyond what the body rules of the plan
// select (scripts): want makes it buffer the message even when no rule does. The plan may be
// nil. maxBody bounds the buffering; ruleMax (0: the same) is the largest body the body rules
// of the plan process, so that a caller that buffers more for scripts does not enlarge the
// limit of the rules.
func (p *Plan) HoldFor(scope, contentType, encoding string, src io.Reader, length int64, streaming bool, maxBody, ruleMax int64, reserved *int64, before func(), want bool) (*Held, error) {
	if !want && !p.NeedsBody(scope, contentType) {
		return nil, nil
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBodySize
	}
	skip := func(reason string) *Held {
		return &Held{Hits: p.SkipHits(scope, contentType, reason), Reason: reason}
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
		held.Reason = SkipBusy
		return held, nil
	} else {
		taken += extra
	}
	*reserved += taken
	if ruleMax > 0 && int64(len(res.Data)) > ruleMax && p.NeedsBody(scope, contentType) {
		return &Held{Hits: p.SkipHits(scope, contentType, SkipSize), Complete: true, Data: res.Data}, nil
	}
	if ruleMax <= 0 {
		ruleMax = maxBody
	}
	result := p.ApplyBody(scope, contentType, encoding, res.Data, ruleMax)
	return &Held{Hits: result.Hits, Complete: true, Changed: result.Changed, Data: result.Data}, nil
}

// ReleaseHold returns the budget taken by Hold calls.
func ReleaseHold(reserved *int64) {
	if *reserved != 0 {
		body.Buffering.Release(*reserved)
		*reserved = 0
	}
}
