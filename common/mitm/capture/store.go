package capture

import (
	"bytes"
	"errors"
	"strconv"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/flow"
)

const (
	smallChunk = 4 << 10
	largeChunk = 16 << 10
)

// bodyStore is a chain of chunks holding the leading bytes of a body. The
// accounted size is the capacity of the chunks.
type bodyStore struct {
	chunks [][]byte
	stored int64
}

func (s *bodyStore) spare() int {
	if len(s.chunks) == 0 {
		return 0
	}
	last := s.chunks[len(s.chunks)-1]
	return cap(last) - len(last)
}

func (s *bodyStore) fill(p []byte) {
	i := len(s.chunks) - 1
	s.chunks[i] = append(s.chunks[i], p...)
	s.stored += int64(len(p))
}

// nextChunk sizes a new chunk for want pending bytes: the first chunk fits
// the data exactly when it is small, later chunks grow in steps.
func (s *bodyStore) nextChunk(want int) int {
	if len(s.chunks) == 0 && want <= largeChunk {
		return want
	}
	if want >= largeChunk {
		return largeChunk
	}
	return max(want, smallChunk)
}

func (s *bodyStore) addChunk(size int) {
	s.chunks = append(s.chunks, make([]byte, 0, size))
}

// shrink trims the unused tail of the last chunk when it is worth a copy and
// returns the bytes released.
func (s *bodyStore) shrink() int64 {
	if len(s.chunks) == 0 {
		return 0
	}
	last := s.chunks[len(s.chunks)-1]
	waste := cap(last) - len(last)
	if waste < 1024 {
		return 0
	}
	s.chunks[len(s.chunks)-1] = append(make([]byte, 0, len(last)), last...)
	return int64(waste)
}

// copyRange copies up to length bytes (all when length <= 0) from offset.
func (s *bodyStore) copyRange(offset, length int64) []byte {
	if offset < 0 || offset >= s.stored {
		return nil
	}
	end := s.stored
	if length > 0 && length < end-offset {
		end = offset + length
	}
	result := make([]byte, 0, end-offset)
	var position int64
	for _, chunk := range s.chunks {
		next := position + int64(len(chunk))
		if next > offset && position < end {
			from := max(offset-position, 0)
			to := min(end-position, int64(len(chunk)))
			result = append(result, chunk[from:to]...)
		}
		position = next
		if position >= end {
			break
		}
	}
	return result
}

// BodyRequest addresses a body range.
type BodyRequest struct {
	ID       string
	Instance string
	Side     flow.Side
	Offset   int64
	// Length limits the bytes returned; zero or less means up to the end.
	Length int64
	// Decoded undoes the Content-Encoding of the body.
	Decoded bool
}

// BodyResult is a part of a body.
type BodyResult struct {
	Data []byte
	// Total is the size of the addressed view: the saved bytes, or the
	// decoded size when Decoded.
	Total int64
	// Original is every byte that passed, saved or not.
	Original int64
	// Truncated means the view lacks bytes that passed.
	Truncated bool
	// Saved reports that body capture was on for the exchange.
	Saved bool
	// Complete means the body ended.
	Complete bool
	Encoding string
	// DecodeError describes why Decoded could not return everything.
	DecodeError string
}

// DecodeLimits bound decoded views.
var DecodeLimits = body.Limits{MaxOutput: 16 << 20}

// GetBody returns a part of a saved body.
func (m *Manager) GetBody(request BodyRequest) (BodyResult, error) {
	if request.Offset < 0 || request.Length < 0 {
		return BodyResult{}, ErrRange
	}
	ordinal, err := strconv.ParseUint(request.ID, 10, 64)
	if err != nil {
		return BodyResult{}, ErrNotFound
	}
	m.mu.Lock()
	if request.Instance != "" && request.Instance != m.instance {
		m.mu.Unlock()
		return BodyResult{}, ErrReset
	}
	e := m.byID[ordinal]
	if e == nil {
		m.mu.Unlock()
		return BodyResult{}, ErrNotFound
	}
	store, saved, truncated, original, encoding := &e.req, e.rec.RequestBodySaved, e.rec.RequestBodyTruncated, e.rec.RequestBytes, e.rec.RequestEncoding
	complete := !e.rec.Timing.RequestBody.IsZero()
	if request.Side == flow.Response {
		store, saved, truncated, original, encoding = &e.resp, e.rec.ResponseBodySaved, e.rec.ResponseBodyTruncated, e.rec.ResponseBytes, e.rec.ResponseEncoding
		complete = !e.rec.Timing.ResponseBody.IsZero()
	}
	result := BodyResult{Saved: saved, Truncated: truncated, Original: original, Encoding: encoding, Complete: complete}
	if !request.Decoded || len(body.ParseEncodings(encoding)) == 0 {
		result.Total = store.stored
		result.Data = store.copyRange(request.Offset, request.Length)
		if !complete {
			result.Original = max(original, store.stored)
		}
		m.mu.Unlock()
		return result, nil
	}
	raw := store.copyRange(0, 0)
	m.mu.Unlock()
	decoded, decodeErr := body.Decode(encoding, bytes.NewReader(raw), DecodeLimits)
	if decodeErr != nil {
		var typed *body.Error
		if errors.As(decodeErr, &typed) && typed.Kind == body.ErrUnsupported {
			// Show the saved bytes as they are.
			decoded = raw
		} else if errors.As(decodeErr, &typed) && typed.Kind == body.ErrCorrupt && truncated {
			// A cut-off stream ends abruptly; the partial result is expected.
			decodeErr = nil
		}
		if decodeErr != nil {
			result.DecodeError = decodeErr.Error()
		}
		if typed != nil && (typed.Kind == body.ErrOutputLimit || typed.Kind == body.ErrBomb) {
			result.Truncated = true
		}
	}
	result.Total = int64(len(decoded))
	if request.Offset < 0 || request.Offset >= int64(len(decoded)) {
		decoded = nil
	} else {
		decoded = decoded[request.Offset:]
		if request.Length > 0 && request.Length < int64(len(decoded)) {
			decoded = decoded[:request.Length]
		}
	}
	result.Data = decoded
	return result, nil
}
