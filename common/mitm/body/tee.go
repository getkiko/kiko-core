// Package body observes message bodies for capture and decodes them for
// display. Observation never alters the forwarded bytes.
package body

import "io"

// Sink stores the leading bytes of a body. WriteBody must copy p if it keeps
// it, and returns false to stop saving.
type Sink interface {
	WriteBody(p []byte) bool
}

// Tee counts every byte that passes and hands the first Limit bytes to Sink.
// Past the limit it sets Truncated and keeps counting without copying. A Sink
// that returns false stops saving and also marks the body Truncated. Tee is
// not safe for concurrent use; one goroutine carries a body.
type Tee struct {
	// Limit is the most bytes passed to Sink. Zero or negative saves nothing.
	Limit int64
	// Sink receives data that must be copied if kept. May be nil to count only.
	Sink Sink

	total     int64
	saved     int64
	truncated bool
	stopped   bool
}

// Write observes p.
func (t *Tee) Write(p []byte) {
	n := int64(len(p))
	t.total += n
	if t.stopped || t.Sink == nil {
		if n > 0 && t.Sink != nil {
			t.truncated = true
		}
		return
	}
	room := t.Limit - t.saved
	if room <= 0 {
		if n > 0 {
			t.truncated = true
			t.stopped = true
		}
		return
	}
	chunk := p
	if n > room {
		chunk = p[:room]
		t.truncated = true
		t.stopped = true
	}
	if len(chunk) == 0 {
		return
	}
	if !t.Sink.WriteBody(chunk) {
		t.truncated = true
		t.stopped = true
		return
	}
	t.saved += int64(len(chunk))
}

// Total is every byte observed, saved or not.
func (t *Tee) Total() int64 { return t.total }

// Saved is the number of bytes handed to Sink.
func (t *Tee) Saved() int64 { return t.saved }

// Truncated reports that some bytes were not saved.
func (t *Tee) Truncated() bool { return t.truncated }

// Reader returns r observed by t.
func (t *Tee) Reader(r io.Reader) io.Reader { return &teeReader{r: r, t: t} }

// Writer returns w observed by t.
func (t *Tee) Writer(w io.Writer) io.Writer { return &teeWriter{w: w, t: t} }

type teeReader struct {
	r io.Reader
	t *Tee
}

func (r *teeReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.t.Write(p[:n])
	}
	return n, err
}

// WriteTo keeps io.Copy from bypassing the observer through an inner WriterTo.
func (r *teeReader) WriteTo(w io.Writer) (int64, error) {
	return io.CopyBuffer(w, struct{ io.Reader }{r}, make([]byte, 32<<10))
}

type teeWriter struct {
	w io.Writer
	t *Tee
}

func (w *teeWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.t.Write(p[:n])
	}
	return n, err
}

// ReadFrom keeps io.Copy from bypassing the observer through an inner ReaderFrom.
func (w *teeWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.CopyBuffer(struct{ io.Writer }{w}, r, make([]byte, 32<<10))
}
