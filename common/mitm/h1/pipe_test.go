package h1

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingWriter records each Write; the first one blocks until release is closed.
type recordingWriter struct {
	mu      sync.Mutex
	writes  []string
	entered chan struct{} // closed when the first Write starts
	release chan struct{}
	err     error
	once    sync.Once
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	if w.entered != nil {
		w.once.Do(func() { close(w.entered) })
	}
	if w.release != nil {
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, string(p))
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func (w *recordingWriter) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.writes...)
}

// pieces is a source returning one piece per Read, each after its gate (if any) opens.
type pieces struct {
	parts []string
	gates []chan struct{}
	i     int
}

func (p *pieces) Read(b []byte) (int, error) {
	if p.i == len(p.parts) {
		return 0, io.EOF
	}
	if p.i < len(p.gates) && p.gates[p.i] != nil {
		<-p.gates[p.i]
	}
	n := copy(b, p.parts[p.i])
	p.i++
	return n, nil
}

// Reads that complete while a write is in progress go out together in the next write.
func TestPipeCoalesces(t *testing.T) {
	var p bodyPipe
	defer p.close()
	w := &recordingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	src := &pieces{parts: []string{"a", "b", "c", "d"}, gates: []chan struct{}{nil, w.entered}}
	go func() {
		<-w.entered
		time.Sleep(50 * time.Millisecond)
		close(w.release)
	}()
	n, err := p.copy(w, src, -1, false)
	if err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if got := strings.Join(w.snapshot(), "|"); got != "a|bcd" {
		t.Fatalf("writes %q", got)
	}
}

// Data read before the source pauses is written at once.
func TestPipeNoAddedLatency(t *testing.T) {
	var p bodyPipe
	defer p.close()
	w := &recordingWriter{}
	gate := make(chan struct{})
	src := &pieces{parts: []string{"first", "second"}, gates: []chan struct{}{nil, gate}}
	done := make(chan struct{})
	go func() {
		p.copy(w, src, -1, false)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(w.snapshot()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first piece not written while the source paused")
		}
		time.Sleep(time.Millisecond)
	}
	if got := w.snapshot(); len(got) != 1 || got[0] != "first" {
		t.Fatalf("writes %q", got)
	}
	close(gate)
	<-done
	if got := strings.Join(w.snapshot(), "|"); got != "first|second" {
		t.Fatalf("writes %q", got)
	}
}

// Each read becomes one chunk; large bodies cross both buffers several times intact.
func TestPipeChunkedAndLarge(t *testing.T) {
	var p bodyPipe
	defer p.close()
	var out bytes.Buffer
	n, err := p.copy(&out, &pieces{parts: []string{"abc", strings.Repeat("x", 300)}}, -1, true)
	if err != nil || n != 303 {
		t.Fatal(n, err)
	}
	if out.String() != "3\r\nabc\r\n12c\r\n"+strings.Repeat("x", 300)+"\r\n" {
		t.Fatalf("%q", out.String())
	}

	body := make([]byte, 5*pipeBufferSize+123)
	for i := range body {
		body[i] = byte(i * 7)
	}
	for _, chunked := range []bool{false, true} {
		out.Reset()
		src := bufio.NewReaderSize(bytes.NewReader(append(body, "rest"...)), 1000)
		n, err = p.copy(&out, src, int64(len(body)), chunked)
		if err != nil || n != int64(len(body)) {
			t.Fatal(n, err)
		}
		got := out.Bytes()
		if chunked {
			got, err = io.ReadAll(newChunkedBody(bufio.NewReader(io.MultiReader(&out, strings.NewReader("0\r\n\r\n")))))
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("chunked %v: %d bytes differ", chunked, len(got))
		}
		if rest, _ := io.ReadAll(src); string(rest) != "rest" {
			t.Fatalf("limit not respected: rest %q", rest)
		}
	}
}

// A write error ends the copy, and the pipe works again for the next body.
func TestPipeWriteError(t *testing.T) {
	var p bodyPipe
	defer p.close()
	failure := errors.New("broken")
	w := &recordingWriter{err: failure}
	_, err := p.copy(w, strings.NewReader(strings.Repeat("y", 3*pipeBufferSize)), -1, false)
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if n, err := p.copy(&out, strings.NewReader("next"), -1, false); err != nil || n != 4 || out.String() != "next" {
		t.Fatal(n, err, out.String())
	}
}
