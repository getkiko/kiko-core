package body

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestCollectComplete(t *testing.T) {
	res := Collect(strings.NewReader("hello"), 100, time.Second, nil)
	if !res.Complete || string(res.Data) != "hello" || res.Rest != nil || res.Err != nil {
		t.Fatalf("%+v", res)
	}
}

func TestCollectEmpty(t *testing.T) {
	res := Collect(strings.NewReader(""), 100, time.Second, nil)
	if !res.Complete || len(res.Data) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestCollectExactLimitIsComplete(t *testing.T) {
	res := Collect(strings.NewReader(strings.Repeat("a", 64)), 64, time.Second, nil)
	if !res.Complete {
		t.Fatalf("%+v", res)
	}
}

func TestCollectSizeReplaysEverything(t *testing.T) {
	payload := strings.Repeat("abcdefgh", 20000)
	res := Collect(strings.NewReader(payload), 1000, time.Second, nil)
	if res.Complete || res.Reason != CollectSize || res.Rest == nil {
		t.Fatalf("%+v", res)
	}
	got, err := io.ReadAll(res.Rest)
	if err != nil || string(got) != payload {
		t.Fatalf("replayed %d bytes, %v", len(got), err)
	}
}

func TestCollectErrorKeepsError(t *testing.T) {
	boom := errors.New("boom")
	res := Collect(io.MultiReader(strings.NewReader("ab"), errReader{boom}), 100, time.Second, nil)
	if res.Complete || res.Err != boom || string(res.Data) != "ab" {
		t.Fatalf("%+v", res)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestCollectTimeoutDeliversPendingRead(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("first"))
		time.Sleep(300 * time.Millisecond)
		pw.Write([]byte("second"))
		pw.Close()
	}()
	res := Collect(pr, 1000, 80*time.Millisecond, nil)
	if res.Complete || res.Reason != CollectTimeout || res.Rest == nil || string(res.Data) != "first" {
		t.Fatalf("%+v", res)
	}
	got, err := io.ReadAll(res.Rest)
	if err != nil || string(got) != "firstsecond" {
		t.Fatalf("replayed %q, %v", got, err)
	}
}

func TestCollectTimeoutPendingError(t *testing.T) {
	pr, pw := io.Pipe()
	boom := errors.New("boom")
	go func() {
		time.Sleep(200 * time.Millisecond)
		pw.CloseWithError(boom)
	}()
	res := Collect(pr, 1000, 50*time.Millisecond, nil)
	if res.Reason != CollectTimeout {
		t.Fatalf("%+v", res)
	}
	var out bytes.Buffer
	_, err := io.Copy(&out, res.Rest)
	if err != boom {
		t.Fatalf("got %v", err)
	}
}

func TestBudget(t *testing.T) {
	b := NewBudget(10)
	if !b.Acquire(6) || b.Acquire(5) || !b.Acquire(4) {
		t.Fatal("acquire")
	}
	b.Release(6)
	if !b.Acquire(5) || b.Used() != 9 {
		t.Fatalf("used %d", b.Used())
	}
}

func TestCollectBusyReplaysEverything(t *testing.T) {
	payload := strings.Repeat("abcdefgh", 10000)
	taken := 0
	res := Collect(strings.NewReader(payload), 1<<20, time.Second, func(n int) bool {
		taken += n
		return taken <= 40000
	})
	if res.Complete || res.Reason != CollectBusy || res.Rest == nil {
		t.Fatalf("%+v", res)
	}
	got, err := io.ReadAll(res.Rest)
	if err != nil || string(got) != payload {
		t.Fatalf("replayed %d bytes, %v", len(got), err)
	}
}
