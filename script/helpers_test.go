package script

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type testLogger struct {
	mu      sync.Mutex
	entries []LogEntry
}

func (l *testLogger) Log(e LogEntry) {
	l.mu.Lock()
	l.entries = append(l.entries, e)
	l.mu.Unlock()
}

type testNotifier struct {
	mu sync.Mutex
	n  []Notification
}

func (t *testNotifier) Notify(n Notification) {
	t.mu.Lock()
	t.n = append(t.n, n)
	t.mu.Unlock()
}

func newTestManager(t testing.TB) *Manager {
	t.Helper()
	m := NewManager(ManagerOptions{})
	t.Cleanup(m.Close)
	return m
}

func httpConfig(tag string, phase Phase, src string) Config {
	return Config{Tag: tag, Type: phase, Pattern: ".*", Source: src}
}

// runOne compiles one script into the manager and runs it.
func runOne(t testing.TB, m *Manager, cfg Config, in *Input) *Result {
	t.Helper()
	if err := m.Apply([]Config{cfg}); err != nil {
		t.Fatalf("compile %s: %v", cfg.Tag, err)
	}
	sc := m.Current().Lookup(cfg.Tag)
	if cfg.Type == PhaseGeneric {
		res, err := m.RunGeneric(context.Background(), cfg.Tag, "")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	return m.Run(context.Background(), sc, in)
}

func reqInput(url string, headers ...string) *Input {
	r := &Request{URL: url, Method: "GET", ID: "r1"}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Headers = append(r.Headers, Header{headers[i], headers[i+1]})
	}
	return &Input{Request: r}
}

func respInput(status int, body string, headers ...string) *Input {
	in := reqInput("https://example.com/x")
	in.Response = &Response{Status: status, Body: []byte(body), HasBody: true}
	for i := 0; i+1 < len(headers); i += 2 {
		in.Response.Headers = append(in.Response.Headers, Header{headers[i], headers[i+1]})
	}
	return in
}

func headerValue(h []Header, name string) string {
	var out []string
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return strings.Join(out, "|")
}

func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not finish within %s", d)
	}
}
