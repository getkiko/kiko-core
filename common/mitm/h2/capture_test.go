//go:build go1.26

package h2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
)

func newCapture(body bool) *capture.Manager {
	return capture.New(capture.Options{Enabled: true, Body: body})
}

func observe(m *capture.Manager) func(*Options) {
	return func(o *Options) {
		o.Observer = m.Observer()
		o.Connection = &flow.ConnectionInfo{ID: "conn-1", Host: testHost, Unverified: true}
	}
}

func waitRecords(t testing.TB, m *capture.Manager, n int) []capture.Record {
	t.Helper()
	var records []capture.Record
	eventually(t, fmt.Sprintf("%d finished records", n), func() bool {
		records = m.List(capture.Filter{}).Records
		if len(records) != n {
			return false
		}
		for _, r := range records {
			if r.State == capture.StateInProgress {
				return false
			}
		}
		return true
	})
	return records
}

func headerOf(headers []flow.Header, name string) []string {
	var out []string
	for _, h := range headers {
		if h.Name == name {
			out = append(out, h.Value)
		}
	}
	return out
}

func body(t testing.TB, m *capture.Manager, id string, side flow.Side) string {
	t.Helper()
	result, err := m.GetBody(capture.BodyRequest{ID: id, Side: side})
	if err != nil {
		t.Fatal(err)
	}
	return string(result.Data)
}

func TestCaptureSingleStream(t *testing.T) {
	m := newCapture(true)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(201)
		w.Write([]byte("echo:" + string(in)))
	}), observe(m))
	resp, err := e.client().Post(e.url("/path?q=1"), "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, resp.Body); string(got) != "echo:hello" {
		t.Fatalf("body %q", got)
	}
	resp.Body.Close()
	records := waitRecords(t, m, 1)
	r := records[0]
	if r.Method != "POST" || r.Path != "/path?q=1" || r.Authority != testHost || r.Proto != "h2" || r.Status != 201 {
		t.Fatalf("record %+v", r)
	}
	if r.State != capture.StateComplete || r.ConnectionID != "conn-1" || !r.Unverified || r.RequestIndex != 1 {
		t.Fatalf("state %+v", r)
	}
	if v := headerOf(r.RequestHeaders, "content-type"); len(v) != 1 || v[0] != "text/plain" {
		t.Fatalf("request headers %v", r.RequestHeaders)
	}
	if v := headerOf(r.ResponseHeaders, "x-reply"); len(v) != 1 || v[0] != "yes" {
		t.Fatalf("response headers %v", r.ResponseHeaders)
	}
	if got := body(t, m, r.ID, flow.Request); got != "hello" {
		t.Fatalf("request body %q", got)
	}
	if got := body(t, m, r.ID, flow.Response); got != "echo:hello" {
		t.Fatalf("response body %q", got)
	}
	if r.RequestBytes != 5 || r.ResponseBytes != 10 {
		t.Fatalf("bytes %d %d", r.RequestBytes, r.ResponseBytes)
	}
	tm := r.Timing
	if tm.Start.IsZero() || tm.RequestHeaders.IsZero() || tm.FirstByte.IsZero() || tm.ResponseHeaders.IsZero() || tm.ResponseBody.IsZero() || tm.End.IsZero() {
		t.Fatalf("timing %+v", tm)
	}
	if tm.End.Before(tm.ResponseHeaders) || tm.ResponseHeaders.Before(tm.Start) {
		t.Fatalf("timing order %+v", tm)
	}
}

func TestCaptureDisabledRecordsNothing(t *testing.T) {
	m := capture.New(capture.Options{Enabled: false})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}), observe(m))
	resp, err := e.client().Get(e.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp.Body)
	resp.Body.Close()
	if n := len(m.List(capture.Filter{}).Records); n != 0 {
		t.Fatalf("records %d", n)
	}
}

func TestCaptureConcurrentStreams(t *testing.T) {
	m := newCapture(true)
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, _ := io.ReadAll(r.Body)
		time.Sleep(10 * time.Millisecond)
		w.Write(append([]byte("r:"), in...))
	}), observe(m))
	client := e.client()
	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Post(e.url(fmt.Sprintf("/s%d", i)), "text/plain", strings.NewReader(fmt.Sprintf("body-%d", i)))
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
	records := waitRecords(t, m, n)
	for _, r := range records {
		var i int
		if _, err := fmt.Sscanf(r.Path, "/s%d", &i); err != nil {
			t.Fatalf("path %q", r.Path)
		}
		if got := body(t, m, r.ID, flow.Request); got != fmt.Sprintf("body-%d", i) {
			t.Fatalf("%s request body %q", r.Path, got)
		}
		if got := body(t, m, r.ID, flow.Response); got != fmt.Sprintf("r:body-%d", i) {
			t.Fatalf("%s response body %q", r.Path, got)
		}
	}
}

func TestCaptureGRPCStreamingTrailers(t *testing.T) {
	m := newCapture(true)
	g := newGRPCOrigin(t)
	e := startProxy(t, proxyConfig{dial: g.dial, mod: observe(m)})
	cc := grpcClient(t, e)
	s, err := cc.NewStream(context.Background(), streamDesc, "/t.Test/Stream")
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("server-stream")
	if err := s.SendMsg(&first); err != nil {
		t.Fatal(err)
	}
	s.CloseSend()
	for i := 0; i < 5; i++ {
		var out []byte
		if err := s.RecvMsg(&out); err != nil || string(out) != fmt.Sprintf("item-%d", i) {
			t.Fatalf("item %d: %q %v", i, out, err)
		}
	}
	var out []byte
	if err := s.RecvMsg(&out); err != io.EOF {
		t.Fatalf("end: %v", err)
	}
	records := waitRecords(t, m, 1)
	r := records[0]
	if r.Path != "/t.Test/Stream" || r.Status != 200 || r.State != capture.StateComplete {
		t.Fatalf("record %+v", r)
	}
	if v := headerOf(r.RequestHeaders, "content-type"); len(v) == 0 || !strings.HasPrefix(v[0], "application/grpc") {
		t.Fatalf("request headers %v", r.RequestHeaders)
	}
	if v := headerOf(r.ResponseTrailers, "x-count"); len(v) != 1 || v[0] != "5" {
		t.Fatalf("trailers %v", r.ResponseTrailers)
	}
	if v := headerOf(r.ResponseTrailers, "grpc-status"); len(v) != 1 || v[0] != "0" {
		t.Fatalf("grpc-status %v", r.ResponseTrailers)
	}
	data := body(t, m, r.ID, flow.Response)
	for i := 0; i < 5; i++ {
		if !strings.Contains(data, fmt.Sprintf("item-%d", i)) {
			t.Fatalf("response body %q", data)
		}
	}
}

func TestCaptureStreamedChunksStayLive(t *testing.T) {
	m := newCapture(true)
	release := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("one"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("two"))
	}), observe(m))
	resp, err := e.client().Get(e.url("/sse"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 3)
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "one" {
		t.Fatalf("first chunk %q %v", buf, err)
	}
	// The first chunk arrived while the exchange is still open and recorded.
	eventually(t, "partial body", func() bool {
		list := m.List(capture.Filter{}).Records
		return len(list) == 1 && list[0].State == capture.StateInProgress && list[0].Status == 200 && body(t, m, list[0].ID, flow.Response) == "one"
	})
	close(release)
	if rest := readAll(t, resp.Body); string(rest) != "two" {
		t.Fatalf("rest %q", rest)
	}
	records := waitRecords(t, m, 1)
	if got := body(t, m, records[0].ID, flow.Response); got != "onetwo" {
		t.Fatalf("body %q", got)
	}
}

func TestCaptureClientReset(t *testing.T) {
	m := newCapture(true)
	started := make(chan struct{})
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}), observe(m))
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", e.url("/hang"), nil)
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	io.ReadFull(resp.Body, buf)
	<-started
	cancel()
	resp.Body.Close()
	records := waitRecords(t, m, 1)
	r := records[0]
	if r.State != capture.StateFailed || r.Error == "" {
		t.Fatalf("record %+v", r)
	}
	if got := body(t, m, r.ID, flow.Response); got != "partial" {
		t.Fatalf("body %q", got)
	}
}

func TestCaptureRetryKeepsOneRecord(t *testing.T) {
	m := newCapture(true)
	var once sync.Once
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kill := false
		once.Do(func() { kill = true })
		if kill {
			killConn(r)
			return
		}
		w.Write([]byte("ok"))
	}), observe(m))
	resp, err := e.client().Get(e.url("/retry"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, resp.Body); !bytes.Equal(got, []byte("ok")) {
		t.Fatalf("body %q", got)
	}
	resp.Body.Close()
	records := waitRecords(t, m, 1)
	if records[0].Status != 200 || records[0].State != capture.StateComplete {
		t.Fatalf("record %+v", records[0])
	}
}
