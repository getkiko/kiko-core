package h1

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
)

func captureOptions(m *capture.Manager) Options {
	return Options{Observer: m.Observer(), Connection: &flow.ConnectionInfo{ID: "c1", Host: "a"}}
}

func captured(t *testing.T, m *capture.Manager, n int) []capture.Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		records := m.List(capture.Filter{}).Records
		done := len(records) == n
		for _, r := range records {
			if r.State == capture.StateInProgress {
				done = false
			}
		}
		if done {
			// Oldest first.
			for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
				records[i], records[j] = records[j], records[i]
			}
			return records
		}
		if time.Now().After(deadline) {
			t.Fatalf("records: %d (%+v), want %d finished", len(records), records, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func bodyOf(t *testing.T, m *capture.Manager, id string, side flow.Side) string {
	t.Helper()
	result, err := m.GetBody(capture.BodyRequest{ID: id, Side: side})
	if err != nil {
		t.Fatal(err)
	}
	return string(result.Data)
}

func TestCaptureSingleRequest(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, captureOptions(m))
	h.send("POST /p?x=1 HTTP/1.1\r\nHost: a\r\nX-B: 1\r\nX-A: 2\r\nContent-Length: 5\r\n\r\nhello")
	h.expectUpstream("POST /p?x=1 HTTP/1.1\r\nHost: a\r\nX-B: 1\r\nX-A: 2\r\nContent-Length: 5\r\n\r\nhello")
	h.reply("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if r.Method != "POST" || r.Path != "/p?x=1" || r.Authority != "a" || r.Proto != "http/1.1" || r.Status != 200 || r.State != capture.StateComplete {
		t.Fatalf("record %+v", r)
	}
	if r.ConnectionID != "c1" || r.RequestIndex != 1 {
		t.Fatalf("connection %+v", r)
	}
	if len(r.RequestHeaders) != 4 || r.RequestHeaders[1].Name != "X-B" || r.RequestHeaders[2].Name != "X-A" {
		t.Fatalf("request headers %+v", r.RequestHeaders)
	}
	if len(r.ResponseHeaders) != 3 || r.ResponseHeaders[0].Value != "a=1" || r.ResponseHeaders[1].Value != "b=2" {
		t.Fatalf("response headers %+v", r.ResponseHeaders)
	}
	if got := bodyOf(t, m, r.ID, flow.Request); got != "hello" {
		t.Fatalf("request body %q", got)
	}
	if got := bodyOf(t, m, r.ID, flow.Response); got != "ok" {
		t.Fatalf("response body %q", got)
	}
	tm := r.Timing
	if tm.Start.IsZero() || tm.RequestHeaders.IsZero() || tm.RequestBody.IsZero() || tm.FirstByte.IsZero() || tm.ResponseHeaders.IsZero() || tm.ResponseBody.IsZero() || tm.End.IsZero() {
		t.Fatalf("timing %+v", tm)
	}
}

func TestCapturePipelined(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, captureOptions(m))
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
	h.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\ntwo")
	h.expectClient("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\ntwo")
	h.client.Close()
	h.wait()
	records := captured(t, m, 2)
	if records[0].Path != "/1" || records[0].Status != 200 || records[0].RequestIndex != 1 {
		t.Fatalf("first %+v", records[0])
	}
	if records[1].Path != "/2" || records[1].Status != 404 || records[1].RequestIndex != 2 {
		t.Fatalf("second %+v", records[1])
	}
	if bodyOf(t, m, records[0].ID, flow.Response) != "one" || bodyOf(t, m, records[1].ID, flow.Response) != "two" {
		t.Fatal("bodies mixed up")
	}
}

func TestCaptureChunkedWithTrailers(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, captureOptions(m))
	h.send("POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-Sum: 7\r\n\r\n")
	readUntil(t, h.upstream, "X-Sum: 7\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwxyz\r\n3\r\n123\r\n0\r\nX-End: yes\r\n\r\n")
	readUntil(t, h.client, "X-End: yes\r\n\r\n")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if got := bodyOf(t, m, r.ID, flow.Request); got != "abcde" {
		t.Fatalf("request body %q", got)
	}
	if got := bodyOf(t, m, r.ID, flow.Response); got != "wxyz123" {
		t.Fatalf("response body %q", got)
	}
	if len(r.RequestTrailers) != 1 || r.RequestTrailers[0].Name != "X-Sum" || r.RequestTrailers[0].Value != "7" {
		t.Fatalf("request trailers %+v", r.RequestTrailers)
	}
	if len(r.ResponseTrailers) != 1 || r.ResponseTrailers[0].Name != "X-End" {
		t.Fatalf("response trailers %+v", r.ResponseTrailers)
	}
}

func TestCaptureExpectContinue(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, captureOptions(m))
	h.send("POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.expectUpstream("POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
	h.reply("HTTP/1.1 100 Continue\r\n\r\n")
	h.expectClient("HTTP/1.1 100 Continue\r\n\r\n")
	h.send("hello")
	h.expectUpstream("hello")
	h.reply("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if len(r.Interim) != 1 || r.Interim[0] != 100 || r.Status != 201 {
		t.Fatalf("record %+v", r)
	}
	if got := bodyOf(t, m, r.ID, flow.Request); got != "hello" {
		t.Fatalf("request body %q", got)
	}
}

func TestCaptureUpgradeStopsCapturing(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, captureOptions(m))
	request := "GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	h.send(request)
	h.expectUpstream(request)
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	h.reply(response)
	h.expectClient(response)
	h.send("tunnel-bytes")
	h.expectUpstream("tunnel-bytes")
	h.reply("back")
	h.expectClient("back")
	h.client.Close()
	h.upstream.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if r.State != capture.StateUpgraded || r.Status != 101 {
		t.Fatalf("record %+v", r)
	}
	if r.RequestBytes != 0 || r.ResponseBytes != 0 {
		t.Fatalf("tunnel bytes were captured: %d %d", r.RequestBytes, r.ResponseBytes)
	}
}

func TestCaptureRedialResendKeepsOneRecord(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true})
	r := newRedialHarnessOptions(t, captureOptions(m))
	r.roundTrip("/1")
	r.send("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.upstream.Close()
	r.switchUpstream()
	r.expectUpstream("GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
	r.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	r.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	r.client.Close()
	r.wait()
	records := captured(t, m, 2)
	if records[1].Path != "/2" || records[1].Status != 200 || records[1].State != capture.StateComplete {
		t.Fatalf("record %+v", records[1])
	}
	if records[1].Timing.RequestHeaders.IsZero() {
		t.Fatal("no request timing")
	}
}

func TestCaptureBodyLimit(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true, MaxBody: 4})
	h := newHarnessOptions(t, captureOptions(m))
	h.send("POST /big HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n0123456789")
	h.expectUpstream("POST /big HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n0123456789")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabcdefgh")
	// The client still gets the whole body.
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabcdefgh")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if !r.RequestBodyTruncated || !r.ResponseBodyTruncated || r.RequestBytes != 10 || r.ResponseBytes != 8 {
		t.Fatalf("record %+v", r)
	}
	if got := bodyOf(t, m, r.ID, flow.Request); got != "0123" {
		t.Fatalf("request body %q", got)
	}
	if got := bodyOf(t, m, r.ID, flow.Response); got != "abcd" {
		t.Fatalf("response body %q", got)
	}
}

func TestCaptureLargeBodyUsesPipe(t *testing.T) {
	m := capture.New(capture.Options{Enabled: true, Body: true, MaxBody: 1 << 20})
	h := newHarnessOptions(t, captureOptions(m))
	const size = 200 << 10
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	go func() {
		h.client.Write([]byte(fmt.Sprintf("POST /l HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n", size)))
		h.client.Write(payload)
	}()
	head := fmt.Sprintf("POST /l HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n", size)
	h.expectUpstream(head)
	h.expectUpstream(string(payload))
	h.reply(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size))
	go h.upstream.Write(payload)
	h.expectClient(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size))
	h.expectClient(string(payload))
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if r.RequestBytes != size || r.ResponseBytes != size || r.RequestBodyTruncated || r.ResponseBodyTruncated {
		t.Fatalf("record %+v", r)
	}
	if got := bodyOf(t, m, r.ID, flow.Response); got != string(payload) {
		t.Fatal("response body differs")
	}
}

func TestCaptureOff(t *testing.T) {
	m := capture.New(capture.Options{Enabled: false})
	// A disabled store yields no observer; Serve behaves as without capture.
	h := newHarnessOptions(t, Options{Observer: m.Observer()})
	h.send("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	if n := len(m.List(capture.Filter{}).Records); n != 0 {
		t.Fatalf("records %d", n)
	}
}

func readUntil(t *testing.T, conn net.Conn, marker string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	chunk := make([]byte, 4096)
	for !strings.Contains(string(got), marker) {
		n, err := conn.Read(chunk)
		got = append(got, chunk[:n]...)
		if err != nil {
			t.Fatalf("waiting for %q, got %q: %v", marker, got, err)
		}
	}
}
