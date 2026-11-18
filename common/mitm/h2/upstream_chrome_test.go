package h2

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// rawServer is a bare HTTP/2 peer for the Chrome client: it reads the preface
// and hands every frame to the test.
type rawServer struct {
	t        *testing.T
	nc       net.Conn
	fr       *http2.Framer
	prefaced bool
}

func startRawServer(t *testing.T) (*rawServer, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		nc, err := ln.Accept()
		if err == nil {
			accepted <- nc
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	nc := <-accepted
	t.Cleanup(func() { nc.Close() })
	s := &rawServer{t: t, nc: nc}
	s.fr = http2.NewFramer(nc, nc)
	s.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	return s, client
}

// next reads the next frame; it is valid until the following call.
func (s *rawServer) next() http2.Frame {
	s.t.Helper()
	s.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if !s.prefaced {
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(s.nc, preface); err != nil || string(preface) != http2.ClientPreface {
			s.t.Fatalf("client preface: %v", err)
		}
		s.prefaced = true
	}
	f, err := s.fr.ReadFrame()
	if err != nil {
		s.t.Fatal(err)
	}
	return f
}

// nextOf skips frames until one of type T arrives.
func nextOf[T http2.Frame](s *rawServer) T {
	s.t.Helper()
	for {
		if f, ok := s.next().(T); ok {
			return f
		}
	}
}

// respond writes a bare 200 response head ending the stream.
func (s *rawServer) respond(id uint32) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	if err := s.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
		s.t.Fatal(err)
	}
}

func TestChromePrefaceAndRequest(t *testing.T) {
	server, client := startRawServer(t)
	cc, err := newChromeClientConn(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	first, ok := server.next().(*http2.SettingsFrame)
	if !ok {
		t.Fatal("the first frame is not SETTINGS")
	}
	var settings []http2.Setting
	first.ForeachSetting(func(s http2.Setting) error {
		settings = append(settings, s)
		return nil
	})
	if !reflect.DeepEqual(settings, chromeSettings) {
		t.Fatalf("settings %v, want %v", settings, chromeSettings)
	}
	update, ok := server.next().(*http2.WindowUpdateFrame)
	if !ok || update.StreamID != 0 || update.Increment != 15663105 {
		t.Fatalf("second frame %#v, want WINDOW_UPDATE 15663105 on the connection", update)
	}
	server.fr.WriteSettings()
	server.fr.WriteSettingsAck()

	req, _ := http.NewRequest("GET", "https://example.test/search?q=1", nil)
	req.Header = http.Header{
		"Cookie":          {"a=1; b=2"},
		"Accept-Language": {"en-US"},
		"Accept-Encoding": {"gzip, br"},
		"Sec-Fetch-Mode":  {"navigate"},
		"X-Custom":        {"1"},
		"Accept":          {"text/html"},
		"User-Agent":      {"Mozilla/5.0"},
		"Sec-Ch-Ua":       {`"Chromium";v="130"`},
		"Connection":      {"close"},
	}
	req.Host = "example.test"
	done := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	headers := nextOf[*http2.MetaHeadersFrame](server)
	if !headers.StreamEnded() || headers.StreamID != 1 {
		t.Fatalf("headers frame: end %v id %d", headers.StreamEnded(), headers.StreamID)
	}
	if headers.Priority != (http2.PriorityParam{Exclusive: true, Weight: 255}) {
		t.Fatalf("priority %+v", headers.Priority)
	}
	var names, values []string
	for _, f := range headers.Fields {
		names = append(names, f.Name)
		values = append(values, f.Value)
	}
	wantNames := []string{
		":method", ":authority", ":scheme", ":path",
		"sec-ch-ua", "user-agent", "accept", "x-custom", "sec-fetch-mode",
		"accept-encoding", "accept-language", "cookie", "cookie",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("field order %v, want %v", names, wantNames)
	}
	if values[0] != "GET" || values[1] != "example.test" || values[2] != "https" || values[3] != "/search?q=1" {
		t.Fatalf("pseudo values %v", values[:4])
	}
	if values[11] != "a=1" || values[12] != "b=2" {
		t.Fatalf("cookie crumbs %v", values[11:])
	}
	server.respond(1)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestChromeBodyAndTrailers(t *testing.T) {
	server, client := startRawServer(t)
	cc, err := newChromeClientConn(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	nextOf[*http2.SettingsFrame](server)
	server.fr.WriteSettings()

	req, _ := http.NewRequest("POST", "https://example.test/up", io.NopCloser(strings.NewReader("payload")))
	req.ContentLength = 7
	req.Header = http.Header{"Content-Type": {"text/plain"}}
	req.Trailer = http.Header{"X-Tr": {"v1"}}
	done := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	headers := nextOf[*http2.MetaHeadersFrame](server)
	if headers.StreamEnded() {
		t.Fatal("request head ends the stream although a body follows")
	}
	got := map[string]string{}
	for _, f := range headers.Fields {
		got[f.Name] = f.Value
	}
	if got["content-length"] != "7" || got["trailer"] != "X-Tr" {
		t.Fatalf("fields %v", got)
	}
	data := nextOf[*http2.DataFrame](server)
	if string(data.Data()) != "payload" {
		t.Fatalf("data %q", data.Data())
	}
	trailer := nextOf[*http2.MetaHeadersFrame](server)
	if !trailer.StreamEnded() || len(trailer.Fields) != 1 || trailer.Fields[0].Name != "x-tr" || trailer.Fields[0].Value != "v1" {
		t.Fatalf("trailer frame %v end %v", trailer.Fields, trailer.StreamEnded())
	}
	server.respond(1)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestChromeBufferCap checks that streams which nobody reads cannot pin more
// than chromeBufferCap on the connection although the announced windows are
// 6 MiB per stream and 15 MiB per connection.
func TestChromeBufferCap(t *testing.T) {
	server, client := startRawServer(t)
	cci, err := newChromeClientConn(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	cc := cci.(*chromeConn)
	defer cc.Close()
	nextOf[*http2.SettingsFrame](server)
	server.fr.WriteSettings()
	server.fr.WriteSettingsAck()

	type result struct {
		resp *http.Response
		err  error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "https://example.test/big", nil)
		go func() {
			resp, err := cc.RoundTrip(req)
			results <- result{resp, err}
		}()
		nextOf[*http2.MetaHeadersFrame](server)
	}
	// Answer both streams and send 6 MiB on each, as far as the windows allow.
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	for _, id := range []uint32{1, 3} {
		if err := server.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
		block.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	}
	var resps [2]*http.Response
	for i := range resps {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		resps[i] = r.resp
	}
	chunk := bytes.Repeat([]byte("x"), 16384)
	var sent atomic.Int64
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for i := 0; i < 6<<20/len(chunk); i++ {
			for _, id := range []uint32{1, 3} {
				if err := server.fr.WriteData(id, false, chunk); err != nil {
					return
				}
				sent.Add(int64(len(chunk)))
			}
		}
		server.fr.WriteData(1, true, nil)
		server.fr.WriteData(3, true, nil)
	}()
	// Nothing reads: the client buffers up to the cap, then stops reading.
	last := int64(-1)
	for stable := 0; stable < 10; {
		time.Sleep(30 * time.Millisecond)
		cc.mu.Lock()
		now := cc.buffered
		cc.mu.Unlock()
		if now == last {
			stable++
		} else {
			stable, last = 0, now
		}
	}
	if last < chromeBufferCap || last > chromeBufferCap+2*chromeDefaultFrameSize {
		t.Fatalf("buffered %d bytes, want the cap %d", last, chromeBufferCap)
	}
	// Reading releases the rest.
	for i, resp := range resps {
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil || n != 6<<20 {
			t.Fatalf("stream %d: read %d bytes, err %v", i, n, err)
		}
	}
	<-writeDone
}

// TestChromeGoAwayRetryable checks that a request refused by GOAWAY fails with
// an error the relay retries on a new connection.
func TestChromeGoAway(t *testing.T) {
	server, client := startRawServer(t)
	cc, err := newChromeClientConn(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	nextOf[*http2.SettingsFrame](server)
	server.fr.WriteSettings()
	server.fr.WriteGoAway(0, http2.ErrCodeNo, nil)
	deadline := time.Now().Add(5 * time.Second)
	for cc.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("GOAWAY not noticed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	req, _ := http.NewRequest("GET", "https://example.test/", nil)
	_, err = cc.RoundTrip(req)
	if err == nil || !notSent(err) || !unusable(err) {
		t.Fatalf("error %v is not a retryable refusal", err)
	}
}
