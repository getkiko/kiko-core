package h2

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/httpx"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestWithoutCredentialsExtended(t *testing.T) {
	h := http.Header{"Referer": {"https://a.test/"}, "Origin": {"https://a.test"}, "X-Other": {"1"}}
	for _, name := range httpx.CredentialHeaders {
		h.Set(name, "secret")
	}
	out := withoutCredentials(h)
	for _, name := range httpx.CredentialHeaders {
		if out.Get(name) != "" {
			t.Errorf("%s kept", name)
		}
	}
	if out.Get("Referer") == "" || out.Get("Origin") == "" || out.Get("X-Other") == "" {
		t.Error("harmless headers dropped")
	}
	if h.Get("X-Api-Key") == "" {
		t.Error("input modified")
	}
}

// startChromePeer connects a Chrome client to a raw server past the SETTINGS exchange.
func startChromePeer(t *testing.T) (*rawServer, *chromeConn) {
	t.Helper()
	server, client := startRawServer(t)
	cci, err := newChromeClientConn(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	cc := cci.(*chromeConn)
	t.Cleanup(func() { cc.Close() })
	nextOf[*http2.SettingsFrame](server)
	server.fr.WriteSettings()
	server.fr.WriteSettingsAck()
	return server, cc
}

func roundTripAsync(cc *chromeConn, req *http.Request) chan error {
	done := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		done <- err
	}()
	return done
}

func writeResponseHead(t *testing.T, s *rawServer, id uint32, endStream bool, fields ...hpack.HeaderField) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range fields {
		enc.WriteField(f)
	}
	if err := s.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndStream: endStream, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
}

func TestChromeControlQueueBounded(t *testing.T) {
	old := chromeCtlLimit
	chromeCtlLimit = 50
	defer func() { chromeCtlLimit = old }()
	server, cc := startChromePeer(t)

	// The socket write stalls: the writer holds wmu as a blocked write would.
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	for i := 0; i < 500; i++ {
		if err := server.fr.WritePing(false, [8]byte{byte(i)}); err != nil {
			break
		}
		if i%3 == 0 {
			server.fr.WriteSettings()
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for cc.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cc.Err() == nil {
		t.Fatal("connection stays open under a control frame flood")
	}
	cc.ctlMu.Lock()
	n := len(cc.ctl)
	cc.ctlMu.Unlock()
	if n > cc.ctlLimit {
		t.Fatalf("queue holds %d, limit %d", n, cc.ctlLimit)
	}
	select {
	case <-cc.done:
	case <-time.After(2 * time.Second):
		t.Fatal("connection not closed")
	}
}

func TestChromeWriteTimeout(t *testing.T) {
	old := chromeWriteTimeout
	chromeWriteTimeout = 100 * time.Millisecond
	defer func() { chromeWriteTimeout = old }()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	start := time.Now()
	if _, err := (deadlineWriter{a, chromeWriteTimeout}).Write([]byte("x")); err == nil {
		t.Fatal("write to a peer that never reads succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("write did not time out")
	}
}

func TestChromeRejects101(t *testing.T) {
	server, cc := startChromePeer(t)
	req, _ := http.NewRequest("GET", "https://example.test/", nil)
	done := roundTripAsync(cc, req)
	nextOf[*http2.MetaHeadersFrame](server)
	writeResponseHead(t, server, 1, false, hpack.HeaderField{Name: ":status", Value: "101"})
	if err := <-done; err == nil {
		t.Fatal("101 accepted as a response")
	}
	rst := nextOf[*http2.RSTStreamFrame](server)
	if rst.StreamID != 1 || rst.ErrCode != http2.ErrCodeProtocol {
		t.Fatalf("reset %v on stream %d", rst.ErrCode, rst.StreamID)
	}
}

func TestChromeRejectsControlCharsInResponse(t *testing.T) {
	for _, value := range []string{"a\r\nInjected: 1", "a\nb", "a\x00b"} {
		server, cc := startChromePeer(t)
		req, _ := http.NewRequest("GET", "https://example.test/", nil)
		done := roundTripAsync(cc, req)
		nextOf[*http2.MetaHeadersFrame](server)
		writeResponseHead(t, server, 1, true, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "x-evil", Value: value})
		if err := <-done; err == nil {
			t.Fatalf("response header value %q accepted", value)
		}
	}
}

func TestChromeResponseTrailerFiltered(t *testing.T) {
	server, cc := startChromePeer(t)
	req, _ := http.NewRequest("GET", "https://example.test/", nil)
	respCh := make(chan *http.Response, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Error(err)
		}
		respCh <- resp
	}()
	nextOf[*http2.MetaHeadersFrame](server)
	writeResponseHead(t, server, 1, false, hpack.HeaderField{Name: ":status", Value: "200"})
	writeResponseHead(t, server, 1, true,
		hpack.HeaderField{Name: "x-ok", Value: "1"},
		hpack.HeaderField{Name: "set-cookie", Value: "a=b"},
		hpack.HeaderField{Name: "content-type", Value: "text/html"},
		hpack.HeaderField{Name: "location", Value: "https://evil.test/"})
	resp := <-respCh
	if resp == nil {
		t.Fatal("no response")
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.Trailer.Get("X-Ok") != "1" || len(resp.Trailer) != 1 {
		t.Fatalf("trailer %v", resp.Trailer)
	}
}

func TestChromeRequestTrailerFiltered(t *testing.T) {
	server, cc := startChromePeer(t)
	req, _ := http.NewRequest("POST", "https://example.test/up", io.NopCloser(bytes.NewReader([]byte("p"))))
	req.ContentLength = 1
	req.Trailer = http.Header{"X-Tr": {"v"}, "Content-Type": {"text/html"}, "Authorization": {"x"}}
	done := roundTripAsync(cc, req)
	headers := nextOf[*http2.MetaHeadersFrame](server)
	for _, f := range headers.Fields {
		if f.Name == "trailer" && f.Value != "X-Tr" {
			t.Fatalf("declared trailer %q", f.Value)
		}
	}
	nextOf[*http2.DataFrame](server)
	trailer := nextOf[*http2.MetaHeadersFrame](server)
	if len(trailer.Fields) != 1 || trailer.Fields[0].Name != "x-tr" {
		t.Fatalf("trailer frame %v", trailer.Fields)
	}
	server.respond(1)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
