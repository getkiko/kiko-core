package h2

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func chromeLengthCase(t *testing.T, method string, status string, length string, data string) (*http.Response, error, error) {
	server, cc := startChromePeer(t)
	req, _ := http.NewRequest(method, "https://example.test/", nil)
	type out struct {
		resp *http.Response
		err  error
	}
	ch := make(chan out, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		ch <- out{resp, err}
	}()
	nextOf[*http2.MetaHeadersFrame](server)
	fields := []hpack.HeaderField{{Name: ":status", Value: status}, {Name: "content-length", Value: length}, {Name: "connection", Value: "close"}}
	writeResponseHead(t, server, 1, false, fields...)
	if data != "" {
		server.fr.WriteData(1, true, []byte(data))
	} else {
		server.fr.WriteData(1, true, nil)
	}
	o := <-ch
	if o.err != nil {
		return nil, o.err, nil
	}
	_, rerr := io.Copy(io.Discard, o.resp.Body)
	return o.resp, nil, rerr
}

func TestChromeContentLengthMismatch(t *testing.T) {
	if _, herr, rerr := chromeLengthCase(t, "GET", "200", "10", "abc"); herr == nil && rerr == nil {
		t.Fatal("short body accepted")
	}
	if _, herr, rerr := chromeLengthCase(t, "GET", "200", "2", "abcdef"); herr == nil && rerr == nil {
		t.Fatal("long body accepted")
	}
	resp, herr, rerr := chromeLengthCase(t, "GET", "200", "3", "abc")
	if herr != nil || rerr != nil {
		t.Fatalf("exact body rejected: %v %v", herr, rerr)
	}
	if resp.Header.Get("Connection") != "" {
		t.Fatal("connection header relayed")
	}
	if _, herr, rerr := chromeLengthCase(t, "HEAD", "200", "10", ""); herr != nil || rerr != nil {
		t.Fatalf("HEAD rejected: %v %v", herr, rerr)
	}
	if _, herr, rerr := chromeLengthCase(t, "GET", "304", "10", ""); herr != nil || rerr != nil {
		t.Fatalf("304 rejected: %v %v", herr, rerr)
	}
}

func TestChromeZeroMaxStreamsStall(t *testing.T) {
	old := chromeStallLimit
	chromeStallLimit = 150 * time.Millisecond
	defer func() { chromeStallLimit = old }()
	server, client := startRawServer(t)
	cci, err := newChromeClientConn(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}
	cc := cci.(*chromeConn)
	t.Cleanup(func() { cc.Close() })
	nextOf[*http2.SettingsFrame](server)
	server.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 0})
	server.fr.WriteSettingsAck()
	time.Sleep(50 * time.Millisecond)
	req, _ := http.NewRequest("GET", "https://example.test/", nil)
	done := roundTripAsync(cc, req)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "no concurrent streams") {
			t.Fatalf("err %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RoundTrip still waiting")
	}
}
