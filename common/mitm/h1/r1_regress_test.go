package h1

import (
	"io"
	"strings"
	"testing"
)

// An upstream response with an empty Transfer-Encoding and an invalid Content-Length is
// delimited by close; the client must not receive the unvalidated Content-Length (found by
// FuzzRelayResponse in package R).
func TestEmptyTransferEncodingDropsContentLength(t *testing.T) {
	h := newHarness(t)
	h.send("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.0 200 \r\nTransfer-Encoding:\r\nContent-Length:\r\n\r\nbody")
	h.upstream.Close()
	got, _ := io.ReadAll(h.clientR)
	if strings.Contains(strings.ToLower(string(got)), "content-length") || !strings.HasSuffix(string(got), "body") {
		t.Fatalf("client got %q", got)
	}
	h.wait()
}
