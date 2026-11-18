package h1

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/body"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

func bodyRule(id, pattern, scope, regex, value string, types ...string) option.MITMBodyRewriteRule {
	return option.MITMBodyRewriteRule{
		ID: id, Pattern: pattern, Scope: scope, ContentTypes: badoption.Listable[string](types),
		Edits: []option.MITMBodyRewriteEdit{{Action: "replace-regex", Regex: regex, Value: value}},
	}
}

func bodyOptions(maxSize string, rules ...option.MITMBodyRewriteRule) option.MITMHTTPRewriteOptions {
	options := option.MITMHTTPRewriteOptions{Body: rules}
	if maxSize != "" {
		var value byteformats.MemoryBytes
		if err := json.Unmarshal([]byte(`"`+maxSize+`"`), &value); err != nil {
			panic(err)
		}
		options.MaxBodySize = &value
	}
	return options
}

func gzipBytes(t *testing.T, text string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := gzip.NewWriter(&buffer)
	w.Write([]byte(text))
	w.Close()
	return buffer.Bytes()
}

func chunk(s string) string {
	return strconv.FormatInt(int64(len(s)), 16) + "\r\n" + s + "\r\n"
}

func TestBodyResponseContentLength(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `goodbye!`)))
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nDigest: sha-256=abc\r\n\r\nhello world")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\n\r\ngoodbye! world")
	// keep-alive survives
	h.send("GET /y HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /y HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 5\r\n\r\nhello")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 5\r\n\r\nhello")
	h.client.Close()
	h.wait()
	records := captured(t, m, 2)
	r := records[0]
	if len(r.Rewrites) != 1 || r.Rewrites[0].Kind != "body" || r.Rewrites[0].Action != "edit" || r.Rewrites[0].Side != "response" || r.Rewrites[0].Rule != "b1" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
	if got := bodyOf(t, m, r.ID, flow.Response); got != "goodbye! world" {
		t.Fatalf("recorded body %q", got)
	}
	foundDigest := false
	for _, c := range r.Rewrites[0].Changes {
		if c.Name == "Digest" && c.Op == "delete" {
			foundDigest = true
		}
	}
	if !foundDigest {
		t.Fatalf("digest removal not recorded: %+v", r.Rewrites[0].Changes)
	}
	for _, header := range r.ResponseHeaders {
		if strings.EqualFold(header.Name, "Digest") {
			t.Fatal("digest recorded in head")
		}
	}
	if len(records[1].Rewrites) != 0 {
		t.Fatalf("unselected content type recorded hits %+v", records[1].Rewrites)
	}
}

func TestBodyResponseChunkedBecomesLength(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `a+`, `X`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("baa") + chunk("aad") + "0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nbXd")
	h.client.Close()
	h.wait()
}

func TestBodyResponseChunkedUnchangedKeepsChunked(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `zzz`, `X`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("baa") + chunk("aad") + "0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nbaaaad\r\n0\r\n\r\n")
	h.client.Close()
	h.wait()
}

func TestBodyResponseGzip(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	packed := gzipBytes(t, "hello hello")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: " + strconv.Itoa(len(packed)) + "\r\n\r\n" + string(packed))
	resp, err := readResponse(h.clientR)
	if err != nil {
		t.Fatal(err)
	}
	if resp.header["Content-Encoding"] != "gzip" || resp.header["Content-Length"] != strconv.Itoa(len(resp.body)) {
		t.Fatalf("head %+v", resp.header)
	}
	reader, err := gzip.NewReader(bytes.NewReader(resp.body))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(reader)
	if string(plain) != "bye bye" {
		t.Fatalf("decoded %q", plain)
	}
	h.client.Close()
	h.wait()
}

type rawResponse struct {
	status string
	header map[string]string
	body   []byte
}

// readResponse reads a Content-Length framed response.
func readResponse(r *bufio.Reader) (*rawResponse, error) {
	status, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	out := &rawResponse{status: strings.TrimSpace(status), header: map[string]string{}}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, _ := strings.Cut(line, ": ")
		out.header[name] = value
	}
	n := 0
	for _, c := range out.header["Content-Length"] {
		n = n*10 + int(c-'0')
	}
	out.body = make([]byte, n)
	_, err = io.ReadFull(r, out.body)
	return out, err
}

func TestBodyResponseTooLargeKnownLengthPassesThrough(t *testing.T) {
	set := compileSet(t, bodyOptions("1KB", bodyRule("b1", `^https://a/`, "response", `a`, `b`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	payload := strings.Repeat("a", 3000)
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3000\r\n\r\n" + payload)
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3000\r\n\r\n" + payload)
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 1 || hits[0].Action != "skipped" || hits[0].Target != "size" || hits[0].Kind != "body" {
		t.Fatalf("hits %+v", hits)
	}
}

func TestBodyResponseTooLargeChunkedPassesThrough(t *testing.T) {
	set := compileSet(t, bodyOptions("1KB", bodyRule("b1", `^https://a/`, "response", `a`, `b`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	part := strings.Repeat("a", 700)
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk(part) + chunk(part) + chunk(part) + "0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
	got := readChunked(t, h.clientR)
	if got != part+part+part {
		t.Fatalf("passthrough lost bytes: %d", len(got))
	}
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 1 || hits[0].Action != "skipped" || hits[0].Target != "size" {
		t.Fatalf("hits %+v", hits)
	}
}

// readChunked decodes a chunked body from r.
func readChunked(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var out strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, c := range strings.TrimSpace(line) {
			switch {
			case c >= '0' && c <= '9':
				n = n*16 + int(c-'0')
			case c >= 'a' && c <= 'f':
				n = n*16 + int(c-'a') + 10
			}
		}
		if n == 0 {
			r.ReadString('\n')
			return out.String()
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			t.Fatal(err)
		}
		out.Write(data)
		r.ReadString('\n')
	}
}

func TestBodyStreamsAreNotBuffered(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `a`, `b`, "event-stream", "grpc")))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /sse HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /sse HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("data: a\n\n"))
	// The first event arrives while the response is still open.
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: a\n\n\r\n")
	h.reply(chunk("data: a\n\n") + "0\r\n\r\n")
	h.expectClient("9\r\ndata: a\n\n\r\n0\r\n\r\n")
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 1 || hits[0].Action != "skipped" || hits[0].Target != "stream" {
		t.Fatalf("hits %+v", hits)
	}
}

func TestBodyGRPCRequestAndResponseStream(t *testing.T) {
	set := compileSet(t, bodyOptions("",
		bodyRule("req", `^https://a/`, "request", `a`, `b`, "grpc"),
		bodyRule("resp", `^https://a/`, "response", `a`, `b`, "grpc")))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("POST /g HTTP/1.1\r\nHost: a\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("aaaa"))
	h.expectUpstream("POST /g HTTP/1.1\r\nHost: a\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n4\r\naaaa\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("aaaa"))
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n4\r\naaaa\r\n")
	h.send("0\r\n\r\n")
	h.expectUpstream("0\r\n\r\n")
	h.reply("0\r\n\r\n")
	h.expectClient("0\r\n\r\n")
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 2 {
		t.Fatalf("hits %+v", hits)
	}
	for _, hit := range hits {
		if hit.Action != "skipped" || hit.Target != "stream" {
			t.Fatalf("hit %+v", hit)
		}
	}
}

func TestBodyBufferTimeoutPassesThrough(t *testing.T) {
	old := rewrite.BufferTimeout
	rewrite.BufferTimeout = 150 * time.Millisecond
	defer func() { rewrite.BufferTimeout = old }()
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `a`, `b`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /poll HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /poll HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("aaa"))
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n3\r\naaa\r\n")
	time.Sleep(50 * time.Millisecond)
	h.reply(chunk("aaa") + "0\r\n\r\n")
	h.expectClient("3\r\naaa\r\n0\r\n\r\n")
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 1 || hits[0].Action != "skipped" || hits[0].Target != "timeout" {
		t.Fatalf("hits %+v", hits)
	}
}

func TestBodyBufferBudgetBusyPassesThrough(t *testing.T) {
	if !body.Buffering.Acquire(body.BufferingLimit) {
		t.Skip("budget in use")
	}
	defer body.Buffering.Release(body.BufferingLimit)
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 1 || hits[0].Action != "skipped" || hits[0].Target != "busy" {
		t.Fatalf("hits %+v", hits)
	}
}

func TestBodyBudgetReleasedAfterExchange(t *testing.T) {
	before := body.Buffering.Used()
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbye")
	h.client.Close()
	h.wait()
	if used := body.Buffering.Used(); used != before {
		t.Fatalf("budget leaked: %d -> %d", before, used)
	}
}

func TestBodyNoBodyResponsesAreUntouched(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `.`, `X`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	// HEAD keeps the representation length and gets no body.
	h.send("HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n")
	h.send("GET /n HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /n HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n")
	h.expectClient("HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n")
	h.send("GET /m HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /m HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 304 Not Modified\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n")
	h.expectClient("HTTP/1.1 304 Not Modified\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n")
	// A 206 answering a range request is not rewritten.
	h.send("GET /r HTTP/1.1\r\nHost: a\r\nRange: bytes=0-4\r\n\r\n")
	h.expectUpstream("GET /r HTTP/1.1\r\nHost: a\r\nRange: bytes=0-4\r\n\r\n")
	h.reply("HTTP/1.1 206 Partial Content\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-4/9\r\nContent-Length: 5\r\n\r\nhello")
	h.expectClient("HTTP/1.1 206 Partial Content\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-4/9\r\nContent-Length: 5\r\n\r\nhello")
	// pipelining stays serial
	h.send("GET /p1 HTTP/1.1\r\nHost: a\r\n\r\nGET /p2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /p1 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nab")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nXX")
	h.expectUpstream("GET /p2 HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\ncd")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nXX")
	h.client.Close()
	h.wait()
	records := captured(t, m, 6)
	for _, i := range []int{0, 1, 2, 3} {
		hits := records[i].Rewrites
		if len(hits) != 1 || hits[0].Action != "skipped" || hits[0].Target != "stream" {
			t.Fatalf("record %d hits %+v", i, hits)
		}
	}
}

func TestBodyResponseCloseDelimited(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello")
	h.upstream.Close()
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbye")
	expectEOF(t, "client", h.clientR)
	h.wait()
}

func TestBodyRequestContentLength(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "request", `"id":\d+`, `"id":1234567`)))
	m := capture.New(capture.Options{Enabled: true, Body: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\n{\"id\":7}")
	h.expectUpstream("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"id\":1234567}")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	r := captured(t, m, 1)[0]
	if got := bodyOf(t, m, r.ID, flow.Request); got != "{\"id\":1234567}" {
		t.Fatalf("recorded request body %q", got)
	}
	if len(r.Rewrites) != 1 || r.Rewrites[0].Side != "request" {
		t.Fatalf("hits %+v", r.Rewrites)
	}
}

func TestBodyRequestChunkedBecomesLength(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "request", `cat`, `tiger`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("a ca") + chunk("t!") + "0\r\n\r\n")
	h.expectUpstream("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\na tiger!")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
}

func TestBodyRequestNeverSendsBothLengthAndChunked(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "request", `x`, `yy`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("xx") + "0\r\n\r\n")
	head := readHead(t, h.upstreamR)
	if strings.Contains(strings.ToLower(head), "transfer-encoding") || !strings.Contains(head, "Content-Length: 4\r\n") {
		t.Fatalf("head %q", head)
	}
	expect(t, "upstream", h.upstreamR, "yyyy")
	h.client.Close()
}

func TestBodyRequestExpectContinue(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "request", `hello`, `hi`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
	// The engine answers the expectation itself, before the body exists.
	h.expectClient("HTTP/1.1 100 Continue\r\n\r\n")
	h.send("hello")
	h.expectUpstream("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
}

func TestBodyRequestTooLargeStreams(t *testing.T) {
	set := compileSet(t, bodyOptions("1KB", bodyRule("b1", `^https://a/`, "request", `a`, `b`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	payload := strings.Repeat("a", 3000)
	h.send("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nContent-Length: 3000\r\n\r\n" + payload)
	h.expectUpstream("POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nContent-Length: 3000\r\n\r\n" + payload)
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	// Unknown length beyond the limit turns into a streamed chunked request, no length.
	h.send("POST /y HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk(payload) + chunk("tail") + "0\r\n\r\n")
	head := readHead(t, h.upstreamR)
	if !strings.Contains(head, "Transfer-Encoding: chunked") || strings.Contains(head, "Content-Length") {
		t.Fatalf("head %q", head)
	}
	if got := readChunked(t, h.upstreamR); got != payload+"tail" {
		t.Fatalf("body lost bytes: %d", len(got))
	}
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	records := captured(t, m, 2)
	for _, r := range records {
		if len(r.Rewrites) != 1 || r.Rewrites[0].Action != "skipped" || r.Rewrites[0].Target != "size" {
			t.Fatalf("hits %+v", r.Rewrites)
		}
	}
}

func TestBodyUnknownEncodingPassesThrough(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: weird\r\nContent-Length: 5\r\n\r\nhello")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: weird\r\nContent-Length: 5\r\n\r\nhello")
	h.client.Close()
	h.wait()
	hits := captured(t, m, 1)[0].Rewrites
	if len(hits) != 1 || hits[0].Target != "encoding" {
		t.Fatalf("hits %+v", hits)
	}
}

// internalDialer returns a dialer whose connections the test serves, and the channel of them.
func internalDialer(t *testing.T) (func(context.Context, *rewrite.Internal) (net.Conn, error), chan net.Conn, chan *rewrite.Internal) {
	conns := make(chan net.Conn, 4)
	targets := make(chan *rewrite.Internal, 4)
	return func(_ context.Context, in *rewrite.Internal) (net.Conn, error) {
		test, proxy := tcpPair(t)
		test.SetDeadline(time.Now().Add(10 * time.Second))
		conns <- test
		targets <- in
		return proxy, nil
	}, conns, targets
}

func internalRule(id, pattern, target string) option.MITMURLRewriteRule {
	return option.MITMURLRewriteRule{ID: id, Pattern: pattern, Action: "header", Target: target}
}

func TestInternalRewriteToOtherOrigin(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{internalRule("i1", `^https://a/old/(.*)`, "https://b.example:8443/new/$1")},
		Headers: []option.MITMHeaderRewriteRule{{
			ID: "h1", Pattern: `^https://b\.example:8443/`, Scope: "request",
			Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-Seen", Value: "yes"}},
		}},
	})
	dial, conns, targets := internalDialer(t)
	m := capture.New(capture.Options{Enabled: true})
	options := rewriteOptions(m, set)
	options.Internal = dial
	h := newHarnessOptions(t, options)
	h.send("GET /old/p?q=1 HTTP/1.1\r\nHost: a\r\n\r\n")
	extConn := <-conns
	target := <-targets
	if target.Host != "b.example" || target.Port != 8443 || target.Scheme != "https" {
		t.Fatalf("target %+v", target)
	}
	extR := bufio.NewReader(extConn)
	expect(t, "internal", extR, "GET /new/p?q=1 HTTP/1.1\r\nHost: b.example:8443\r\nX-Seen: yes\r\n\r\n")
	// The regular upstream saw nothing.
	h.upstream.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := h.upstreamR.Peek(1); err == nil {
		t.Fatal("regular upstream received data")
	}
	h.upstream.SetReadDeadline(time.Time{})
	io.WriteString(extConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	// The next request goes to the regular upstream, whose connection is intact.
	h.send("GET /plain HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /plain HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	// The internal connection was dropped after its response.
	extConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extR.ReadByte(); err == nil {
		t.Fatal("internal connection not closed")
	}
	h.client.Close()
	h.wait()
	records := captured(t, m, 2)
	r := records[0]
	if r.Path != "/new/p?q=1" || len(r.Rewrites) != 2 || r.Rewrites[0].Kind != "url" || r.Rewrites[0].Action != "header" || r.Rewrites[0].Target != "https://b.example:8443/new/p?q=1" {
		t.Fatalf("record %+v", r)
	}
}

func TestInternalRewriteSameOriginReusesUpstream(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{internalRule("i1", `^https://a/old`, "https://A/new")},
	})
	dial, conns, _ := internalDialer(t)
	options := rewriteOptions(nil, set)
	options.Internal = dial
	h := newHarnessOptions(t, options)
	h.send("GET /old HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /new HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	select {
	case <-conns:
		t.Fatal("same origin dialed")
	default:
	}
	h.client.Close()
	h.wait()
}

func TestInternalRewriteFailureIs502(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{internalRule("i1", `^https://a/old`, "http://b.example/new")},
	})
	options := rewriteOptions(nil, set)
	options.Internal = func(context.Context, *rewrite.Internal) (net.Conn, error) { return nil, errors.New("refused") }
	h := newHarnessOptions(t, options)
	h.send("GET /old HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	h.upstream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := h.upstreamR.Peek(1); len(n) > 0 {
		t.Fatal("original host received the request")
	}
	h.wait()
}

func TestInternalRewriteWithoutDialerIs502(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{internalRule("i1", `^https://a/old`, "http://b.example/new")},
	})
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	h.send("GET /old HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectClient("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	h.wait()
}

func TestInternalRewriteThenBodyRule(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL:  []option.MITMURLRewriteRule{internalRule("i1", `^https://a/old`, "http://b.example/new")},
		Body: []option.MITMBodyRewriteRule{bodyRule("b1", `^http://b\.example/new`, "response", `hello`, `bye`)},
	})
	dial, conns, _ := internalDialer(t)
	options := rewriteOptions(nil, set)
	options.Internal = dial
	h := newHarnessOptions(t, options)
	h.send("GET /old HTTP/1.1\r\nHost: a\r\n\r\n")
	extConn := <-conns
	extR := bufio.NewReader(extConn)
	expect(t, "internal", extR, "GET /new HTTP/1.1\r\nHost: b.example\r\n\r\n")
	io.WriteString(extConn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbye")
	h.client.Close()
	h.wait()
}

func TestInternalRewriteDoesNotLoop(t *testing.T) {
	// The new URL matches the rule again; it must not be rewritten twice.
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{internalRule("i1", `^https?://[^/]+/`, "https://b.example/again")},
	})
	dial, conns, _ := internalDialer(t)
	options := rewriteOptions(nil, set)
	options.Internal = dial
	h := newHarnessOptions(t, options)
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	extConn := <-conns
	expect(t, "internal", bufio.NewReader(extConn), "GET /again HTTP/1.1\r\nHost: b.example\r\n\r\n")
	h.client.Close()
	extConn.Close()
}

func TestBodyBudgetIsTakenByActualBytes(t *testing.T) {
	// Leave room for about 1 MiB: unknown-length responses must not each claim the maximum.
	spare := int64(1 << 20)
	if !body.Buffering.Acquire(body.BufferingLimit - spare) {
		t.Skip("budget in use")
	}
	defer body.Buffering.Release(body.BufferingLimit - spare)
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	t.Run("group", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			t.Run("c", func(t *testing.T) {
				t.Parallel()
				m := capture.New(capture.Options{Enabled: true})
				h := newHarnessOptions(t, rewriteOptions(m, set))
				h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
				h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
				h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk("hello") + "0\r\n\r\n")
				h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbye")
				h.client.Close()
				h.wait()
				if hits := captured(t, m, 1)[0].Rewrites; len(hits) != 1 || hits[0].Action != "edit" {
					t.Errorf("hits %+v", hits)
				}
			})
		}
	})
	if used := body.Buffering.Used(); used != body.BufferingLimit-spare {
		t.Fatalf("budget leaked: %d", used-(body.BufferingLimit-spare))
	}
}

func TestBodyEditDropsTrailerAndIntegrityFields(t *testing.T) {
	set := compileSet(t, bodyOptions("", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	m := capture.New(capture.Options{Enabled: true})
	h := newHarnessOptions(t, rewriteOptions(m, set))
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\nRepr-Digest: sha-256=:abc=:\r\nContent-MD5: abc\r\n\r\n" + chunk("hello") + "0\r\nX-Sum: 1\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbye")
	h.client.Close()
	h.wait()
	changes := captured(t, m, 1)[0].Rewrites[0].Changes
	seen := map[string]bool{}
	for _, c := range changes {
		seen[c.Op+":"+c.Name] = true
	}
	for _, want := range []string{"delete:Repr-Digest", "delete:Content-MD5", "trailer-dropped:Trailer"} {
		if !seen[want] {
			t.Fatalf("missing %s in %+v", want, changes)
		}
	}
}

func TestInternalRewriteRecordsTargetScheme(t *testing.T) {
	set := compileSet(t, option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{internalRule("i1", `^https://a/old/(.*)`, "http://b.example:8080/new/$1")},
	})
	dial, conns, _ := internalDialer(t)
	m := capture.New(capture.Options{Enabled: true})
	options := rewriteOptions(m, set)
	options.Internal = dial
	h := newHarnessOptions(t, options)
	h.send("GET /old/p HTTP/1.1\r\nHost: a\r\n\r\n")
	extConn := <-conns
	expect(t, "internal", bufio.NewReader(extConn), "GET /new/p HTTP/1.1\r\nHost: b.example:8080\r\n\r\n")
	io.WriteString(extConn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	// The next request is an ordinary https one again.
	h.send("GET /plain HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /plain HTTP/1.1\r\nHost: a\r\n\r\n")
	h.reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.expectClient("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	h.client.Close()
	h.wait()
	records := captured(t, m, 2)
	if records[0].Scheme != "http" || records[0].Authority != "b.example:8080" || records[0].Rewrites[0].Target != "http://b.example:8080/new/p" {
		t.Fatalf("record %+v", records[0])
	}
	if records[1].Scheme != "https" {
		t.Fatalf("scheme %q", records[1].Scheme)
	}
}

func TestBodyLargeMessageWithinBudget(t *testing.T) {
	set := compileSet(t, bodyOptions("32MB", bodyRule("b1", `^https://a/`, "response", `hello`, `bye`)))
	h := newHarnessOptions(t, rewriteOptions(nil, set))
	const size = 28 << 20
	payload := strings.Repeat("a", size-5) + "hello"
	h.send("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	h.expectUpstream("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	go h.reply("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(size) + "\r\n\r\n" + payload)
	h.client.SetDeadline(time.Now().Add(30 * time.Second))
	resp, err := readResponse(h.clientR)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.body) != size-2 || !strings.HasSuffix(string(resp.body), "aabye") || resp.header["Content-Length"] != strconv.Itoa(size-2) {
		t.Fatalf("not rewritten: %d bytes, length %q", len(resp.body), resp.header["Content-Length"])
	}
	h.client.Close()
	h.wait()
}
