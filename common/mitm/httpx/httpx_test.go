package httpx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func readRequest(raw string) (*Request, error) {
	h := NewHeadReader(bufio.NewReader(strings.NewReader(raw)))
	req := &Request{}
	return req, h.ReadRequest(req)
}

func readResponse(raw string) (*Response, error) {
	h := NewHeadReader(bufio.NewReader(strings.NewReader(raw)))
	resp := &Response{}
	return resp, h.ReadResponse(resp)
}

func TestReadRequest(t *testing.T) {
	req, err := readRequest("\r\nGET /a?b=c HTTP/1.1\r\nHost: example.com\r\nX-Custom-CASE:  v1 \r\nx-custom-case:\tv2\r\nEmpty:\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "GET" || req.Target != "/a?b=c" || req.Proto != "HTTP/1.1" || req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		t.Fatalf("%+v", req)
	}
	want := Header{{"Host", "example.com"}, {"X-Custom-CASE", "v1"}, {"x-custom-case", "v2"}, {"Empty", ""}}
	if fmt.Sprint(req.Header) != fmt.Sprint(want) {
		t.Fatalf("header = %v", req.Header)
	}
	if req.Header.Get("x-CUSTOM-case") != "v1" || req.Header.Count("X-Custom-Case") != 2 {
		t.Fatal("case-insensitive lookup")
	}
}

func TestReadRequestErrors(t *testing.T) {
	long := strings.Repeat("a", 9000)
	manyFields := strings.Repeat("A: b\r\n", 129)
	for _, tc := range []struct {
		raw string
		err error
	}{
		{"", io.EOF},
		{"GET / HTTP/1.1\r\nHost: a\r\n", io.ErrUnexpectedEOF},
		{"GET / HTTP/1.1\nHost: a\r\n\r\n", ErrBareLF},
		{"GET / HTTP/1.1\r\nHost: a\n\r\n", ErrBareLF},
		{"GET / HTTP/1.1\r\nHost: a\r\n\n", ErrBareLF},
		{"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", ErrBareCR},
		{"GET /\r HTTP/1.1\r\n\r\n", ErrBareCR},
		{"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", ErrObsFold},
		{"GET / HTTP/1.1\r\nHo st: a\r\n\r\n", ErrMalformed},
		{"GET / HTTP/1.1\r\nHost : a\r\n\r\n", ErrMalformed},
		{"GET / HTTP/1.1\r\n: a\r\n\r\n", ErrMalformed},
		{"GET / HTTP/1.1\r\nNoColon\r\n\r\n", ErrMalformed},
		{"GET / HTTP/1.1\r\nA: b\x00c\r\n\r\n", ErrMalformed},
		{"G(T / HTTP/1.1\r\n\r\n", ErrMalformed},
		{"GET  / HTTP/1.1\r\n\r\n", ErrMalformed},
		{"GET / HTTP/1.1 \r\n\r\n", ErrMalformed},
		{"GET /\r\n\r\n", ErrMalformed},
		{"GET / HTTP/2.0\r\n\r\n", ErrVersion},
		{"GET / HTTP/1.10\r\n\r\n", ErrMalformed},
		{"GET /" + long + " HTTP/1.1\r\n\r\n", ErrStartLineTooLong},
		{"GET / HTTP/1.1\r\nA: " + strings.Repeat("b", 70000) + "\r\n\r\n", ErrHeaderTooLarge},
		{"GET / HTTP/1.1\r\n" + manyFields + "\r\n", ErrTooManyFields},
	} {
		_, err := readRequest(tc.raw)
		if !errors.Is(err, tc.err) {
			raw := tc.raw
			if len(raw) > 60 {
				raw = raw[:60]
			}
			t.Errorf("%q: err = %v, want %v", raw, err, tc.err)
		}
	}
	if _, err := readRequest("GET / HTTP/1.1\r\n" + strings.Repeat("A: b\r\n", 128) + "\r\n"); err != nil {
		t.Errorf("128 fields: %v", err)
	}
}

func TestReadResponse(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		code   int
		reason string
		ok     bool
	}{
		{"HTTP/1.1 200 OK\r\nA: b\r\n\r\n", 200, "OK", true},
		{"HTTP/1.0 404 Not  Found\r\n\r\n", 404, "Not  Found", true},
		{"HTTP/1.1 204 \r\n\r\n", 204, "", true},
		{"HTTP/1.1 204\r\n\r\n", 204, "", true},
		{"HTTP/1.1 20\r\n\r\n", 0, "", false},
		{"HTTP/1.1 2000 OK\r\n\r\n", 0, "", false},
		{"HTTP/1.1 099 X\r\n\r\n", 0, "", false},
		{"HTTP/1.1 abc OK\r\n\r\n", 0, "", false},
		{"HTTP/1.1 200 O\x01K\r\n\r\n", 0, "", false},
		{"\r\nHTTP/1.1 200 OK\r\n\r\n", 0, "", false},
		{"HTTP/3.0 200 OK\r\n\r\n", 0, "", false},
	} {
		resp, err := readResponse(tc.raw)
		if (err == nil) != tc.ok {
			t.Errorf("%q: err = %v", tc.raw, err)
			continue
		}
		if tc.ok && (resp.StatusCode != tc.code || resp.Reason != tc.reason) {
			t.Errorf("%q: %d %q", tc.raw, resp.StatusCode, resp.Reason)
		}
	}
}

func TestHeadReaderReuseAndPipelining(t *testing.T) {
	raw := "GET /1 HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\nGET /2 HTTP/1.1\r\nC: 3\r\n\r\n"
	h := NewHeadReader(bufio.NewReaderSize(strings.NewReader(raw), 16))
	var first, second Request
	if err := h.ReadRequest(&first); err != nil {
		t.Fatal(err)
	}
	if err := h.ReadRequest(&second); err != nil {
		t.Fatal(err)
	}
	if first.Target != "/1" || first.Header.Get("B") != "2" || second.Target != "/2" || second.Header.Get("C") != "3" {
		t.Fatalf("%+v %+v", first, second)
	}
	if err := h.ReadRequest(&second); err != io.EOF {
		t.Fatalf("err = %v", err)
	}
}

func TestRequestFraming(t *testing.T) {
	for _, tc := range []struct {
		header Header
		kind   BodyKind
		length int64
		err    error
	}{
		{nil, BodyNone, 0, nil},
		{Header{{"Content-Length", "10"}}, BodyLength, 10, nil},
		{Header{{"content-length", "0"}}, BodyNone, 0, nil},
		{Header{{"Content-Length", "10"}, {"Content-Length", "10"}}, BodyLength, 10, nil},
		{Header{{"Content-Length", "10, 10"}}, BodyLength, 10, nil},
		{Header{{"Content-Length", "10"}, {"Content-Length", "11"}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Content-Length", "10,11"}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Content-Length", "-1"}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Content-Length", "+1"}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Content-Length", ""}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Content-Length", "0x10"}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Content-Length", "1234567890123456789"}}, 0, 0, ErrInvalidContentLength},
		{Header{{"Transfer-Encoding", "chunked"}}, BodyChunked, 0, nil},
		{Header{{"Transfer-Encoding", "Chunked"}}, BodyChunked, 0, nil},
		{Header{{"Transfer-Encoding", "chunked"}, {"Content-Length", "5"}}, 0, 0, ErrContentLengthWithTransferEncoding},
		{Header{{"Transfer-Encoding", "gzip, chunked"}}, 0, 0, ErrUnsupportedTransferEncoding},
		{Header{{"Transfer-Encoding", "chunked, chunked"}}, 0, 0, ErrInvalidTransferEncoding},
		{Header{{"Transfer-Encoding", "chunked"}, {"Transfer-Encoding", "chunked"}}, 0, 0, ErrInvalidTransferEncoding},
		{Header{{"Transfer-Encoding", "xchunked"}}, 0, 0, ErrInvalidTransferEncoding},
		{Header{{"Transfer-Encoding", "gzip"}}, 0, 0, ErrInvalidTransferEncoding},
		{Header{{"Transfer-Encoding", ""}}, 0, 0, ErrInvalidTransferEncoding},
	} {
		framing, err := RequestFraming(&Request{ProtoMajor: 1, ProtoMinor: 1, Header: tc.header})
		if !errors.Is(err, tc.err) || err == nil && (framing.Kind != tc.kind || framing.Length != tc.length) {
			t.Errorf("%v: %+v %v", tc.header, framing, err)
		}
	}
}

// Transfer-Encoding below HTTP/1.1 is faulty framing; Content-Length alone stays valid.
func TestRequestFramingHTTP10(t *testing.T) {
	for _, header := range []Header{
		{{"Transfer-Encoding", "chunked"}},
		{{"Transfer-Encoding", "gzip"}},
		{{"Transfer-Encoding", "chunked"}, {"Content-Length", "5"}},
	} {
		_, err := RequestFraming(&Request{ProtoMajor: 1, ProtoMinor: 0, Header: header})
		if !errors.Is(err, ErrTransferEncodingHTTP10) {
			t.Errorf("%v: %v", header, err)
		}
	}
	framing, err := RequestFraming(&Request{ProtoMajor: 1, ProtoMinor: 0, Header: Header{{"Content-Length", "5"}}})
	if err != nil || framing.Kind != BodyLength || framing.Length != 5 {
		t.Errorf("HTTP/1.0 Content-Length: %+v %v", framing, err)
	}
}

func TestResponseFraming(t *testing.T) {
	cl := Header{{"Content-Length", "5"}}
	te := Header{{"Transfer-Encoding", "chunked"}}
	for _, tc := range []struct {
		method string
		code   int
		header Header
		kind   BodyKind
		err    error
	}{
		{"GET", 200, cl, BodyLength, nil},
		{"GET", 200, te, BodyChunked, nil},
		{"GET", 200, append(Header{{"Content-Length", "9"}}, te...), BodyChunked, nil},
		{"GET", 200, nil, BodyClose, nil},
		{"HEAD", 200, cl, BodyNone, nil},
		{"HEAD", 200, te, BodyNone, nil},
		{"GET", 100, nil, BodyNone, nil},
		{"GET", 101, nil, BodyNone, nil},
		{"GET", 204, cl, BodyNone, nil},
		{"GET", 304, cl, BodyNone, nil},
		{"CONNECT", 200, nil, BodyNone, nil},
		{"CONNECT", 200, cl, BodyNone, nil},
		{"CONNECT", 299, te, BodyNone, nil},
		{"CONNECT", 200, Header{{"Transfer-Encoding", "gzip"}}, BodyNone, nil},
		{"CONNECT", 407, cl, BodyLength, nil},
		{"CONNECT", 502, nil, BodyClose, nil},
		{"GET", 200, Header{{"Content-Length", "5"}, {"Content-Length", "6"}}, 0, ErrInvalidContentLength},
		{"GET", 200, Header{{"Transfer-Encoding", "gzip"}}, BodyClose, nil},
		{"GET", 200, Header{{"Transfer-Encoding", "chunked, chunked"}}, 0, ErrInvalidTransferEncoding},
	} {
		framing, err := ResponseFraming(tc.method, &Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: tc.code, Header: tc.header})
		if !errors.Is(err, tc.err) || err == nil && framing.Kind != tc.kind {
			t.Errorf("%s %d %v: %+v %v", tc.method, tc.code, tc.header, framing, err)
		}
	}
}

func TestChunkedReader(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		body string
		err  error
		rest string
	}{
		{"5\r\nhello\r\n0\r\n\r\nNEXT", "hello", nil, "NEXT"},
		{"5;ext=1\r\nhello\r\n6 ; a=\"b\"\r\n world\r\n0\r\n\r\n", "hello world", nil, ""},
		{"A\r\n0123456789\r\n0\r\nTrailer: x\r\nOther: y\r\n\r\nNEXT", "0123456789", nil, "NEXT"},
		{"5\r\nhello\r\n0\r\n", "hello", io.ErrUnexpectedEOF, ""},
		{"5\r\nhel", "hel", io.ErrUnexpectedEOF, ""},
		{"5\r\nhelloXX0\r\n\r\n", "hello", ErrChunkData, ""},
		{"5\nhello\r\n0\r\n\r\n", "", ErrChunkSizeLine, ""},
		{"x\r\n", "", ErrChunkSizeLine, ""},
		{"\r\n", "", ErrChunkSizeLine, ""},
		{"5x\r\nhello\r\n", "", ErrChunkSizeLine, ""},
		{"-5\r\n", "", ErrChunkSizeLine, ""},
		{"1000000000000000\r\n", "", ErrChunkSizeLine, ""},
		{"5;a\rb\r\nhello\r\n0\r\n\r\n", "", ErrChunkSizeLine, ""},
		{"0\r\nTrailer: x\n\r\n", "", ErrBareLF, ""},
		{"1;" + strings.Repeat("e", 5000) + "\r\nx\r\n0\r\n\r\n", "", ErrChunkSizeLine, ""},
	} {
		br := bufio.NewReader(strings.NewReader(tc.raw))
		body, err := io.ReadAll(NewChunkedReader(br))
		if !errors.Is(err, tc.err) || string(body) != tc.body {
			t.Errorf("%q: body %q err %v", tc.raw, body, err)
			continue
		}
		if tc.err == nil {
			rest, _ := io.ReadAll(br)
			if string(rest) != tc.rest {
				t.Errorf("%q: rest %q", tc.raw, rest)
			}
		}
	}
}

func TestChunkedRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	w := NewChunkedWriter(&buffer)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1000)
	for _, size := range []int{1, 15, 16, 255, 4096, len(payload) - 4383} {
		if _, err := w.Write(payload[:size]); err != nil {
			t.Fatal(err)
		}
		payload = payload[size:]
	}
	w.Write(nil)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buffer.Bytes(), []byte("1\r\n0\r\nf\r\n")) || !bytes.HasSuffix(buffer.Bytes(), []byte("\r\n0\r\n\r\n")) {
		t.Fatalf("encoding %q", buffer.Bytes()[:20])
	}
	body, err := io.ReadAll(NewChunkedReader(bufio.NewReader(&buffer)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, bytes.Repeat([]byte("0123456789abcdef"), 1000)) {
		t.Fatal("round trip mismatch")
	}
}

func TestHeaderEditing(t *testing.T) {
	h := Header{{"A", "1"}, {"b", "2"}, {"a", "3"}}
	h.Set("A", "x")
	if fmt.Sprint(h) != "[{A x} {b 2}]" {
		t.Fatal(h)
	}
	h.Set("C", "y")
	h.Del("B")
	if fmt.Sprint(h) != "[{A x} {C y}]" {
		t.Fatal(h)
	}
	if !h.Has("c") || h.Has("b") {
		t.Fatal("Has")
	}
}

func TestRemoveHopByHop(t *testing.T) {
	base := Header{
		{"Host", "a"},
		{"Connection", "keep-alive, X-Remove-Me"},
		{"Keep-Alive", "timeout=5"},
		{"x-remove-me", "1"},
		{"Proxy-Connection", "keep-alive"},
		{"TE", "trailers"},
		{"Trailer", "X"},
		{"Transfer-Encoding", "chunked"},
		{"Upgrade", "websocket"},
		{"connection", "Upgrade, Other"},
		{"Other", "o"},
		{"Accept", "*/*"},
	}
	got := RemoveHopByHop(append(Header(nil), base...), false)
	if fmt.Sprint(got) != "[{Host a} {Trailer X} {Accept */*}]" {
		t.Fatal(got)
	}
	got = RemoveHopByHop(append(Header(nil), base...), true)
	if fmt.Sprint(got) != "[{Host a} {Connection Upgrade} {Trailer X} {Upgrade websocket} {Accept */*}]" {
		t.Fatal(got)
	}
	got = RemoveHopByHop(Header{{"connection", "upgrade"}, {"Upgrade", "websocket"}}, true)
	if fmt.Sprint(got) != "[{connection upgrade} {Upgrade websocket}]" {
		t.Fatal(got)
	}
}

// Connection cannot nominate the fields the framing and routing were decided from.
func TestRemoveHopByHopKeepsProtectedFields(t *testing.T) {
	for _, keepUpgrade := range []bool{false, true} {
		got := RemoveHopByHop(Header{
			{"Host", "a"},
			{"Connection", "content-length, HOST, transfer-encoding, X-Drop"},
			{"Content-Length", "5"},
			{"Transfer-Encoding", "chunked"},
			{"X-Drop", "1"},
		}, keepUpgrade)
		want := "[{Host a} {Content-Length 5}]"
		if keepUpgrade {
			want = "[{Host a} {Connection Upgrade} {Content-Length 5}]"
		}
		if fmt.Sprint(got) != want {
			t.Errorf("keepUpgrade=%v: %v", keepUpgrade, got)
		}
	}
}

func TestHasToken(t *testing.T) {
	h := Header{{"Connection", "keep-alive , Upgrade"}, {"connection", "close"}}
	for token, want := range map[string]bool{"upgrade": true, "CLOSE": true, "keep-alive": true, "keep": false, "": false} {
		if h.HasToken("Connection", token) != want {
			t.Errorf("%q", token)
		}
	}
}

func TestWriteHead(t *testing.T) {
	var buffer bytes.Buffer
	w := bufio.NewWriter(&buffer)
	WriteRequestHead(w, &Request{Method: "POST", Target: "/x", Proto: "HTTP/1.1", Header: Header{{"Host", "a"}, {"x-B", "1"}}})
	WriteResponseHead(w, &Response{Proto: "HTTP/1.1", StatusCode: 204, Header: Header{{"A", ""}}})
	w.Flush()
	want := "POST /x HTTP/1.1\r\nHost: a\r\nx-B: 1\r\n\r\nHTTP/1.1 204 \r\nA: \r\n\r\n"
	if buffer.String() != want {
		t.Fatalf("%q", buffer.String())
	}
}

func TestReadAllocs(t *testing.T) {
	raw := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"
	reader := strings.NewReader(raw)
	br := bufio.NewReader(reader)
	h := NewHeadReader(br)
	var req Request
	allocs := testing.AllocsPerRun(100, func() {
		reader.Reset(raw)
		br.Reset(reader)
		if err := h.ReadRequest(&req); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("ReadRequest allocs = %v, want 1", allocs)
	}
}
