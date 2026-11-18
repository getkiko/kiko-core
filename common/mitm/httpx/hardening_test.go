package httpx

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// requestStatus reads raw as a request and returns the status a proxy answers it with, or 0
// when it is accepted.
func requestStatus(raw string) (int, error) {
	req, err := readRequest(raw)
	if err == nil {
		err = CheckHost(req)
	}
	if err == nil {
		_, err = RequestFraming(req)
	}
	if err == nil {
		return 0, nil
	}
	return RequestErrorStatus(err), err
}

func TestRequestErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		status int
	}{
		{"GET / HTTP/1.1\r\nHost: a\r\n\r\n", 0},
		{"GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\nHost: a\r\n\r\n", 414},
		{"GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("a", 70000) + "\r\n\r\n", 431},
		{"GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("A: b\r\n", 129) + "\r\n", 431},
		{"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 505},
		{"GET / HTTP/0.9\r\nHost: a\r\n\r\n", 505},
		{"GET / HTTP/1.x\r\nHost: a\r\n\r\n", 400},
		{"GET / HTTP/11\r\nHost: a\r\n\r\n", 400},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n", 501},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", 400},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 400},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", 400},
		{"POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", 400},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", 400},
		{"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", 400},
		{"GET / HTTP/1.1\r\n\r\n", 400},
		{"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\nContent-Length: 2\r\n\r\n", 400},
	} {
		status, err := requestStatus(tc.raw)
		if status != tc.status {
			name := tc.raw
			if len(name) > 60 {
				name = name[:60]
			}
			t.Errorf("%q: status %d (%v), want %d", name, status, err, tc.status)
		}
	}
}

// Every Transfer-Encoding spelling a peer could disagree on is either exactly chunked or
// rejected (RFC 9112 sections 6.1 and 6.3).
func TestRequestTransferEncodingVariants(t *testing.T) {
	for _, tc := range []struct {
		values []string
		err    error
	}{
		{[]string{"chunked"}, nil},
		{[]string{"CHUNKED"}, nil},
		{[]string{" chunked"}, nil},
		{[]string{"chunked\t"}, nil},
		{[]string{", chunked,"}, nil},
		{[]string{"chunked", ""}, nil},
		{[]string{"xchunked"}, ErrInvalidTransferEncoding},
		{[]string{"chunkedx"}, ErrInvalidTransferEncoding},
		{[]string{"chunked;x=1"}, ErrInvalidTransferEncoding},
		{[]string{"\"chunked\""}, ErrInvalidTransferEncoding},
		{[]string{"chun ked"}, ErrInvalidTransferEncoding},
		{[]string{"chunked, chunked"}, ErrInvalidTransferEncoding},
		{[]string{"chunked", "chunked"}, ErrInvalidTransferEncoding},
		{[]string{"chunked, identity"}, ErrInvalidTransferEncoding},
		{[]string{"identity"}, ErrInvalidTransferEncoding},
		{[]string{""}, ErrInvalidTransferEncoding},
		{[]string{","}, ErrInvalidTransferEncoding},
		{[]string{"@, chunked"}, ErrInvalidTransferEncoding},
		{[]string{"gzip, chunked"}, ErrUnsupportedTransferEncoding},
		{[]string{"gzip;q=1 ,chunked"}, ErrUnsupportedTransferEncoding},
		{[]string{"gzip", "chunked"}, ErrUnsupportedTransferEncoding},
	} {
		var header Header
		for _, value := range tc.values {
			header = append(header, Field{"Transfer-Encoding", value})
		}
		framing, err := RequestFraming(&Request{Method: "POST", ProtoMajor: 1, ProtoMinor: 1, Header: header})
		if !errors.Is(err, tc.err) || err == nil && framing.Kind != BodyChunked {
			t.Errorf("%q: %+v %v", tc.values, framing, err)
		}
	}
}

func TestResponseFramingCodings(t *testing.T) {
	for _, tc := range []struct {
		proto   int // minor version
		header  Header
		kind    BodyKind
		codings string
		err     error
	}{
		{1, Header{{"Transfer-Encoding", "chunked"}}, BodyChunked, "", nil},
		{1, Header{{"Transfer-Encoding", "gzip, chunked"}}, BodyChunked, "gzip", nil},
		{1, Header{{"Transfer-Encoding", "br,gzip ,chunked"}}, BodyChunked, "br, gzip", nil},
		{1, Header{{"Transfer-Encoding", "gzip"}, {"Transfer-Encoding", "chunked"}}, BodyChunked, "gzip", nil},
		{1, Header{{"Transfer-Encoding", "gzip, chunked"}, {"Content-Length", "3"}}, BodyChunked, "gzip", nil},
		{1, Header{{"Transfer-Encoding", "gzip"}}, BodyClose, "gzip", nil},
		{1, Header{{"Transfer-Encoding", "chunked, gzip"}}, BodyClose, "chunked, gzip", nil},
		{1, Header{{"Transfer-Encoding", "chunked"}, {"Transfer-Encoding", "gzip"}}, BodyClose, "chunked, gzip", nil},
		{1, Header{{"Transfer-Encoding", "gzip"}, {"Content-Length", "3"}}, BodyClose, "gzip", nil},
		{1, Header{{"Transfer-Encoding", "chunked, chunked"}}, 0, "", ErrInvalidTransferEncoding},
		{1, Header{{"Transfer-Encoding", "x y"}}, 0, "", ErrInvalidTransferEncoding},
		{1, Header{{"Transfer-Encoding", ""}}, 0, "", ErrInvalidTransferEncoding},
		// HTTP/1.0: faulty framing, delimited by close whatever the fields say.
		{0, Header{{"Transfer-Encoding", "chunked"}}, BodyClose, "chunked", nil},
		{0, Header{{"Transfer-Encoding", "chunked"}, {"Content-Length", "3"}}, BodyClose, "chunked", nil},
		{0, Header{{"Content-Length", "3"}}, BodyLength, "", nil},
	} {
		resp := &Response{ProtoMajor: 1, ProtoMinor: tc.proto, StatusCode: 200, Header: tc.header}
		framing, err := ResponseFraming("GET", resp)
		if !errors.Is(err, tc.err) || err == nil && (framing.Kind != tc.kind || framing.Codings != tc.codings) {
			t.Errorf("1.%d %v: %+v %v", tc.proto, tc.header, framing, err)
		}
	}
}

// Bodiless responses still carry a valid Content-Length or none.
func TestBodilessResponseContentLength(t *testing.T) {
	for _, tc := range []struct {
		method string
		code   int
	}{{"HEAD", 200}, {"GET", 204}, {"GET", 304}, {"GET", 100}, {"CONNECT", 200}} {
		for _, value := range []string{"5, 6", "-1", "x"} {
			resp := &Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: tc.code, Header: Header{{"Content-Length", value}}}
			if _, err := ResponseFraming(tc.method, resp); !errors.Is(err, ErrInvalidContentLength) {
				t.Errorf("%s %d %q: %v", tc.method, tc.code, value, err)
			}
		}
		resp := &Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: tc.code, Header: Header{{"Content-Length", "10"}}}
		if framing, err := ResponseFraming(tc.method, resp); err != nil || framing.Kind != BodyNone {
			t.Errorf("%s %d: %+v %v", tc.method, tc.code, framing, err)
		}
		// Beside Transfer-Encoding the length is overridden, not validated; h1 drops it.
		resp = &Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: tc.code, Header: Header{{"Transfer-Encoding", "chunked"}, {"Content-Length", "5, 6"}}}
		if framing, err := ResponseFraming(tc.method, resp); err != nil || framing.Kind != BodyNone {
			t.Errorf("%s %d with Transfer-Encoding: %+v %v", tc.method, tc.code, framing, err)
		}
	}
}

func TestCheckHost(t *testing.T) {
	for _, tc := range []struct {
		raw string
		err error
	}{
		{"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", nil},
		{"GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n", nil},
		{"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n", nil},
		{"GET / HTTP/1.1\r\nhost: a\r\n\r\n", nil},
		{"GET / HTTP/1.1\r\nHost:\r\n\r\n", nil},
		{"GET http://a/b HTTP/1.1\r\nHost: other\r\n\r\n", nil},
		{"GET / HTTP/1.0\r\n\r\n", nil},
		{"GET / HTTP/1.1\r\n\r\n", ErrMissingHost},
		{"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n", ErrMultipleHost},
		{"GET / HTTP/1.0\r\nHost: a\r\nhost: b\r\n\r\n", ErrMultipleHost},
		{"GET / HTTP/1.1\r\nHost: a b\r\n\r\n", ErrInvalidHost},
		{"GET / HTTP/1.1\r\nHost: a,b\r\n\r\n", ErrInvalidHost},
		{"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n", ErrInvalidHost},
		{"GET / HTTP/1.1\r\nHost: a\"b\r\n\r\n", ErrInvalidHost},
		{"GET / HTTP/1.1\r\nHost: a\x01\r\n\r\n", ErrMalformed},
	} {
		req, err := readRequest(tc.raw)
		if err == nil {
			err = CheckHost(req)
		}
		if !errors.Is(err, tc.err) {
			t.Errorf("%q: %v, want %v", tc.raw, err, tc.err)
		}
	}
}

func TestUpgradeAccepted(t *testing.T) {
	request := Header{{"Upgrade", "websocket, foo/2"}, {"Upgrade", "bar"}}
	for _, tc := range []struct {
		response Header
		ok       bool
	}{
		{Header{{"Upgrade", "websocket"}}, true},
		{Header{{"Upgrade", "WebSocket"}}, true},
		{Header{{"Upgrade", "foo/2, bar"}}, true},
		{Header{{"Upgrade", "h2c"}}, false},
		{Header{{"Upgrade", "websocket, h2c"}}, false},
		{Header{{"Upgrade", ""}}, false},
		{nil, false},
	} {
		if got := UpgradeAccepted(request, tc.response); got != tc.ok {
			t.Errorf("%v: %v", tc.response, got)
		}
	}
}

func TestFilterTrailer(t *testing.T) {
	h := Header{
		{"X-Checksum", "1"}, {"Content-Length", "5"}, {"transfer-encoding", "chunked"},
		{"Host", "a"}, {"Authorization", "x"}, {"Set-Cookie", "a=b"}, {"Connection", "close"},
		{"Grpc-Status", "0"}, {"Content-Type", "x"}, {"Trailer", "x"},
	}
	got := FilterTrailer(h)
	if fmt.Sprint(got) != "[{X-Checksum 1} {Grpc-Status 0}]" {
		t.Fatal(got)
	}
	if FilterTrailer(nil) != nil {
		t.Fatal("nil")
	}
}

func TestChunkedReaderTrailer(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		trailer string
		err     error
	}{
		{"3\r\nabc\r\n0\r\n\r\n", "[]", nil},
		{"3\r\nabc\r\n0\r\nX: 1\r\ny:\t2 \r\n\r\nNEXT", "[{X 1} {y 2}]", nil},
		{"0\r\nX: 1\r\n folded\r\n\r\n", "", ErrObsFold},
		{"0\r\nX : 1\r\n\r\n", "", ErrMalformed},
		{"0\r\nX: a\x00b\r\n\r\n", "", ErrMalformed},
		{"0\r\nX: a\rb\r\n\r\n", "", ErrBareCR},
		{"0\r\nX: 1\n\r\n", "", ErrBareLF},
		{"0\r\nX: 1\r\n", "", io.ErrUnexpectedEOF},
		{"0\r\n" + strings.Repeat("A: b\r\n", 129) + "\r\n", "", ErrTooManyFields},
		{"0\r\nX: " + strings.Repeat("a", 70000) + "\r\n\r\n", "", ErrHeaderTooLarge},
	} {
		c := NewChunkedReader(bufio.NewReader(strings.NewReader(tc.raw)))
		if c.Trailer() != nil {
			t.Fatal("trailer before EOF")
		}
		_, err := io.ReadAll(c)
		if !errors.Is(err, tc.err) {
			t.Errorf("%.40q: %v, want %v", tc.raw, err, tc.err)
			continue
		}
		if err == nil && fmt.Sprint(c.Trailer()) != tc.trailer {
			t.Errorf("%.40q: trailer %v", tc.raw, c.Trailer())
		}
		if err != nil && c.Trailer() != nil {
			t.Errorf("%.40q: trailer after error", tc.raw)
		}
	}
}

// The reader keeps its trailer storage across Reset, and a body without trailer fields does
// not allocate.
func TestChunkedReaderTrailerReuse(t *testing.T) {
	const withTrailer = "3\r\nabc\r\n0\r\nX: 1\r\n\r\n"
	const without = "3\r\nabc\r\n0\r\n\r\n"
	source := strings.NewReader(withTrailer)
	br := bufio.NewReader(source)
	var c ChunkedReader
	buffer := make([]byte, 64)
	read := func(raw string) {
		source.Reset(raw)
		br.Reset(source)
		c.Reset(br)
		for {
			_, err := c.Read(buffer)
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	read(withTrailer)
	if fmt.Sprint(c.Trailer()) != "[{X 1}]" {
		t.Fatal(c.Trailer())
	}
	read(without)
	if len(c.Trailer()) != 0 {
		t.Fatal(c.Trailer())
	}
	if allocs := testing.AllocsPerRun(100, func() { read(without) }); allocs != 0 {
		t.Fatalf("allocs without trailer = %v", allocs)
	}
	if allocs := testing.AllocsPerRun(100, func() { read(withTrailer) }); allocs > 1 {
		t.Fatalf("allocs with trailer = %v", allocs)
	}
}

// Field lines that differ from the grammar only by whitespace, control characters or line
// endings are rejected (RFC 9112 sections 2.2 and 5).
func TestFieldLineVariants(t *testing.T) {
	for _, line := range []string{
		"Content-Length : 5",
		"Content-Length\t: 5",
		" Content-Length: 5",
		"Content-Length: 5\x00",
		"Content-Length: \x7f5",
		"Content-Length: 5\x0b",
		"Transfer-Encoding: chunked\x0c",
		"X: a\x1bb",
	} {
		_, err := readRequest("POST / HTTP/1.1\r\nHost: a\r\n" + line + "\r\n\r\n")
		if err == nil {
			t.Errorf("%q accepted", line)
		}
	}
	for _, value := range []string{"5 ", "\t5", " 5\t"} {
		req, err := readRequest("POST / HTTP/1.1\r\nHost: a\r\nContent-Length:" + value + "\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		if length, err := ContentLength(req.Header); err != nil || length != 5 {
			t.Errorf("%q: %d %v", value, length, err)
		}
	}
	for _, value := range []string{"5 5", "5;", "05x", "١", "5 "} {
		req, err := readRequest("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: " + value + "\r\n\r\n")
		if err != nil {
			continue
		}
		if _, err := ContentLength(req.Header); err == nil {
			t.Errorf("Content-Length %q accepted", value)
		}
	}
}

func TestChunkSizeVariants(t *testing.T) {
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{"fffffffffffffff\r\n", true}, // 15 digits fit; the body is truncated afterwards
		{"0000000000000000\r\n", false},
		{"ffffffffffffffff\r\n", false},
		{"5 \r\nhello\r\n0\r\n\r\n", true},
		{"5\t;e\r\nhello\r\n0\r\n\r\n", true},
		{" 5\r\nhello\r\n0\r\n\r\n", false},
		{"0x5\r\nhello\r\n0\r\n\r\n", false},
		{"5;e\nhello\r\n0\r\n\r\n", false},
		{"5;e=\"\r\"\r\nhello\r\n0\r\n\r\n", false},
		{"5\r\nhello\n0\r\n\r\n", false},
		{"5\r\nhello0\r\n\r\n", false},
		{"+5\r\nhello\r\n0\r\n\r\n", false},
		// Chunk extensions (RFC 9112 section 7.1.1).
		{"5;a\r\nhello\r\n0\r\n\r\n", true},
		{"5 ; a = b ;c\r\nhello\r\n0\r\n\r\n", true},
		{"5;a=\"x;y\\\"z\"\r\nhello\r\n0\r\n\r\n", true},
		{"5;a=\"\"\r\nhello\r\n0\r\n\r\n", true},
		{"5;a=\"x\r\nhello\r\n0\r\n\r\n", false},
		{"5;a=\"x\\\"\r\nhello\r\n0\r\n\r\n", false},
		{"5;\r\nhello\r\n0\r\n\r\n", false},
		{"5;=b\r\nhello\r\n0\r\n\r\n", false},
		{"5;a=\r\nhello\r\n0\r\n\r\n", false},
		{"5;a=b c\r\nhello\r\n0\r\n\r\n", false},
		{"5;a\x00\r\nhello\r\n0\r\n\r\n", false},
		{"5;a=\"\x01\"\r\nhello\r\n0\r\n\r\n", false},
		{"5;a;;b\r\nhello\r\n0\r\n\r\n", false},
	} {
		_, err := io.ReadAll(NewChunkedReader(bufio.NewReader(strings.NewReader(tc.raw))))
		if tc.ok && err != nil && err != io.ErrUnexpectedEOF || !tc.ok && (err == nil || err == io.ErrUnexpectedEOF) {
			t.Errorf("%q: %v", tc.raw, err)
		}
	}
}
