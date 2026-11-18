package httpx

import (
	"bufio"
	"bytes"
	"io"
	"net/http/httputil"
	"regexp"
	"strings"
	"testing"
)

// smuggleSeeds are request streams from the h1 smuggling table, used as fuzz seeds and as the
// hand-written part of the differential corpus.
var smuggleSeeds = []string{
	"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
	"\r\n\r\nGET /1 HTTP/1.1\r\nHost: a\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 4\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 2\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0, 0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length:  5\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\nhello",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \"chunked\"\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\t\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: CHUNKED\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: , chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\n chunked\r\n\r\n",
	"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nX Y: a\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nX\x01: a\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nX: a\rTransfer-Encoding: chunked\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nX: a\nTransfer-Encoding: chunked\r\n\r\n",
	"GET / HTTP/1.1\nHost: a\n\n",
	"GET /\r HTTP/1.1\r\nHost: a\r\n\r\n",
	"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
	"GET\t/\tHTTP/1.1\r\nHost: a\r\n\r\n",
	"GET / HTTP/2.0\r\nHost: a\r\n\r\n",
	"GET / HTTP/1.1\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
	"GET http://b/x HTTP/1.1\r\nHost: a\r\n\r\n",
	"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
	"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nConnection: content-length\r\nContent-Length: 5\r\n\r\nhello",
	"GET /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;a=b;c=\"d;e\"\r\nhello\r\n0\r\nX-T: 1\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;a=\"x\r\nhello\r\n0\r\n\r\n",
	"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n",
}

// responseSeeds are response heads exercising the framing rules.
var responseSeeds = []string{
	"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	"HTTP/1.1 200 OK\r\n\r\nclose-delimited",
	"HTTP/1.1 200\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
	"HTTP/1.1 200 OK\r\nContent-Length: 0, 0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\nhello",
	"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
	"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
	"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
	"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
	"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n folded\r\n\r\n",
	"HTTP/2.0 200 OK\r\n\r\n",
	"HTTP/1.1 099 Low\r\n\r\n",
	"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n",
}

// chunkedSeeds are chunked bodies, valid and not.
var chunkedSeeds = []string{
	"5\r\nhello\r\n0\r\n\r\n",
	"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
	"5;a=b;c=\"d;e\"\r\nhello\r\n0\r\nX-T: 1\r\nY: 2\r\n\r\n",
	"5 ;a\r\nhello\r\n0\r\n\r\n",
	"0x5\r\nhello\r\n0\r\n\r\n",
	" 5\r\nhello\r\n0\r\n\r\n",
	"00000000000000005\r\nhello\r\n0\r\n\r\n",
	"fffffffffffffff\r\nhello\r\n0\r\n\r\n",
	"-5\r\nhello\r\n0\r\n\r\n",
	"5\nhello\r\n0\r\n\r\n",
	"5;a\rb\r\nhello\r\n0\r\n\r\n",
	"5;a=\"x\r\nhello\r\n0\r\n\r\n",
	"5\r\nhello0\r\n\r\n",
	"5\r\nhelloXX\r\n0\r\n\r\n",
	"5\r\nhello\r\n0\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n",
	"5\r\nhello\r\n0\r\nX: a\r\n b\r\n\r\n",
	"5\r\nhello\r\n0\r\nX: a\n\r\n",
	"0\r\n\r\n",
	"0\r\n",
}

var fuzzLimits = Limits{StartLine: 256, Header: 1024, Fields: 16}

func isTchar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTchar(s[i]) {
			return false
		}
	}
	return true
}

// checkHeader verifies an accepted header independently of the parser: tokens for names,
// trimmed values without CTLs, and the limits.
func checkHeader(t *testing.T, header Header, limits Limits) {
	t.Helper()
	if len(header) > limits.Fields {
		t.Fatalf("%d fields over the limit %d", len(header), limits.Fields)
	}
	total := 2
	for _, f := range header {
		if !isToken(f.Name) {
			t.Fatalf("field name %q is not a token", f.Name)
		}
		if strings.Trim(f.Value, " \t") != f.Value {
			t.Fatalf("field value %q not trimmed", f.Value)
		}
		for i := 0; i < len(f.Value); i++ {
			if c := f.Value[i]; c != '\t' && (c < 0x20 || c == 0x7f) {
				t.Fatalf("field value %q holds CTL %#x", f.Value, c)
			}
		}
		// The wire line was at least "Name:Value\r\n".
		total += len(f.Name) + 1 + len(f.Value) + 2
	}
	if total > limits.Header {
		t.Fatalf("header section of at least %d bytes over the limit %d", total, limits.Header)
	}
}

func sameHeader(a, b Header) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// skipBody consumes the body framed by framing so the next message can be read.
func skipBody(r *bufio.Reader, framing Framing) bool {
	switch framing.Kind {
	case BodyLength:
		_, err := r.Discard(int(min(framing.Length, 1<<20)))
		return err == nil && framing.Length <= 1<<20
	case BodyChunked:
		_, err := io.Copy(io.Discard, NewChunkedReader(r))
		return err == nil
	case BodyClose:
		return false
	}
	return true
}

func FuzzReadRequest(f *testing.F) {
	for _, seed := range smuggleSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// A minimum-size buffer exercises the ErrBufferFull paths.
		reader := bufio.NewReaderSize(bytes.NewReader(data), 16)
		head := HeadReader{Reader: reader, Limits: fuzzLimits}
		var req Request
		for range 4 {
			if err := head.ReadRequest(&req); err != nil {
				return
			}
			if !isToken(req.Method) || req.Target == "" || strings.ContainsAny(req.Target, " \t\r\n\x00") || req.ProtoMajor != 1 {
				t.Fatalf("accepted request line %q %q %q", req.Method, req.Target, req.Proto)
			}
			if lineLength := len(req.Method) + len(req.Target) + len(req.Proto) + 4; lineLength > fuzzLimits.StartLine {
				t.Fatalf("request line of %d bytes over the limit", lineLength)
			}
			checkHeader(t, req.Header, fuzzLimits)
			framing, framingErr := RequestFraming(&req)

			// An accepted head written back out parses to the same fields and framing.
			var out bytes.Buffer
			w := bufio.NewWriter(&out)
			if err := WriteRequestHead(w, &req); err != nil {
				t.Fatal(err)
			}
			w.Flush()
			var again Request
			reparse := HeadReader{Reader: bufio.NewReader(bytes.NewReader(out.Bytes())), Limits: DefaultLimits}
			if err := reparse.ReadRequest(&again); err != nil {
				t.Fatalf("re-serialized head %q rejected: %v", out.Bytes(), err)
			}
			if again.Method != req.Method || again.Target != req.Target || again.Proto != req.Proto || again.ProtoMinor != req.ProtoMinor || !sameHeader(again.Header, req.Header) {
				t.Fatalf("round trip changed the head:\n%+v\n%+v", req, again)
			}
			againFraming, againErr := RequestFraming(&again)
			if againFraming != framing || errString(againErr) != errString(framingErr) {
				t.Fatalf("round trip changed the framing: %+v %v -> %+v %v", framing, framingErr, againFraming, againErr)
			}
			if framingErr != nil {
				return
			}
			if framing.Kind == BodyClose || framing.Kind == BodyLength && framing.Length <= 0 {
				t.Fatalf("request framing %+v", framing)
			}
			if !skipBody(reader, framing) {
				return
			}
		}
	})
}

func FuzzReadResponse(f *testing.F) {
	for _, seed := range responseSeeds {
		f.Add([]byte(seed), uint8(0))
	}
	f.Fuzz(func(t *testing.T, data []byte, methodIndex uint8) {
		method := [...]string{"GET", "HEAD", "CONNECT", "POST"}[methodIndex%4]
		reader := bufio.NewReaderSize(bytes.NewReader(data), 16)
		head := HeadReader{Reader: reader, Limits: fuzzLimits}
		var resp Response
		for range 4 {
			if err := head.ReadResponse(&resp); err != nil {
				return
			}
			if resp.ProtoMajor != 1 || resp.StatusCode < 100 || resp.StatusCode > 999 {
				t.Fatalf("accepted status line %q %d", resp.Proto, resp.StatusCode)
			}
			if lineLength := len(resp.Proto) + 5 + len(resp.Reason) + 2; lineLength > fuzzLimits.StartLine+1 {
				t.Fatalf("status line of %d bytes over the limit", lineLength)
			}
			checkHeader(t, resp.Header, fuzzLimits)
			framing, framingErr := ResponseFraming(method, &resp)

			var out bytes.Buffer
			w := bufio.NewWriter(&out)
			if err := WriteResponseHead(w, &resp); err != nil {
				t.Fatal(err)
			}
			w.Flush()
			var again Response
			reparse := HeadReader{Reader: bufio.NewReader(bytes.NewReader(out.Bytes())), Limits: DefaultLimits}
			if err := reparse.ReadResponse(&again); err != nil {
				t.Fatalf("re-serialized head %q rejected: %v", out.Bytes(), err)
			}
			if again.Proto != resp.Proto || again.StatusCode != resp.StatusCode || again.Reason != resp.Reason || !sameHeader(again.Header, resp.Header) {
				t.Fatalf("round trip changed the head:\n%+v\n%+v", resp, again)
			}
			againFraming, againErr := ResponseFraming(method, &again)
			if againFraming != framing || errString(againErr) != errString(framingErr) {
				t.Fatalf("round trip changed the framing: %+v %v -> %+v %v", framing, framingErr, againFraming, againErr)
			}
			if framingErr != nil {
				return
			}
			noBody := method == "HEAD" || resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 || method == "CONNECT" && resp.StatusCode < 300
			if noBody && framing.Kind != BodyNone {
				t.Fatalf("%s %d framed as %+v", method, resp.StatusCode, framing)
			}
			if framing.Kind == BodyLength && framing.Length <= 0 {
				t.Fatalf("response framing %+v", framing)
			}
			checkCodings(t, method, &resp, framing)
			if !skipBody(reader, framing) {
				return
			}
		}
	})
}

// checkCodings verifies Framing.Codings: the codings before a final chunked for BodyChunked,
// which declared again with chunked frame the same way; the received list for BodyClose; empty
// otherwise.
func checkCodings(t *testing.T, method string, resp *Response, framing Framing) {
	t.Helper()
	te := resp.Header.Has("Transfer-Encoding")
	switch framing.Kind {
	case BodyChunked:
		if !te {
			t.Fatalf("chunked framing without Transfer-Encoding")
		}
		if framing.Codings == "" {
			return
		}
		redeclared := Response{Proto: resp.Proto, ProtoMajor: resp.ProtoMajor, ProtoMinor: resp.ProtoMinor, StatusCode: resp.StatusCode,
			Header: Header{{Name: "Transfer-Encoding", Value: framing.Codings + ", chunked"}}}
		again, err := ResponseFraming(method, &redeclared)
		if err != nil || again != framing {
			t.Fatalf("Codings %q declared again frame as %+v %v, want %+v", framing.Codings, again, err, framing)
		}
	case BodyClose:
		if !te && framing.Codings != "" || strings.ContainsAny(framing.Codings, "\r\n") {
			t.Fatalf("close-delimited Codings %q with Transfer-Encoding %v", framing.Codings, te)
		}
	default:
		if framing.Codings != "" {
			t.Fatalf("Codings %q on %+v", framing.Codings, framing)
		}
	}
}

// overheadErr is net/http's limit on chunk extensions relative to data.
const overheadErr = "chunked encoding contains too much non-data"

// bwsBeforeExtension finds a chunk size followed by whitespace and an extension, which RFC 9112
// section 7.1.1 allows (BWS) and net/http rejects.
var bwsBeforeExtension = regexp.MustCompile(`(?m)^[0-9a-fA-F]+[ \t]+;`)

func FuzzChunked(f *testing.F) {
	for _, seed := range chunkedSeeds {
		f.Add([]byte(seed), uint8(7))
	}
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		// h1 decodes from a 4096-byte bufio.Reader, the chunk size line limit.
		reader := bufio.NewReaderSize(bytes.NewReader(data), MaxChunkSizeLine)
		chunked := NewChunkedReader(reader)
		readSize := int(step%64) + 1
		var decoded []byte
		buffer := make([]byte, readSize)
		var err error
		for {
			var n int
			n, err = chunked.Read(buffer)
			decoded = append(decoded, buffer[:n]...)
			if n > readSize {
				t.Fatalf("read %d into %d bytes", n, readSize)
			}
			if err != nil {
				break
			}
		}
		if err != io.EOF {
			return
		}
		if len(decoded) > len(data) {
			t.Fatalf("decoded %d bytes from %d", len(decoded), len(data))
		}
		if n, err := chunked.Read(buffer); n != 0 || err != io.EOF {
			t.Fatalf("read after the end: %d %v", n, err)
		}
		trailer := append(Header(nil), chunked.Trailer()...)
		checkHeader(t, trailer, DefaultLimits)
		written := 2
		for _, f := range trailer {
			written += len(f.Name) + 2 + len(f.Value) + 2
		}
		if written > DefaultLimits.Header {
			// "Name:v" grows to "Name: v" when written; keep the round trip within the limit.
			trailer = nil
		}

		// net/http's decoder agrees on the data wherever it accepts the body.
		reference, refErr := io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(data)))
		if refErr != nil {
			if !strings.Contains(refErr.Error(), overheadErr) && !bwsBeforeExtension.Match(data) {
				t.Fatalf("accepted %q, net/http rejects it: %v", data, refErr)
			}
		} else if !bytes.Equal(reference, decoded) {
			t.Fatalf("decoded %q, net/http %q", decoded, reference)
		}

		// Re-encoding in step-sized writes decodes to the same bytes.
		var encoded bytes.Buffer
		writer := NewChunkedWriter(&encoded)
		for rest := decoded; len(rest) > 0; {
			n := min(len(rest), int(step)+1)
			if _, err := writer.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		// The last chunk with the trailer section, as h1 writes it.
		encoded.WriteString("0\r\n")
		bw := bufio.NewWriter(&encoded)
		if err := WriteHeader(bw, trailer); err != nil {
			t.Fatal(err)
		}
		bw.Flush()
		// Decode with the reader used above, so Reset must not leak the old trailer.
		chunked.Reset(bufio.NewReader(&encoded))
		again, err := io.ReadAll(chunked)
		if err != nil || !bytes.Equal(again, decoded) {
			t.Fatalf("round trip: %q %v, want %q", again, err, decoded)
		}
		if !sameHeader(chunked.Trailer(), trailer) {
			t.Fatalf("round trip trailer %v, want %v", chunked.Trailer(), trailer)
		}
	})
}
