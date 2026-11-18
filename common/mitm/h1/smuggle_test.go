package h1

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file drives Serve with hostile client and upstream byte streams. Both far ends are read
// by an independent strict RFC 9112 reader (strictReader below, no httpx code) and cross-checked
// with net/http: the upstream must receive exactly the requests the client meant, every message
// h1 emits must be unambiguously framed, and nothing an attacker smuggled may reach the other
// side.

// ---- independent strict reader ----

// errIncomplete means the stream ended inside a message.
var errIncomplete = errors.New("incomplete message")

type strictError string

func (e strictError) Error() string { return string(e) }

// strictMsg is one message as the strict reader saw it.
type strictMsg struct {
	request  bool
	method   string // request method, or the method the response answers
	target   string
	proto    string
	status   int
	fields   [][2]string
	body     []byte
	trailers [][2]string
	complete bool
	invalid  string
}

func (m *strictMsg) get(name string) string {
	for _, f := range m.fields {
		if strings.EqualFold(f[0], name) {
			return f[1]
		}
	}
	return ""
}

func (m *strictMsg) count(name string) int {
	n := 0
	for _, f := range m.fields {
		if strings.EqualFold(f[0], name) {
			n++
		}
	}
	return n
}

// String is the summary the tests compare: "METHOD TARGET [PROTO] [body=..] [trailers=..]" or
// "STATUS [PROTO] [body=..]", prefixed with "!" when incomplete and "INVALID(reason)" when the
// message broke a strict rule.
func (m *strictMsg) String() string {
	var b strings.Builder
	if m.invalid != "" {
		fmt.Fprintf(&b, "INVALID(%s) ", m.invalid)
	}
	if !m.complete {
		b.WriteByte('!')
	}
	if m.request {
		b.WriteString(m.method + " " + m.target)
	} else {
		b.WriteString(strconv.Itoa(m.status))
	}
	if m.proto != "" && m.proto != "HTTP/1.1" {
		b.WriteString(" " + m.proto)
	}
	if len(m.body) > 0 {
		b.WriteString(" body=" + strconv.Quote(string(m.body)))
	}
	if len(m.trailers) > 0 {
		b.WriteString(" trailers=" + trailerString(m.trailers))
	}
	return b.String()
}

func trailerString(trailers [][2]string) string {
	list := make([]string, 0, len(trailers))
	for _, t := range trailers {
		list = append(list, textproto.CanonicalMIMEHeaderKey(t[0])+": "+t[1])
	}
	sort.Strings(list)
	return "[" + strings.Join(list, ", ") + "]"
}

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

func trimSPHT(s string) string { return strings.Trim(s, " \t") }

func validFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\t' && (c < 0x20 || c == 0x7f) {
			return false
		}
	}
	return true
}

type strictReader struct {
	r *bufio.Reader
}

// line reads one CRLF-terminated line. first reports io.EOF for a clean end before any byte.
func (s *strictReader) line(first bool) (string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		if first && line == "" {
			// io.EOF for a clean end; a reset or timeout before any byte is passed on as is.
			return "", err
		}
		return "", errIncomplete
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", strictError("bare LF")
	}
	line = line[:len(line)-2]
	if strings.ContainsAny(line, "\r\x00") {
		return "", strictError("bare CR or NUL")
	}
	return line, nil
}

func (s *strictReader) fieldLines() ([][2]string, error) {
	var fields [][2]string
	for {
		line, err := s.line(false)
		if err != nil {
			return fields, err
		}
		if line == "" {
			return fields, nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			return fields, strictError("obs-fold")
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !isToken(name) {
			return fields, strictError("field name")
		}
		value = trimSPHT(value)
		if !validFieldValue(value) {
			return fields, strictError("field value")
		}
		fields = append(fields, [2]string{name, value})
	}
}

func validProto(p string) bool {
	return len(p) == 8 && strings.HasPrefix(p, "HTTP/1.") && '0' <= p[7] && p[7] <= '9'
}

// read reads one message. method is the request method a response answers.
func (s *strictReader) read(request bool, method string) (*strictMsg, error) {
	m := &strictMsg{request: request, method: method}
	start, err := s.line(true)
	if err != nil {
		if _, ok := err.(strictError); !ok && err != errIncomplete {
			return nil, err
		}
		return s.fail(m, err)
	}
	if request {
		parts := strings.Split(start, " ")
		if len(parts) != 3 || !isToken(parts[0]) || parts[1] == "" || !validProto(parts[2]) {
			return s.fail(m, strictError("request line"))
		}
		for i := 0; i < len(parts[1]); i++ {
			if c := parts[1][i]; c <= ' ' || c == 0x7f {
				return s.fail(m, strictError("request target"))
			}
		}
		m.method, m.target, m.proto = parts[0], parts[1], parts[2]
	} else {
		proto, rest, ok := strings.Cut(start, " ")
		if !ok || !validProto(proto) || len(rest) < 3 || len(rest) > 3 && rest[3] != ' ' {
			return s.fail(m, strictError("status line"))
		}
		code, err := strconv.Atoi(rest[:3])
		if err != nil || code < 100 {
			return s.fail(m, strictError("status code"))
		}
		m.proto, m.status = proto, code
	}
	m.fields, err = s.fieldLines()
	if err != nil {
		return s.fail(m, err)
	}
	http11 := m.proto != "HTTP/1.0"
	te, cl := m.count("Transfer-Encoding"), m.count("Content-Length")
	var codings []string
	for _, f := range m.fields {
		if strings.EqualFold(f[0], "Transfer-Encoding") {
			for _, c := range strings.Split(f[1], ",") {
				codings = append(codings, strings.ToLower(trimSPHT(c)))
			}
		}
	}
	length := int64(-1)
	if cl > 0 {
		value := m.get("Content-Length")
		if cl != 1 || value == "" || len(value) > 18 || strings.Trim(value, "0123456789") != "" {
			return s.fail(m, strictError("Content-Length"))
		}
		length, _ = strconv.ParseInt(value, 10, 64)
	}
	if te > 0 && cl > 0 {
		return s.fail(m, strictError("Content-Length with Transfer-Encoding"))
	}
	if request {
		if http11 && m.count("Host") != 1 {
			return s.fail(m, strictError("Host"))
		}
		switch {
		case te > 0 && (!http11 || len(codings) != 1 || codings[0] != "chunked"):
			return s.fail(m, strictError("request Transfer-Encoding"))
		case te > 0:
			err = s.chunked(m)
		case length > 0:
			err = s.fixed(m, length)
		}
		if err != nil {
			return s.fail(m, err)
		}
		m.complete = true
		return m, nil
	}
	switch {
	case method == "HEAD" || m.status < 200 || m.status == 204 || m.status == 304:
	case method == "CONNECT" && m.status < 300:
	case te > 0 && http11 && codings[len(codings)-1] == "chunked":
		err = s.chunked(m)
	case te > 0 || length < 0:
		// HTTP/1.0 with Transfer-Encoding is faulty framing (RFC 9112 section 6.1); a final
		// coding other than chunked (section 6.3) or no framing field: delimited by close.
		m.body, err = io.ReadAll(s.r)
		if err != nil {
			err = errIncomplete
		}
	case length > 0:
		err = s.fixed(m, length)
	}
	if err != nil {
		return s.fail(m, err)
	}
	m.complete = true
	return m, nil
}

func (s *strictReader) fail(m *strictMsg, err error) (*strictMsg, error) {
	if se, ok := err.(strictError); ok {
		m.invalid = string(se)
	}
	return m, err
}

func (s *strictReader) fixed(m *strictMsg, length int64) error {
	// Read what is there: a declared length of 10^13 must not allocate 10^13 bytes.
	m.body, _ = io.ReadAll(io.LimitReader(s.r, length))
	if int64(len(m.body)) != length {
		return errIncomplete
	}
	return nil
}

func (s *strictReader) chunked(m *strictMsg) error {
	for {
		line, err := s.line(false)
		if err != nil {
			return err
		}
		size, ext, _ := strings.Cut(line, ";")
		// BWS may precede extensions only.
		size = strings.TrimRight(size, " \t")
		if size == "" || len(size) > 16 || strings.Trim(size, "0123456789abcdefABCDEF") != "" {
			return strictError("chunk size")
		}
		if strings.Contains(line, ";") && !validChunkExt(";"+ext) {
			return strictError("chunk extension")
		}
		n, err := strconv.ParseUint(size, 16, 63)
		if err != nil {
			return strictError("chunk size")
		}
		if n == 0 {
			trailers, err := s.fieldLines()
			m.trailers = trailers
			return err
		}
		data, _ := io.ReadAll(io.LimitReader(s.r, int64(n)))
		m.body = append(m.body, data...)
		if uint64(len(data)) != n {
			return errIncomplete
		}
		end, err := s.line(false)
		if err != nil {
			return err
		}
		if end != "" {
			return strictError("chunk data length")
		}
	}
}

// validChunkExt checks *( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] ).
func validChunkExt(s string) bool {
	i := 0
	skip := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	tok := func() bool {
		start := i
		for i < len(s) && isTchar(s[i]) {
			i++
		}
		return i > start
	}
	for {
		skip()
		if i == len(s) {
			return true
		}
		if s[i] != ';' {
			return false
		}
		i++
		skip()
		if !tok() {
			return false
		}
		skip()
		if i < len(s) && s[i] == '=' {
			i++
			skip()
			if i < len(s) && s[i] == '"' {
				i++
				for {
					if i >= len(s) {
						return false
					}
					c := s[i]
					if c == '"' {
						i++
						break
					}
					if c == '\\' {
						i++
						if i >= len(s) {
							return false
						}
						c = s[i]
					}
					if c != '\t' && (c < 0x20 || c == 0x7f) {
						return false
					}
					i++
				}
			} else if !tok() {
				return false
			}
		}
	}
}

// ---- net/http cross-check ----

func netHTTPRequests(raw []byte, max int) []string {
	r := bufio.NewReader(bytes.NewReader(raw))
	var out []string
	for len(out) < max {
		req, err := http.ReadRequest(r)
		if err != nil {
			break
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			break
		}
		m := strictMsg{request: true, method: req.Method, target: req.RequestURI, proto: req.Proto, body: body, complete: true}
		out = append(out, m.String())
	}
	return out
}

// netHTTPResponses reads responses to requests with the given methods (GET beyond).
func netHTTPResponses(raw []byte, max int, methods []string) []string {
	r := bufio.NewReader(bytes.NewReader(raw))
	var out []string
	for len(out) < max {
		method := "GET"
		if len(out) < len(methods) {
			method = methods[len(out)]
		}
		resp, err := http.ReadResponse(r, &http.Request{Method: method})
		if err != nil {
			break
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			break
		}
		if resp.StatusCode < 200 {
			continue
		}
		m := strictMsg{status: resp.StatusCode, proto: resp.Proto, body: body, complete: true}
		out = append(out, m.String())
	}
	return out
}

// crossCheck asserts that net/http, wherever it parses the stream, agrees with the strict reader
// on everything but trailers (net/http drops undeclared response trailers). net/http is more
// lenient in places, so a parse failure on its side ends the comparison.
func crossCheck(t reporter, side string, strict []*strictMsg, parsed []string) {
	t.Helper()
	for i, m := range strict {
		if !m.complete || m.invalid != "" || i >= len(parsed) {
			return
		}
		withoutTrailers := *m
		withoutTrailers.trailers = nil
		if parsed[i] != withoutTrailers.String() {
			t.Errorf("%s message %d: strict %q, net/http %q", side, i, withoutTrailers.String(), parsed[i])
		}
	}
}

// ---- relay harness ----

type upstreamReply struct {
	raw   string
	close bool // close the upstream after writing raw
	// closeAfter keeps reading requests without answering them and closes the upstream this
	// long after raw was written.
	closeAfter time.Duration
}

const okReply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

type relayResult struct {
	upstream    []*strictMsg
	upstreamRaw []byte
	client      []*strictMsg // final responses only
	clientRaw   []byte
	serveErr    error
	hung        string
	methods     []string // from relayConfig
	// repliesWritten counts the replies written completely (over net.Pipe: read by the relay).
	repliesWritten int
}

type relayConfig struct {
	client string
	// later is sent once the first final response arrived.
	later   string
	replies []upstreamReply // by complete upstream request; okReply beyond
	// methods are the request methods the client's final responses answer, in order; GET beyond.
	methods []string
	pipe    bool // net.Pipe instead of loopback TCP
	// closeClient closes the client after writing instead of reading until the relay closes.
	closeClient time.Duration
	timeout     time.Duration
}

func smugglePair(t testing.TB, pipe bool) (net.Conn, net.Conn) {
	if pipe {
		return net.Pipe()
	}
	return tcpPair(t)
}

func runRelay(t testing.TB, cfg relayConfig) relayResult {
	if cfg.timeout == 0 {
		cfg.timeout = 5 * time.Second
	}
	client, proxyClient := smugglePair(t, cfg.pipe)
	proxyUpstream, upstream := smugglePair(t, cfg.pipe)
	defer client.Close()
	defer upstream.Close()
	deadline := time.Now().Add(cfg.timeout)
	client.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- Serve(ctx, proxyClient, proxyUpstream, Options{}) }()

	var (
		result       relayResult
		upstreamMsgs []*strictMsg
		replies      int
		clientMsgs   []*strictMsg
		clientHung   string
	)
	// Upstream: strict reader, scripted replies.
	var upstreamRaw bytes.Buffer
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		reader := strictReader{r: bufio.NewReader(io.TeeReader(upstream, &upstreamRaw))}
		silent := false
		for i := 0; ; i++ {
			m, err := reader.read(true, "")
			if m != nil {
				upstreamMsgs = append(upstreamMsgs, m)
			}
			if err != nil {
				upstream.Close()
				return
			}
			if silent {
				continue
			}
			reply := upstreamReply{raw: okReply}
			if i < len(cfg.replies) {
				reply = cfg.replies[i]
			} else if m.method == "CONNECT" {
				// No tunnel: the strict reader would read tunnel bytes as requests.
				reply.raw = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
			}
			if reply.closeAfter > 0 {
				// A relay that stops reading must not block the write forever.
				safety := time.AfterFunc(time.Second, func() { upstream.Close() })
				_, err = io.WriteString(upstream, reply.raw)
				safety.Stop()
				if err != nil {
					upstream.Close()
					return
				}
				replies++
				silent = true
				time.AfterFunc(reply.closeAfter, func() { upstream.Close() })
				continue
			}
			if _, err = io.WriteString(upstream, reply.raw); err != nil || reply.close {
				upstream.Close()
				return
			}
			replies++
		}
	}()
	// Client: strict response reader.
	var clientRaw bytes.Buffer
	firstResponse := make(chan struct{})
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		reader := strictReader{r: bufio.NewReader(io.TeeReader(client, &clientRaw))}
		signalled := false
		for {
			method := "GET"
			if len(clientMsgs) < len(cfg.methods) {
				method = cfg.methods[len(clientMsgs)]
			}
			m, err := reader.read(false, method)
			if m != nil && (m.status >= 200 || err != nil) {
				clientMsgs = append(clientMsgs, m)
				if !signalled {
					signalled = true
					close(firstResponse)
				}
			}
			if err != nil {
				if !signalled {
					close(firstResponse)
				}
				if !time.Now().Before(deadline) {
					clientHung = "client read timed out: the relay kept the connection open"
				}
				return
			}
		}
	}()
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		if _, err := io.WriteString(client, cfg.client); err != nil {
			return
		}
		if cfg.later != "" {
			<-firstResponse
			if _, err := io.WriteString(client, cfg.later); err != nil {
				return
			}
		}
		if cfg.closeClient > 0 {
			select {
			case <-clientDone:
			case <-time.After(cfg.closeClient):
			}
			client.Close()
		}
	}()

	select {
	case <-clientDone:
	case <-time.After(cfg.timeout + time.Second):
		result.hung = "client reader did not finish"
	}
	select {
	case result.serveErr = <-serveDone:
	case <-time.After(3 * time.Second):
		if result.hung == "" {
			result.hung = "Serve did not return after the client side ended"
		}
		cancel()
		client.Close()
		upstream.Close()
		select {
		case result.serveErr = <-serveDone:
		case <-time.After(3 * time.Second):
			result.hung = "Serve ignores context cancellation"
			return result
		}
	}
	client.Close()
	<-writeDone
	<-clientDone
	select {
	case <-upstreamDone:
	case <-time.After(3 * time.Second):
		result.hung = "upstream side did not see a close"
		upstream.Close()
		<-upstreamDone
	}
	if result.hung == "" {
		result.hung = clientHung
	}
	result.upstream, result.client, result.repliesWritten = upstreamMsgs, clientMsgs, replies
	result.methods = cfg.methods
	result.upstreamRaw = upstreamRaw.Bytes()
	result.clientRaw = clientRaw.Bytes()
	return result
}

func summaries(list []*strictMsg) []string {
	out := make([]string, 0, len(list))
	for _, m := range list {
		out = append(out, m.String())
	}
	return out
}

// checkRelayInvariants holds for every input: no hang, every message h1 emitted is strictly
// valid on both sides and agrees with net/http, and no marked byte crossed over.
func checkRelayInvariants(t reporter, r relayResult, markers bool) {
	t.Helper()
	if r.hung != "" {
		t.Errorf("hang: %s", r.hung)
	}
	for _, m := range r.upstream {
		if m.invalid != "" {
			t.Errorf("upstream got an invalid request: %s\nraw: %q", m, r.upstreamRaw)
		}
	}
	for _, m := range r.client {
		if m.invalid != "" {
			t.Errorf("client got an invalid response: %s\nraw: %q", m, r.clientRaw)
		}
	}
	crossCheck(t, "upstream", r.upstream, netHTTPRequests(r.upstreamRaw, len(r.upstream)))
	crossCheck(t, "client", r.client, netHTTPResponses(r.clientRaw, len(r.client), r.methods))
	if !markers {
		return
	}
	if bytes.Contains(r.clientRaw, []byte("SMUGGLED")) {
		t.Errorf("smuggled upstream bytes reached the client: %q", r.clientRaw)
	}
	if bytes.Contains(r.upstreamRaw, []byte("/smuggled")) {
		t.Errorf("smuggled request reached the upstream: %q", r.upstreamRaw)
	}
}

// ---- cases ----

const (
	endReq = "GET /end HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"
	endGot = "GET /end"
	smug   = "GET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n"
	// afterReq follows a request that must end the connection; reaching the upstream means
	// the relay resynchronized on bytes it should not trust.
	afterReq = "GET /after HTTP/1.1\r\nHost: a\r\n\r\n"
)

func post(fields, body string) string {
	return "POST /a HTTP/1.1\r\nHost: a\r\n" + fields + "\r\n" + body
}

type smuggleCase struct {
	name    string
	client  string
	later   string
	replies []upstreamReply
	// upstream lists the strict summaries of what the upstream must receive; with prefix, any
	// prefix of it is accepted (the relay may stop earlier).
	upstream []string
	prefix   bool
	// status lists the final statuses the client must receive in order, "|" separating
	// alternatives and "-" meaning no (further) response.
	status string
	bodies []string // optional, final response bodies in order
	// lenient checks the invariants only (the outcome is a policy choice).
	lenient bool
	check   func(t reporter, r relayResult)
}

// bodyError is the outcome of a request whose body turns out malformed after its head was
// forwarded: the upstream never receives a complete request, the client no success.
func bodyError(name, fields, body string) smuggleCase {
	return smuggleCase{name: name, client: post(fields, body) + afterReq, upstream: []string{"!POST /a*"}, prefix: true, status: "400|502|-"}
}

func chunkedError(name, body string) smuggleCase {
	return bodyError(name, "Transfer-Encoding: chunked\r\n", body)
}

var smuggleCases = []smuggleCase{
	{name: "baseline keep-alive", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, upstream: []string{"GET /1", endGot}, status: "200 200"},
	{name: "leading empty lines", client: "\r\n\r\nGET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, upstream: []string{"GET /1", endGot}, status: "200 200"},

	// Content-Length / Transfer-Encoding conflicts.
	{name: "CL then TE", client: post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "0\r\n\r\n") + smug, status: "400"},
	{name: "TE then CL", client: post("Transfer-Encoding: chunked\r\nContent-Length: 4\r\n", "0\r\n\r\n") + smug, status: "400"},
	{name: "TE with CL 0", client: post("Content-Length: 0\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400"},
	{name: "CL CL differing", client: post("Content-Length: 5\r\nContent-Length: 4\r\n", "hello") + smug, status: "400"},
	{name: "CL CL identical", client: post("Content-Length: 5\r\nContent-Length: 5\r\n", "hello") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	{name: "CL list differing", client: post("Content-Length: 1, 2\r\n", "hello") + smug, status: "400"},
	{name: "CL list identical", client: post("Content-Length: 5, 5\r\n", "hello") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	{name: "CL zero list", client: post("Content-Length: 0, 0\r\n", "") + endReq, upstream: []string{"POST /a", endGot}, status: "200 200"},
	{name: "CL zero twice", client: post("Content-Length: 0\r\nContent-Length: 0\r\n", "") + endReq, upstream: []string{"POST /a", endGot}, status: "200 200"},
	{name: "CL plus sign", client: post("Content-Length: +5\r\n", "hello") + smug, status: "400"},
	{name: "CL negative", client: post("Content-Length: -1\r\n", "hello") + smug, status: "400"},
	{name: "CL leading OWS", client: post("Content-Length:  5\r\n", "hello") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	{name: "CL trailing junk", client: post("Content-Length: 5x\r\n", "hello") + smug, status: "400"},
	{name: "CL hex", client: post("Content-Length: 0x5\r\n", "hello") + smug, status: "400"},
	{name: "CL empty", client: post("Content-Length: \r\n", "hello") + smug, status: "400"},
	{name: "CL overflow", client: post("Content-Length: 99999999999999999999\r\n", "hello") + smug, status: "400"},
	{name: "CL inner space", client: post("Content-Length: 1 5\r\n", "hello") + smug, status: "400"},

	// Transfer-Encoding variants.
	{name: "TE xchunked", client: post("Transfer-Encoding: xchunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400|501"},
	{name: "TE chunked, identity", client: post("Transfer-Encoding: chunked, identity\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400|501"},
	{name: "TE identity, chunked", client: post("Transfer-Encoding: identity, chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "501"},
	{name: "TE identity", client: post("Transfer-Encoding: identity\r\n", "hello") + smug, status: "400|501"},
	{name: "TE gzip, chunked", client: post("Transfer-Encoding: gzip, chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "501"},
	{name: "TE chunked, chunked", client: post("Transfer-Encoding: chunked, chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400|501"},
	{name: "TE two fields", client: post("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400|501"},
	{name: "TE quoted", client: post("Transfer-Encoding: \"chunked\"\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400|501"},
	{name: "TE trailing tab", client: post("Transfer-Encoding: chunked\t\r\n", "5\r\nhello\r\n0\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	{name: "TE upper case", client: post("Transfer-Encoding: CHUNKED\r\n", "5\r\nhello\r\n0\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	{name: "TE empty list element", client: post("Transfer-Encoding: chunked, \r\n", "5\r\nhello\r\n0\r\n\r\n") + endReq, lenient: true},
	{name: "TE in HTTP/1.0", client: "POST /a HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n" + smug, status: "400"},
	{name: "TE only in HTTP/1.0", client: "POST /a HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" + smug, status: "400"},
	{name: "TE space before colon", client: post("Content-Length: 5\r\nTransfer-Encoding : chunked\r\n", "0\r\n\r\n") + smug, status: "400"},
	{name: "TE obs-fold", client: post("Transfer-Encoding: identity\r\n chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400"},
	{name: "TE vertical tab", client: post("Transfer-Encoding:\x0bchunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + smug, status: "400"},

	// Field syntax.
	{name: "leading whitespace field", client: "GET / HTTP/1.1\r\n Host: a\r\n\r\n" + afterReq, status: "400"},
	{name: "obs-fold value", client: "GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n\tb\r\n\r\n" + afterReq, status: "400"},
	{name: "space in name", client: "GET / HTTP/1.1\r\nHost: a\r\nX Y: a\r\n\r\n" + afterReq, status: "400"},
	{name: "CTL in name", client: "GET / HTTP/1.1\r\nHost: a\r\nX\x01: a\r\n\r\n" + afterReq, status: "400"},
	{name: "NUL in value", client: "GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n" + afterReq, status: "400"},
	{name: "bare CR in value", client: "GET / HTTP/1.1\r\nHost: a\r\nX: a\rTransfer-Encoding: chunked\r\n\r\n" + afterReq, status: "400"},
	{name: "bare LF in value", client: "GET / HTTP/1.1\r\nHost: a\r\nX: a\nTransfer-Encoding: chunked\r\n\r\n" + afterReq, status: "400"},
	{name: "bare LF line endings", client: "GET / HTTP/1.1\nHost: a\n\n" + afterReq, status: "400"},
	{name: "bare LF end of head", client: "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\nhello" + afterReq, status: "400"},
	{name: "bare CR in request line", client: "GET /\r HTTP/1.1\r\nHost: a\r\n\r\n" + afterReq, status: "400"},
	{name: "no colon", client: "GET / HTTP/1.1\r\nHost: a\r\nGET /smuggled HTTP/1.1\r\n\r\n", status: "400"},

	// Request line.
	{name: "double space", client: "GET  / HTTP/1.1\r\nHost: a\r\n\r\n" + afterReq, status: "400"},
	{name: "tab separators", client: "GET\t/\tHTTP/1.1\r\nHost: a\r\n\r\n" + afterReq, status: "400"},
	{name: "trailing space", client: "GET / HTTP/1.1 \r\nHost: a\r\n\r\n" + afterReq, status: "400"},
	{name: "missing version", client: "GET /\r\nHost: a\r\n\r\n" + afterReq, status: "400"},
	{name: "HTTP/2.0", client: "GET / HTTP/2.0\r\nHost: a\r\n\r\n" + afterReq, status: "505"},
	{name: "HTTP/3.0", client: "GET / HTTP/3.0\r\nHost: a\r\n\r\n" + afterReq, status: "505"},
	{name: "target too long", client: "GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\nHost: a\r\n\r\n", status: "414"},
	{name: "header too large", client: "GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("X: "+strings.Repeat("b", 1000)+"\r\n", 70) + "\r\n", status: "431"},
	{name: "too many fields", client: "GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("X: b\r\n", 200) + "\r\n", status: "431"},

	// Host.
	{name: "missing Host", client: "GET / HTTP/1.1\r\n\r\n" + afterReq, status: "400"},
	{name: "two Hosts", client: "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n" + afterReq, status: "400"},
	{name: "Host with space", client: "GET / HTTP/1.1\r\nHost: a b\r\n\r\n" + afterReq, status: "400"},
	{name: "HTTP/1.0 without Host", client: "GET /1 HTTP/1.0\r\n\r\n", upstream: []string{"GET /1 HTTP/1.0"}, status: "200"},
	{name: "absolute-form with conflicting Host", client: "GET http://b/x HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, lenient: true},

	// Connection nominating framing and routing fields.
	{name: "Connection: content-length", client: post("Connection: content-length\r\nContent-Length: 5\r\n", "hello") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	{name: "Connection: host", client: "GET /1 HTTP/1.1\r\nConnection: host\r\nHost: a\r\n\r\n" + endReq, upstream: []string{"GET /1", endGot}, status: "200 200"},
	{name: "Connection: transfer-encoding", client: post("Connection: transfer-encoding\r\nTransfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},

	// Bodies on GET.
	{name: "GET with Content-Length body", client: "GET /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello" + endReq, upstream: []string{`GET /a body="hello"`, endGot}, status: "200 200"},
	{name: "GET with chunked body", client: "GET /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" + endReq, upstream: []string{`GET /a body="hello"`, endGot}, status: "200 200"},

	// Chunked body syntax.
	{name: "chunked baseline", client: post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello world"`, endGot}, status: "200 200"},
	{name: "chunk extension", client: post("Transfer-Encoding: chunked\r\n", "5;a=b;c=\"d;e\"\r\nhello\r\n0\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello"`, endGot}, status: "200 200"},
	chunkedError("chunk size 0x", "0x5\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk size leading space", " 5\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk size 17 hex digits", "00000000000000005\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk size overflow", "fffffffffffffffff\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk size negative", "-5\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk size bare LF", "5\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk extension bare CR", "5;a\rb\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk extension bare LF", "5;a\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk extension quoted CRLF", "5;a=\"x\r\nhello\r\n0\r\n\r\n"),
	chunkedError("chunk extension NUL", "5;a\x00\r\nhello\r\n0\r\n\r\n"),
	chunkedError("missing CRLF after chunk data", "5\r\nhello0\r\n\r\n"),
	chunkedError("chunk data longer than declared", "5\r\nhelloXX\r\n0\r\n\r\n"),
	chunkedError("chunk data LF only", "5\r\nhello\n0\r\n\r\n"),
	chunkedError("last chunk bare LF", "5\r\nhello\r\n0\n\r\n"),
	chunkedError("trailer section smuggling a request", "5\r\nhello\r\n0\r\n"+smug),
	chunkedError("trailer obs-fold", "5\r\nhello\r\n0\r\nX: a\r\n b\r\n\r\n"),
	chunkedError("trailer bare LF", "5\r\nhello\r\n0\r\nX: a\n\r\n"),
	{name: "trailer forwarded", client: post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello" trailers=[X-T: 1]`, endGot}, status: "200 200"},
	{name: "trailer framing fields dropped", client: post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\nHost: evil\r\nX-T: 1\r\n\r\n") + endReq, upstream: []string{`POST /a body="hello" trailers=[X-T: 1]`, endGot}, status: "200 200"},

	// Pipelining.
	{name: "pipelined after close-delimited response", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n", replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\n\r\nfirst", close: true}}, upstream: []string{"GET /1"}, status: "200", bodies: []string{"first"}},
	{name: "pipelined after rejected request", client: post("Content-Length: 1, 2\r\n", "") + "GET /2 HTTP/1.1\r\nHost: a\r\n\r\n", status: "400"},
	{name: "rejected request after a good one", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + post("Content-Length: 1, 2\r\n", "") + smug, upstream: []string{"GET /1"}, status: "200 400"},
	{name: "pipelined after Connection: close", client: "GET /1 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n" + smug, upstream: []string{"GET /1"}, status: "200"},
	{name: "pipelined after HTTP/1.0", client: "GET /1 HTTP/1.0\r\nHost: a\r\n\r\n" + smug, upstream: []string{"GET /1 HTTP/1.0"}, status: "200"},
	{name: "body bytes are not a request", client: post("Content-Length: 28\r\n", "GET /x HTTP/1.1\r\nHost: a\r\n\r\n") + endReq, upstream: []string{`POST /a body="GET /x HTTP/1.1\r\nHost: a\r\n\r\n"`, endGot}, status: "200 200"},

	// Response side.
	{name: "response CL and TE", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"}}, upstream: []string{"GET /1", endGot}, status: "200 200", bodies: []string{"hello", ""}},
	{name: "response two CLs", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 13\r\n\r\nhelloSMUGGLED"}}, upstream: []string{"GET /1", endGot}, prefix: true, status: "502"},
	{name: "response CL list zero", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"}}, upstream: []string{"GET /1", endGot}, status: "200 200"},
	{name: "response gzip, chunked", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"}}, upstream: []string{"GET /1", endGot}, status: "200 200", bodies: []string{"hello", ""}, check: wantFirstTE("gzip, chunked")},
	{name: "response gzip, chunked to HTTP/1.0", client: "GET /1 HTTP/1.0\r\nHost: a\r\n\r\n", replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"}}, upstream: []string{"GET /1 HTTP/1.0"}, status: "502"},
	{name: "response TE identity", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\nhello", close: true}}, upstream: []string{"GET /1"}, prefix: true, status: "200", bodies: []string{"hello"}},
	{name: "response HTTP/1.0 with TE", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n0\r\n\r\nTAIL", close: true}}, upstream: []string{"GET /1"}, prefix: true, status: "200", bodies: []string{"5;x=1\r\nhello\r\n0\r\n\r\nTAIL"}},
	{name: "response HTTP/1.0 with TE and CL", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n", close: true}}, upstream: []string{"GET /1"}, prefix: true, status: "200", bodies: []string{"5\r\nhello\r\n0\r\n\r\n"}},
	{name: "response extra bytes after CL body, pipelined", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED"}}, upstream: []string{"GET /1", endGot}, prefix: true, status: "200 502|-", bodies: []string{"ok"}},
	{name: "response extra bytes after CL body, sequential", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n", later: endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED"}}, upstream: []string{"GET /1", endGot}, prefix: true, status: "200 502|-", bodies: []string{"ok"}},
	{name: "response extra bytes after chunked body", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED"}}, upstream: []string{"GET /1", endGot}, prefix: true, status: "200 502|-", bodies: []string{"ok"}},
	{name: "response 204 with conflicting CLs", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"}}, upstream: []string{"GET /1", endGot}, prefix: true, status: "204|502 200|-"},
	{name: "response bare LF", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\nContent-Length: 0\n\n"}}, upstream: []string{"GET /1"}, prefix: true, status: "502"},
	{name: "response obs-fold", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n folded\r\n\r\n"}}, upstream: []string{"GET /1"}, prefix: true, status: "502"},
	{name: "response xchunked", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\n\r\nhello", close: true}}, upstream: []string{"GET /1"}, prefix: true, lenient: true},
	{name: "response chunked trailer forwarded", client: "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n" + endReq, replies: []upstreamReply{{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\nContent-Length: 5\r\n\r\n"}}, upstream: []string{"GET /1", endGot}, status: "200 200", bodies: []string{"hello", ""}, check: wantFirstTrailers("[X-T: 1]")},
}

func wantFirstTE(te string) func(t reporter, r relayResult) {
	return func(t reporter, r relayResult) {
		if len(r.client) > 0 && r.client[0].get("Transfer-Encoding") != te {
			t.Errorf("Transfer-Encoding = %q, want %q", r.client[0].get("Transfer-Encoding"), te)
		}
	}
}

func wantFirstTrailers(want string) func(t reporter, r relayResult) {
	return func(t reporter, r relayResult) {
		if len(r.client) > 0 && trailerString(r.client[0].trailers) != want {
			t.Errorf("trailers = %s, want %s", trailerString(r.client[0].trailers), want)
		}
	}
}

func matchStatuses(want string, got []*strictMsg) bool {
	positions := strings.Fields(want)
	if len(got) > len(positions) {
		return false
	}
	for i, position := range positions {
		ok := false
		for _, alt := range strings.Split(position, "|") {
			if i >= len(got) {
				ok = ok || alt == "-"
			} else if got[i].complete && alt == strconv.Itoa(got[i].status) {
				ok = true
			}
		}
		if !ok {
			return false
		}
		if i >= len(got) {
			// "-": no further response.
			return true
		}
	}
	return true
}

// reporter is the part of testing.TB the checks use.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

func TestSmuggling(t *testing.T) {
	for _, tc := range smuggleCases {
		t.Run(tc.name, func(t *testing.T) {
			r := runRelay(t, relayConfig{client: tc.client, later: tc.later, replies: tc.replies})
			checkSmuggleCase(t, tc, r)
		})
	}
}

func checkSmuggleCase(t reporter, tc smuggleCase, r relayResult) {
	t.Helper()
	checkRelayInvariants(t, r, true)
	if tc.lenient {
		return
	}
	got := summaries(r.upstream)
	if !upstreamMatches(tc.upstream, tc.prefix, got) {
		t.Errorf("upstream got %q, want %q (prefix %v)\nraw: %q", got, tc.upstream, tc.prefix, r.upstreamRaw)
	}
	if !matchStatuses(tc.status, r.client) {
		t.Errorf("client got %q, want statuses %q\nraw: %q", summaries(r.client), tc.status, r.clientRaw)
	}
	for i, body := range tc.bodies {
		if i < len(r.client) && string(r.client[i].body) != body {
			t.Errorf("response %d body %q, want %q", i, r.client[i].body, body)
		}
	}
	if tc.check != nil {
		tc.check(t, r)
	}
}

func upstreamMatches(want []string, prefix bool, got []string) bool {
	if len(got) > len(want) || !prefix && len(got) != len(want) {
		return false
	}
	for i := range got {
		if w, ok := strings.CutSuffix(want[i], "*"); ok && strings.HasPrefix(got[i], w) {
			continue
		}
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestStrictReader pins the independent reader the other tests rely on.
func TestStrictReader(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"GET / HTTP/1.1\r\nHost: a\r\n\r\n", []string{"GET /"}},
		{"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi", []string{`POST /a body="hi"`}},
		{"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2;x=\"a\\\"b\"\r\nhi\r\n0\r\nT: v\r\n\r\n", []string{`POST /a body="hi" trailers=[T: v]`}},
		{"GET / HTTP/1.1\r\n\r\n", []string{"INVALID(Host) !GET /"}},
		{"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 2, 2\r\n\r\nhi", []string{"INVALID(Content-Length) !POST /a"}},
		{"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", []string{"INVALID(Content-Length with Transfer-Encoding) !POST /a"}},
		{"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi", []string{`!POST /a body="hi"`}},
		{"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2;x=\"a\r\nhi\r\n0\r\n\r\n", []string{"INVALID(chunk extension) !POST /a"}},
		{"GET / HTTP/1.1\nHost: a\r\n\r\n", []string{"INVALID(bare LF) ! "}},
	} {
		reader := strictReader{r: bufio.NewReader(strings.NewReader(tc.raw))}
		var got []string
		for {
			m, err := reader.read(true, "")
			if m != nil {
				got = append(got, m.String())
			}
			if err != nil {
				break
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: got %q, want %q", tc.raw, got, tc.want)
		}
	}
}
