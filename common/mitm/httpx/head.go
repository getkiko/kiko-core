package httpx

import (
	"bufio"
	"io"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http/httpguts"
)

// Limits bound the size of a message head.
type Limits struct {
	// StartLine is the maximum request or status line length in bytes, CRLF included.
	StartLine int
	// Header is the maximum total length of the field lines in bytes, CRLFs included.
	Header int
	// Fields is the maximum number of header fields.
	Fields int
}

// DefaultLimits are the limits used when a HeadReader has zero Limits.
var DefaultLimits = Limits{StartLine: 8 << 10, Header: 64 << 10, Fields: 128}

var (
	ErrStartLineTooLong = E.New("start line too long")
	ErrHeaderTooLarge   = E.New("header section too large")
	ErrTooManyFields    = E.New("too many header fields")
	ErrBareLF           = E.New("line not terminated by CRLF")
	ErrBareCR           = E.New("bare CR in message head")
	ErrObsFold          = E.New("obsolete line folding")
	ErrMalformed        = E.New("malformed message head")
	ErrVersion          = E.New("unsupported HTTP version")
)

// Request is a parsed request head. Strings are substrings of one allocation per head.
type Request struct {
	Method     string
	Target     string
	Proto      string // as on the wire, e.g. "HTTP/1.1"
	ProtoMajor int
	ProtoMinor int
	Header     Header
}

// Response is a parsed response head.
type Response struct {
	Proto      string
	ProtoMajor int
	ProtoMinor int
	StatusCode int
	Reason     string
	Header     Header
}

// ProtoAtLeast reports whether the request version is at least major.minor.
func (r *Request) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major || r.ProtoMajor == major && r.ProtoMinor >= minor
}

// ProtoAtLeast reports whether the response version is at least major.minor.
func (r *Response) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major || r.ProtoMajor == major && r.ProtoMinor >= minor
}

// HeadReader reads message heads from a buffered connection, reusing its scratch space between
// messages. It is not safe for concurrent use.
type HeadReader struct {
	Reader  *bufio.Reader
	Limits  Limits
	scratch []byte
	ends    []int
	lines   []string
}

// NewHeadReader returns a HeadReader with DefaultLimits.
func NewHeadReader(reader *bufio.Reader) *HeadReader {
	return &HeadReader{Reader: reader, Limits: DefaultLimits}
}

func (h *HeadReader) limits() Limits {
	limits := h.Limits
	if limits.StartLine <= 0 {
		limits.StartLine = DefaultLimits.StartLine
	}
	if limits.Header <= 0 {
		limits.Header = DefaultLimits.Header
	}
	if limits.Fields <= 0 {
		limits.Fields = DefaultLimits.Fields
	}
	return limits
}

// Partial reports whether the last ReadRequest or ReadResponse consumed bytes of the message
// head before it failed (always true after success).
func (h *HeadReader) Partial() bool {
	return len(h.scratch) > 0
}

// ReadRequest reads a request head into req, reusing req.Header's storage. Empty lines before
// the request line are skipped. It returns io.EOF only when the stream ended before any byte.
func (h *HeadReader) ReadRequest(req *Request) error {
	lines, err := h.readHead(true)
	if err != nil {
		return err
	}
	line := lines[0]
	method, rest, ok := strings.Cut(line, " ")
	if !ok || !httpguts.ValidHeaderFieldName(method) {
		return E.Cause(ErrMalformed, "request method")
	}
	target, proto, ok := strings.Cut(rest, " ")
	if !ok || !validTarget(target) {
		return E.Cause(ErrMalformed, "request target")
	}
	major, minor, ok := parseVersion(proto)
	if !ok {
		return E.Cause(ErrMalformed, "request version")
	}
	if major != 1 {
		return ErrVersion
	}
	header, err := parseFields(req.Header[:0], lines[1:])
	if err != nil {
		return err
	}
	*req = Request{Method: method, Target: target, Proto: proto, ProtoMajor: major, ProtoMinor: minor, Header: header}
	return nil
}

// ReadResponse reads a response head into resp, reusing resp.Header's storage.
func (h *HeadReader) ReadResponse(resp *Response) error {
	lines, err := h.readHead(false)
	if err != nil {
		return err
	}
	line := lines[0]
	proto, rest, ok := strings.Cut(line, " ")
	if !ok {
		return E.Cause(ErrMalformed, "status line")
	}
	major, minor, ok := parseVersion(proto)
	if !ok {
		return E.Cause(ErrMalformed, "response version")
	}
	if major != 1 {
		return ErrVersion
	}
	if len(rest) < 3 || len(rest) > 3 && rest[3] != ' ' {
		return E.Cause(ErrMalformed, "status code")
	}
	code := 0
	for i := 0; i < 3; i++ {
		c := rest[i]
		if c < '0' || c > '9' {
			return E.Cause(ErrMalformed, "status code")
		}
		code = code*10 + int(c-'0')
	}
	if code < 100 {
		return E.Cause(ErrMalformed, "status code")
	}
	var reason string
	if len(rest) > 3 {
		reason = rest[4:]
		if !httpguts.ValidHeaderFieldValue(reason) {
			return E.Cause(ErrMalformed, "reason phrase")
		}
	}
	header, err := parseFields(resp.Header[:0], lines[1:])
	if err != nil {
		return err
	}
	*resp = Response{Proto: proto, ProtoMajor: major, ProtoMinor: minor, StatusCode: code, Reason: reason, Header: header}
	return nil
}

// readHead reads the start line and the field lines up to the empty line and returns them
// without CRLF as substrings of a single string.
func (h *HeadReader) readHead(skipEmpty bool) ([]string, error) {
	limits := h.limits()
	h.scratch = h.scratch[:0]
	h.ends = h.ends[:0]
	start := 0
	for {
		err := h.readLine(limits.StartLine, true)
		if err != nil {
			return nil, err
		}
		if skipEmpty && len(h.scratch) == start+2 && start+2 <= limits.StartLine {
			// RFC 9112 section 2.2: ignore empty lines before the request line.
			start += 2
			continue
		}
		break
	}
	if start > 0 {
		h.scratch = append(h.scratch[:0], h.scratch[start:]...)
	}
	h.ends = append(h.ends, len(h.scratch))
	headerStart := len(h.scratch)
	for {
		remaining := limits.Header - (len(h.scratch) - headerStart)
		if remaining <= 0 {
			return nil, ErrHeaderTooLarge
		}
		lineStart := len(h.scratch)
		err := h.readLine(remaining, false)
		if err != nil {
			return nil, err
		}
		h.ends = append(h.ends, len(h.scratch))
		if len(h.scratch)-lineStart == 2 {
			break
		}
		if len(h.ends)-1 > limits.Fields {
			return nil, ErrTooManyFields
		}
	}
	head := string(h.scratch)
	lines := h.lines[:0]
	begin := 0
	for _, end := range h.ends[:len(h.ends)-1] {
		line := head[begin : end-2]
		if strings.IndexByte(line, '\r') >= 0 {
			return nil, ErrBareCR
		}
		lines = append(lines, line)
		begin = end
	}
	h.lines = lines
	return lines, nil
}

// readLine appends one CRLF-terminated line to scratch. With startLine, an EOF before any byte of
// the line is reported as io.EOF.
func (h *HeadReader) readLine(limit int, startLine bool) error {
	begin := len(h.scratch)
	for {
		chunk, err := h.Reader.ReadSlice('\n')
		if len(h.scratch)-begin+len(chunk) > limit {
			if startLine {
				return ErrStartLineTooLong
			}
			return ErrHeaderTooLarge
		}
		h.scratch = append(h.scratch, chunk...)
		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if startLine && len(h.scratch) == begin {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}
		return err
	}
	line := h.scratch[begin:]
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return ErrBareLF
	}
	return nil
}

func parseFields(header Header, lines []string) (Header, error) {
	for _, line := range lines {
		field, err := parseField(line)
		if err != nil {
			return nil, err
		}
		header = append(header, field)
	}
	return header, nil
}

// parseField parses one field line without its CRLF (RFC 9112 section 5): no obs-fold, no
// whitespace before the colon, a token name and a value of visible characters, SP and HTAB.
func parseField(line string) (Field, error) {
	if line == "" {
		return Field{}, E.Cause(ErrMalformed, "header field")
	}
	if line[0] == ' ' || line[0] == '\t' {
		return Field{}, ErrObsFold
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return Field{}, E.Cause(ErrMalformed, "header field")
	}
	name := line[:colon]
	if !httpguts.ValidHeaderFieldName(name) {
		return Field{}, E.Cause(ErrMalformed, "header field name")
	}
	value := trimOWS(line[colon+1:])
	if !httpguts.ValidHeaderFieldValue(value) {
		return Field{}, E.Cause(ErrMalformed, "header field value")
	}
	return Field{Name: name, Value: value}, nil
}

func parseVersion(proto string) (int, int, bool) {
	if len(proto) != 8 || proto[:5] != "HTTP/" || proto[6] != '.' {
		return 0, 0, false
	}
	major, minor := proto[5], proto[7]
	if major < '0' || major > '9' || minor < '0' || minor > '9' {
		return 0, 0, false
	}
	return int(major - '0'), int(minor - '0'), true
}

func validTarget(target string) bool {
	if target == "" {
		return false
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}
