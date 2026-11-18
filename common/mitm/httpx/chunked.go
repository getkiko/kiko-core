package httpx

import (
	"bufio"
	"io"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http/httpguts"
)

// MaxChunkSizeLine is the longest accepted chunk size line, extensions and CRLF included.
const MaxChunkSizeLine = 4096

var (
	ErrChunkSizeLine = E.New("malformed chunk size line")
	ErrChunkData     = E.New("chunk data not followed by CRLF")
)

var crlf = []byte("\r\n")

// ChunkedReader decodes a chunked body. Chunk extensions are ignored; the trailer section is
// parsed with the header rules and limits (DefaultLimits.Header bytes, DefaultLimits.Fields
// fields) and available from Trailer after io.EOF. Read returns io.EOF after the last chunk and
// io.ErrUnexpectedEOF when the stream ends early. The zero value is not usable; see Reset.
type ChunkedReader struct {
	r         *bufio.Reader
	remaining int64
	inChunk   bool // a chunk was read and its trailing CRLF is pending
	err       error
	// Trailer storage, kept across Reset.
	trailer Header
	scratch []byte
	ends    []int
}

// NewChunkedReader returns a reader decoding the chunked body that follows in r.
func NewChunkedReader(r *bufio.Reader) *ChunkedReader {
	c := &ChunkedReader{}
	c.Reset(r)
	return c
}

// Reset prepares c to decode a new body from r, reusing the trailer storage.
func (c *ChunkedReader) Reset(r *bufio.Reader) {
	clear(c.trailer)
	*c = ChunkedReader{r: r, trailer: c.trailer[:0], scratch: c.scratch[:0], ends: c.ends[:0]}
}

// Trailer returns the trailer fields once Read returned io.EOF; nil before. The fields are
// valid until the next Reset, and may be edited in place.
func (c *ChunkedReader) Trailer() Header {
	if c.err != io.EOF {
		return nil
	}
	return c.trailer
}

func (c *ChunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.remaining == 0 {
		if err := c.next(); err != nil {
			c.err = err
			return 0, err
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		c.err = err
	}
	return n, err
}

// next consumes the CRLF after the previous chunk and the next size line, and the trailer
// section after the last chunk.
func (c *ChunkedReader) next() error {
	if c.inChunk {
		if err := expectCRLF(c.r); err != nil {
			return err
		}
		c.inChunk = false
	}
	line, err := c.r.ReadSlice('\n')
	if err != nil {
		if err == bufio.ErrBufferFull {
			return ErrChunkSizeLine
		}
		return unexpected(err)
	}
	if len(line) > MaxChunkSizeLine {
		return ErrChunkSizeLine
	}
	size, err := parseChunkSize(line)
	if err != nil {
		return err
	}
	if size == 0 {
		if err = c.readTrailer(); err != nil {
			return err
		}
		return io.EOF
	}
	c.remaining = size
	c.inChunk = true
	return nil
}

func parseChunkSize(line []byte) (int64, error) {
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return 0, ErrChunkSizeLine
	}
	line = line[:len(line)-2]
	var size int64
	digits := 0
	i := 0
	for ; i < len(line); i++ {
		c := line[i]
		var v byte
		switch {
		case '0' <= c && c <= '9':
			v = c - '0'
		case 'a' <= c && c <= 'f':
			v = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			v = c - 'A' + 10
		default:
			goto rest
		}
		digits++
		if digits > 15 {
			return 0, ErrChunkSizeLine
		}
		size = size<<4 | int64(v)
	}
rest:
	if digits == 0 {
		return 0, ErrChunkSizeLine
	}
	if !validChunkExtensions(line[i:]) {
		return 0, ErrChunkSizeLine
	}
	return size, nil
}

// validChunkExtensions checks the chunk extensions after the size against RFC 9112 section 7.1.1:
// *( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] ). Extensions are ignored, but
// a malformed one (an unterminated quoted string in particular) could be read differently by a
// peer that does interpret them.
func validChunkExtensions(ext []byte) bool {
	i := skipBWS(ext, 0)
	for i < len(ext) {
		if ext[i] != ';' {
			return false
		}
		i = skipBWS(ext, i+1)
		start := i
		for i < len(ext) && isTokenByte(ext[i]) {
			i++
		}
		if i == start {
			return false
		}
		i = skipBWS(ext, i)
		if i < len(ext) && ext[i] == '=' {
			i = skipBWS(ext, i+1)
			if i < len(ext) && ext[i] == '"' {
				i++
				closed := false
				for i < len(ext) {
					c := ext[i]
					if c == '"' {
						closed = true
						i++
						break
					}
					if c == '\\' {
						i++
						if i == len(ext) || !isQuotedPairByte(ext[i]) {
							return false
						}
					} else if !isQDTextByte(c) {
						return false
					}
					i++
				}
				if !closed {
					return false
				}
			} else {
				start = i
				for i < len(ext) && isTokenByte(ext[i]) {
					i++
				}
				if i == start {
					return false
				}
			}
			i = skipBWS(ext, i)
		}
	}
	return true
}

func skipBWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return i
}

func isTokenByte(c byte) bool {
	return c < 0x80 && httpguts.IsTokenRune(rune(c))
}

// isQDTextByte: HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text (RFC 9110 section 5.6.4).
func isQDTextByte(c byte) bool {
	return c == '\t' || c == ' ' || c == 0x21 || c >= 0x23 && c <= 0x5b || c >= 0x5d && c <= 0x7e || c >= 0x80
}

// isQuotedPairByte: HTAB / SP / VCHAR / obs-text.
func isQuotedPairByte(c byte) bool {
	return c == '\t' || c >= 0x20 && c != 0x7f
}

func expectCRLF(r *bufio.Reader) error {
	b, err := r.Peek(2)
	if err != nil {
		return unexpected(err)
	}
	if b[0] != '\r' || b[1] != '\n' {
		return ErrChunkData
	}
	_, _ = r.Discard(2)
	return nil
}

// readTrailer reads the trailer section up to and including the empty line and parses its
// fields. Without trailer fields nothing is allocated.
func (c *ChunkedReader) readTrailer() error {
	limit := DefaultLimits.Header
	c.scratch = c.scratch[:0]
	c.ends = c.ends[:0]
	for {
		lineStart := len(c.scratch)
		for {
			chunk, err := c.r.ReadSlice('\n')
			if len(c.scratch)+len(chunk) > limit {
				return ErrHeaderTooLarge
			}
			c.scratch = append(c.scratch, chunk...)
			if err == nil {
				break
			}
			if err != bufio.ErrBufferFull {
				return unexpected(err)
			}
		}
		line := c.scratch[lineStart:]
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return ErrBareLF
		}
		if len(line) == 2 {
			break
		}
		c.ends = append(c.ends, len(c.scratch))
		if len(c.ends) > DefaultLimits.Fields {
			return ErrTooManyFields
		}
	}
	if len(c.ends) == 0 {
		return nil
	}
	section := string(c.scratch)
	begin := 0
	for _, end := range c.ends {
		line := section[begin : end-2]
		if strings.IndexByte(line, '\r') >= 0 {
			return ErrBareCR
		}
		field, err := parseField(line)
		if err != nil {
			return E.Cause(err, "trailer")
		}
		c.trailer = append(c.trailer, field)
		begin = end
	}
	return nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// ChunkedWriter encodes writes as chunks. Close writes the last chunk and an empty trailer
// section; it does not close the underlying writer.
type ChunkedWriter struct {
	w      io.Writer
	header [18]byte
}

// NewChunkedWriter returns a writer that chunk-encodes into w.
func NewChunkedWriter(w io.Writer) *ChunkedWriter {
	return &ChunkedWriter{w: w}
}

// Reset makes c write to w.
func (c *ChunkedWriter) Reset(w io.Writer) {
	c.w = w
}

const hexDigits = "0123456789abcdef"

// Write writes p as one chunk. An empty p writes nothing, since a zero-size chunk ends the body.
func (c *ChunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(c.header) - 2
	for size := uint64(len(p)); ; size >>= 4 {
		n--
		c.header[n] = hexDigits[size&0xf]
		if size < 16 {
			break
		}
	}
	c.header[len(c.header)-2] = '\r'
	c.header[len(c.header)-1] = '\n'
	if _, err := c.w.Write(c.header[n:]); err != nil {
		return 0, err
	}
	written, err := c.w.Write(p)
	if err != nil {
		return written, err
	}
	if _, err = c.w.Write(crlf); err != nil {
		return written, err
	}
	return written, nil
}

var lastChunk = []byte("0\r\n\r\n")

// Close writes the last chunk.
func (c *ChunkedWriter) Close() error {
	_, err := c.w.Write(lastChunk)
	return err
}
