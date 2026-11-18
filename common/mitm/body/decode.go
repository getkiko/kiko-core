package body

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Limits bound the work of Decode. A zero field takes the default.
type Limits struct {
	// MaxOutput is the most decoded bytes returned (default 8 MiB).
	MaxOutput int64
	// MaxRatio is the most decoded bytes per encoded byte (default 200).
	MaxRatio int64
	// RatioSlack lets small inputs expand before the ratio applies
	// (default 64 KiB of output).
	RatioSlack int64
}

const (
	DefaultMaxOutput  = 8 << 20
	DefaultMaxRatio   = 200
	DefaultRatioSlack = 64 << 10
)

// ErrKind classifies a decoding failure.
type ErrKind uint8

const (
	// ErrUnsupported means the encoding is unknown; no data is returned.
	ErrUnsupported ErrKind = iota + 1
	// ErrCorrupt means the stream is damaged or cut short; the data decoded
	// before the damage is returned.
	ErrCorrupt
	// ErrOutputLimit means decoding stopped at MaxOutput.
	ErrOutputLimit
	// ErrBomb means the expansion ratio was exceeded.
	ErrBomb
)

// Error is returned by Decode with the data decoded so far.
type Error struct {
	Kind     ErrKind
	Encoding string
	Err      error
}

func (e *Error) Error() string {
	var what string
	switch e.Kind {
	case ErrUnsupported:
		what = "unsupported content encoding"
	case ErrCorrupt:
		what = "corrupt or incomplete content"
	case ErrOutputLimit:
		what = "decoded size limit reached"
	case ErrBomb:
		what = "decompression ratio limit reached"
	default:
		what = "decode failed"
	}
	if e.Encoding != "" {
		what += " (" + e.Encoding + ")"
	}
	if e.Err != nil {
		what += ": " + e.Err.Error()
	}
	return what
}

func (e *Error) Unwrap() error { return e.Err }

// ParseEncodings splits a Content-Encoding value into lower-case tokens in
// the order they were applied by the sender. "identity" entries are dropped.
func ParseEncodings(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" || part == "identity" {
			continue
		}
		result = append(result, part)
	}
	return result
}

// Decode decodes r according to the Content-Encoding value. Encodings undo in
// reverse order. On failure it returns the data decoded so far and an *Error.
func Decode(encoding string, r io.Reader, limits Limits) (result []byte, err error) {
	// The third-party decoders panic on some malformed input (brotli v1.1.0 indexes out of range).
	defer func() {
		if recovered := recover(); recovered != nil {
			result, err = nil, &Error{Kind: ErrCorrupt, Encoding: encoding, Err: fmt.Errorf("decoder panic: %v", recovered)}
		}
	}()
	if limits.MaxOutput <= 0 {
		limits.MaxOutput = DefaultMaxOutput
	}
	if limits.MaxRatio <= 0 {
		limits.MaxRatio = DefaultMaxRatio
	}
	if limits.RatioSlack <= 0 {
		limits.RatioSlack = DefaultRatioSlack
	}
	encodings := ParseEncodings(encoding)
	counter := &countReader{r: r}
	var current io.Reader = counter
	var closers []func()
	defer func() {
		for _, closeFn := range closers {
			closeFn()
		}
	}()
	for i := len(encodings) - 1; i >= 0; i-- {
		next, closeFn, err := newDecoder(encodings[i], current)
		if err != nil {
			return nil, &Error{Kind: ErrUnsupported, Encoding: encodings[i], Err: err}
		}
		if closeFn != nil {
			closers = append(closers, closeFn)
		}
		current = next
	}
	var out bytes.Buffer
	buf := make([]byte, 16<<10)
	for {
		n, err := current.Read(buf)
		if n > 0 {
			room := limits.MaxOutput - int64(out.Len())
			if int64(n) > room {
				out.Write(buf[:room])
				return out.Bytes(), &Error{Kind: ErrOutputLimit, Encoding: encoding}
			}
			out.Write(buf[:n])
			if len(encodings) > 0 {
				allowed := counter.n*limits.MaxRatio + limits.RatioSlack
				if int64(out.Len()) > allowed {
					return out.Bytes(), &Error{Kind: ErrBomb, Encoding: encoding}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return out.Bytes(), nil
			}
			return out.Bytes(), &Error{Kind: ErrCorrupt, Encoding: encoding, Err: err}
		}
	}
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func newDecoder(encoding string, r io.Reader) (io.Reader, func(), error) {
	switch encoding {
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(r)
		if err != nil {
			return &failReader{err: err}, nil, nil
		}
		return reader, func() { _ = reader.Close() }, nil
	case "deflate":
		return newDeflate(r), nil, nil
	case "br":
		return brotli.NewReader(r), nil, nil
	case "zstd":
		decoder, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20), zstd.WithDecoderMaxWindow(32<<20))
		if err != nil {
			return nil, nil, err
		}
		return decoder, decoder.Close, nil
	default:
		return nil, nil, errors.New("unknown encoding")
	}
}

// failReader reports a deferred construction error as a read error, so a
// damaged header surfaces as corruption.
type failReader struct{ err error }

func (f *failReader) Read([]byte) (int, error) { return 0, f.err }

// newDeflate accepts zlib-wrapped data (RFC 9110) and raw deflate, which some
// servers send.
func newDeflate(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	head, _ := br.Peek(2)
	if len(head) == 2 && head[0]&0x0f == 8 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
		reader, err := zlib.NewReader(br)
		if err != nil {
			return &failReader{err: err}
		}
		return reader
	}
	return flate.NewReader(br)
}
