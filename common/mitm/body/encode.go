package body

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Encode compresses data according to a Content-Encoding value. The codings are
// applied in the order listed, the order a sender applies them, so Decode with the
// same value restores data. "identity" entries are skipped. An unknown coding yields
// an *Error of kind ErrUnsupported.
func Encode(encoding string, data []byte) ([]byte, error) {
	encodings := ParseEncodings(encoding)
	current := data
	for _, name := range encodings {
		next, err := encodeOne(name, current)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func encodeOne(name string, data []byte) ([]byte, error) {
	var out bytes.Buffer
	switch name {
	case "gzip", "x-gzip":
		w := gzip.NewWriter(&out)
		if _, err := w.Write(data); err != nil {
			return nil, &Error{Kind: ErrCorrupt, Encoding: name, Err: err}
		}
		if err := w.Close(); err != nil {
			return nil, &Error{Kind: ErrCorrupt, Encoding: name, Err: err}
		}
	case "deflate":
		w := zlib.NewWriter(&out)
		if _, err := w.Write(data); err != nil {
			return nil, &Error{Kind: ErrCorrupt, Encoding: name, Err: err}
		}
		if err := w.Close(); err != nil {
			return nil, &Error{Kind: ErrCorrupt, Encoding: name, Err: err}
		}
	case "br":
		w := brotli.NewWriter(&out)
		if _, err := w.Write(data); err != nil {
			return nil, &Error{Kind: ErrCorrupt, Encoding: name, Err: err}
		}
		if err := w.Close(); err != nil {
			return nil, &Error{Kind: ErrCorrupt, Encoding: name, Err: err}
		}
	case "zstd":
		w, err := zstd.NewWriter(io.Discard, zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true), zstd.WithWindowSize(4<<20))
		if err != nil {
			return nil, &Error{Kind: ErrUnsupported, Encoding: name, Err: err}
		}
		result := w.EncodeAll(data, make([]byte, 0, len(data)/2+64))
		_ = w.Close()
		return result, nil
	default:
		return nil, &Error{Kind: ErrUnsupported, Encoding: name}
	}
	return out.Bytes(), nil
}
