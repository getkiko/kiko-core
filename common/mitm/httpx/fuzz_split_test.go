package httpx

import (
	"bufio"
	"bytes"
	"io"
	"testing"
	"testing/iotest"
)

// FuzzChunkedSplit checks that the chunked decoder gives the same body, trailer and error
// class however the transport splits the stream: byte by byte, or in one piece.
func FuzzChunkedSplit(f *testing.F) {
	for _, seed := range chunkedSeeds {
		f.Add([]byte(seed))
	}
	f.Add([]byte("3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		read := func(r io.Reader) ([]byte, Header, error) {
			c := NewChunkedReader(bufio.NewReaderSize(r, MaxChunkSizeLine))
			out, err := io.ReadAll(c)
			return out, append(Header(nil), c.Trailer()...), err
		}
		whole, wholeTrailer, wholeErr := read(bytes.NewReader(data))
		slow, slowTrailer, slowErr := read(iotest.OneByteReader(bytes.NewReader(data)))
		if (wholeErr == nil) != (slowErr == nil) {
			t.Fatalf("errors differ: %v vs %v for %q", wholeErr, slowErr, data)
		}
		if wholeErr == nil && (!bytes.Equal(whole, slow) || !sameHeader(wholeTrailer, slowTrailer)) {
			t.Fatalf("split changes the result for %q", data)
		}
	})
}
