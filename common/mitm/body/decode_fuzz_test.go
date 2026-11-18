package body

import (
	"bytes"
	"testing"
	"testing/iotest"
)

// FuzzDecodeArbitrary feeds arbitrary bytes to every decoder path. Invariants: no panic, the
// output stays within MaxOutput, and a success never exceeds the ratio bound.
func FuzzDecodeArbitrary(f *testing.F) {
	for _, seed := range []string{"hello", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff", "\x28\xb5\x2f\xfd\x00", "\x78\x9c\x03\x00\x00\x00\x00\x01", "\x0b\x00\x80", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00"} {
		for pick := range uint8(8) {
			f.Add([]byte(seed), pick, false)
		}
	}
	// A real bomb: 4 MiB of zeroes in every format.
	zeros := make([]byte, 4<<20)
	for _, name := range []string{"gzip", "deflate", "br", "zstd", "gzip, br"} {
		if encoded, err := Encode(name, zeros); err == nil {
			f.Add(encoded, uint8(0), false)
		}
	}
	names := []string{"gzip", "deflate", "br", "zstd", "gzip, br", "br, zstd, gzip", "x-gzip", "unknown"}
	f.Fuzz(func(t *testing.T, data []byte, pick uint8, slow bool) {
		encoding := names[int(pick)%len(names)]
		limits := Limits{MaxOutput: 1 << 20, MaxRatio: 50, RatioSlack: 16 << 10}
		var src = bytes.NewReader(data)
		var out []byte
		var err error
		if slow {
			out, err = Decode(encoding, iotest.OneByteReader(src), limits)
		} else {
			out, err = Decode(encoding, src, limits)
		}
		if int64(len(out)) > limits.MaxOutput {
			t.Fatalf("output %d over the limit", len(out))
		}
		if err == nil && int64(len(out)) > int64(len(data))*limits.MaxRatio+limits.RatioSlack {
			t.Fatalf("output %d from %d bytes passes the ratio bound", len(out), len(data))
		}
	})
}
