package body

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEncodeRoundTrip(t *testing.T) {
	payloads := [][]byte{nil, []byte("a"), []byte(strings.Repeat("hello json ", 5000)), {0, 1, 2, 255, 254}}
	encodings := []string{"", "identity", "gzip", "x-gzip", "deflate", "br", "zstd", "gzip, br", "br, gzip", "deflate, zstd, gzip", "GZIP , identity"}
	for _, encoding := range encodings {
		for _, payload := range payloads {
			encoded, err := Encode(encoding, payload)
			if err != nil {
				t.Fatalf("%q encode: %v", encoding, err)
			}
			decoded, err := Decode(encoding, bytes.NewReader(encoded), Limits{})
			if err != nil {
				t.Fatalf("%q decode: %v", encoding, err)
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatalf("%q round trip mismatch (%d vs %d bytes)", encoding, len(decoded), len(payload))
			}
		}
	}
}

func TestEncodeChainOrder(t *testing.T) {
	encoded, err := Encode("gzip, br", []byte("ordered"))
	if err != nil {
		t.Fatal(err)
	}
	// Outermost coding is the last one listed: undoing br first must give a gzip stream.
	inner, err := Decode("br", bytes.NewReader(encoded), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decode("gzip", bytes.NewReader(inner), Limits{})
	if err != nil || string(plain) != "ordered" {
		t.Fatalf("got %q %v", plain, err)
	}
}

func TestEncodeUnsupported(t *testing.T) {
	_, err := Encode("gzip, compress", []byte("x"))
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrUnsupported {
		t.Fatalf("got %v", err)
	}
}

func FuzzEncodeDecode(f *testing.F) {
	f.Add([]byte("hello"), uint8(0))
	f.Add([]byte(strings.Repeat("ab", 1000)), uint8(5))
	names := []string{"gzip", "deflate", "br", "zstd", "gzip, br", "zstd, deflate", "", "br, zstd, gzip"}
	f.Fuzz(func(t *testing.T, data []byte, pick uint8) {
		encoding := names[int(pick)%len(names)]
		encoded, err := Encode(encoding, data)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(encoding, bytes.NewReader(encoded), Limits{MaxRatio: 1 << 20, RatioSlack: 1 << 30})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatal("round trip mismatch")
		}
	})
}
