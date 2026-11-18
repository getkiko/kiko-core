package body

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type bufferSink struct {
	data  []byte
	limit int
}

func (s *bufferSink) WriteBody(p []byte) bool {
	if s.limit > 0 && len(s.data)+len(p) > s.limit {
		return false
	}
	s.data = append(s.data, p...)
	return true
}

func TestTeeTruncatesAndPassesThrough(t *testing.T) {
	sink := &bufferSink{}
	tee := &Tee{Limit: 10, Sink: sink}
	source := strings.Repeat("a", 25)
	var out bytes.Buffer
	n, err := io.Copy(&out, tee.Reader(strings.NewReader(source)))
	if err != nil || n != 25 || out.String() != source {
		t.Fatalf("forwarded %d %v", n, err)
	}
	if len(sink.data) != 10 || !tee.Truncated() || tee.Total() != 25 || tee.Saved() != 10 {
		t.Fatalf("sink=%d truncated=%v total=%d", len(sink.data), tee.Truncated(), tee.Total())
	}
}

func TestTeeWithinLimitIsNotTruncated(t *testing.T) {
	sink := &bufferSink{}
	tee := &Tee{Limit: 10, Sink: sink}
	var out bytes.Buffer
	if _, err := io.Copy(tee.Writer(&out), strings.NewReader("0123456789")); err != nil {
		t.Fatal(err)
	}
	if tee.Truncated() || string(sink.data) != "0123456789" {
		t.Fatalf("%q %v", sink.data, tee.Truncated())
	}
}

func TestTeeCountOnly(t *testing.T) {
	tee := &Tee{}
	tee.Write([]byte("abc"))
	if tee.Total() != 3 || tee.Truncated() || tee.Saved() != 0 {
		t.Fatalf("%d %v", tee.Total(), tee.Truncated())
	}
}

func TestTeeSinkRefusal(t *testing.T) {
	sink := &bufferSink{limit: 4}
	tee := &Tee{Limit: 100, Sink: sink}
	tee.Write([]byte("abc"))
	tee.Write([]byte("defg"))
	tee.Write([]byte("h"))
	if string(sink.data) != "abc" || !tee.Truncated() || tee.Total() != 8 {
		t.Fatalf("%q %v %d", sink.data, tee.Truncated(), tee.Total())
	}
}

func compress(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		w := gzip.NewWriter(&buf)
		w.Write(data)
		w.Close()
	case "deflate":
		w := zlib.NewWriter(&buf)
		w.Write(data)
		w.Close()
	case "deflate-raw":
		w, _ := flate.NewWriter(&buf, 6)
		w.Write(data)
		w.Close()
	case "br":
		w := brotli.NewWriter(&buf)
		w.Write(data)
		w.Close()
	case "zstd":
		w, _ := zstd.NewWriter(&buf)
		w.Write(data)
		w.Close()
	}
	return buf.Bytes()
}

func TestDecodeFormats(t *testing.T) {
	plain := []byte(strings.Repeat("hello kiko ", 200))
	for _, encoding := range []string{"gzip", "deflate", "deflate-raw", "br", "zstd"} {
		header := encoding
		if encoding == "deflate-raw" {
			header = "deflate"
		}
		got, err := Decode(header, bytes.NewReader(compress(t, encoding, plain)), Limits{})
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%s: err=%v len=%d", encoding, err, len(got))
		}
	}
}

func TestDecodeIdentityAndCase(t *testing.T) {
	got, err := Decode("identity", strings.NewReader("raw"), Limits{})
	if err != nil || string(got) != "raw" {
		t.Fatal(got, err)
	}
	got, err = Decode(" GZip ", bytes.NewReader(compress(t, "gzip", []byte("x"))), Limits{})
	if err != nil || string(got) != "x" {
		t.Fatal(got, err)
	}
}

func TestDecodeMultipleEncodingsReverseOrder(t *testing.T) {
	plain := []byte(strings.Repeat("layered ", 300))
	// Content-Encoding: gzip, br means gzip was applied first, then br.
	wire := compress(t, "br", compress(t, "gzip", plain))
	got, err := Decode("gzip, br", bytes.NewReader(wire), Limits{})
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("err=%v len=%d", err, len(got))
	}
	_, err = Decode("br, gzip", bytes.NewReader(wire), Limits{})
	if err == nil {
		t.Fatal("wrong order must fail")
	}
}

func TestDecodeBombRatio(t *testing.T) {
	plain := make([]byte, 64<<20)
	wire := compress(t, "gzip", plain)
	got, err := Decode("gzip", bytes.NewReader(wire), Limits{MaxOutput: 128 << 20})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrBomb {
		t.Fatalf("err=%v", err)
	}
	if int64(len(got)) > int64(len(wire))*DefaultMaxRatio+DefaultRatioSlack+(1<<20) {
		t.Fatalf("decoded %d bytes from %d", len(got), len(wire))
	}
}

func TestDecodeOutputLimit(t *testing.T) {
	plain := bytes.Repeat([]byte("noise-"), 1000)
	got, err := Decode("gzip", bytes.NewReader(compress(t, "gzip", plain)), Limits{MaxOutput: 100, MaxRatio: 1 << 20})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrOutputLimit || len(got) != 100 {
		t.Fatalf("err=%v len=%d", err, len(got))
	}
}

func TestDecodeCorruptKeepsPartial(t *testing.T) {
	plain := []byte(strings.Repeat("0123456789abcdef", 4096))
	wire := compress(t, "gzip", plain)
	got, err := Decode("gzip", bytes.NewReader(wire[:len(wire)/2]), Limits{})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrCorrupt {
		t.Fatalf("err=%v", err)
	}
	if len(got) == 0 || !bytes.HasPrefix(plain, got) {
		t.Fatalf("partial result %d bytes", len(got))
	}
	_, err = Decode("gzip", strings.NewReader("not gzip at all"), Limits{})
	if !errors.As(err, &typed) || typed.Kind != ErrCorrupt {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeUnsupported(t *testing.T) {
	got, err := Decode("compress", strings.NewReader("x"), Limits{})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrUnsupported || got != nil {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseEncodings(t *testing.T) {
	got := ParseEncodings(" GZip, identity ,br,")
	if len(got) != 2 || got[0] != "gzip" || got[1] != "br" {
		t.Fatalf("%v", got)
	}
}
