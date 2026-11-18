package capture

import (
	"errors"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

// FuzzCaptureOps drives the store with a random program of exchange events under tiny limits.
// Invariants: no panic, record count stays within MaxRecords (plus exchanges in progress), and
// once every exchange finished the store is back within its memory budget.
func FuzzCaptureOps(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	f.Add([]byte{0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11})
	f.Add([]byte{0, 3, 200, 3, 255, 4, 5, 7, 12, 13, 14, 15, 11, 0, 3, 200, 11})
	f.Fuzz(func(t *testing.T, program []byte) {
		if len(program) > 4096 {
			return
		}
		m := New(Options{Enabled: true, Body: true, MaxBody: 8 << 10, MaxMemory: 64 << 10, MaxRecords: 8})
		conn := &flow.ConnectionInfo{ID: "c"}
		var open []flow.Exchange
		encodings := []string{"", "gzip", "br", "zstd", "deflate", "x"}
		for i, op := range program {
			arg := 0
			if i+1 < len(program) {
				arg = int(program[i+1])
			}
			switch op % 16 {
			case 0:
				x := m.NewExchange(conn)
				x.RequestHead(flow.RequestHead{Method: "POST", Scheme: "https", Authority: "h.test:443", Path: "/" + strconv.Itoa(i), Proto: "h2",
					Headers: []flow.Header{{Name: "Content-Encoding", Value: encodings[arg%len(encodings)]}}})
				open = append(open, x)
			case 1, 2:
				if len(open) > 0 {
					open[arg%len(open)].ResponseHead(200+arg%3, []flow.Header{{Name: "Content-Encoding", Value: encodings[arg%len(encodings)]}})
				}
			case 3, 4, 5:
				if len(open) > 0 {
					x := open[arg%len(open)]
					chunk := make([]byte, arg*37)
					for j := range chunk {
						chunk[j] = byte(j * arg)
					}
					if op%2 == 0 {
						x.RequestBody().Write(chunk)
					} else {
						x.ResponseBody().Write(chunk)
					}
				}
			case 6:
				if len(open) > 0 {
					open[arg%len(open)].Trailers(flow.Response, []flow.Header{{Name: "X-T", Value: "v"}})
				}
			case 7:
				if len(open) > 0 {
					open[arg%len(open)].Upgrade(101, nil)
				}
			case 8:
				if len(open) > 0 {
					open[arg%len(open)].Rewritten([]flow.RewriteHit{{Kind: "body", Rule: "r", Action: "x"}})
				}
			case 9, 10:
				if len(open) > 0 {
					k := arg % len(open)
					x := open[k]
					x.RequestBody().Done()
					x.ResponseBody().Done()
					var err error
					if op%2 == 1 {
						err = errors.New("e")
					}
					x.Finish(err)
					open = append(open[:k], open[k+1:]...)
				}
			case 11:
				for _, side := range []flow.Side{flow.Request, flow.Response} {
					for id := 1; id <= 24; id++ {
						_, _ = m.GetBody(BodyRequest{ID: strconv.Itoa(id), Side: side, Offset: int64(arg), Length: int64(arg), Decoded: arg%2 == 0})
					}
				}
			case 12:
				m.List(Filter{Search: "h", Limit: arg})
			case 13:
				m.Poll("", 0)
			case 14:
				if arg%16 == 0 {
					m.Clear()
				}
			case 15:
				m.SetOptions(Options{Enabled: true, Body: arg%2 == 0, MaxBody: int64(arg) * 64, MaxMemory: int64(arg+1) << 10, MaxRecords: arg%12 + 1})
			}
			s := m.Stats()
			if s.Records > s.MaxRecords+s.InProgress || s.Bytes < 0 {
				t.Fatalf("after op %d: %+v", i, s)
			}
		}
		for _, x := range open {
			x.RequestBody().Done()
			x.ResponseBody().Done()
			x.Finish(nil)
		}
		if s := m.Stats(); s.InProgress != 0 || s.Bytes > s.MaxMemory || s.Records > s.MaxRecords {
			t.Fatalf("settled store over budget: %+v", s)
		}
	})
}
