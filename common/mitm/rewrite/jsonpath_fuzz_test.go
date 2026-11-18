package rewrite

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// FuzzJSONPathShape builds documents of a chosen depth and fan-out and runs wildcard and
// recursive paths over them. Invariants: bounded time, bounded output (never over the limit),
// valid JSON after a change.
func FuzzJSONPathShape(f *testing.F) {
	f.Add(uint8(3), uint8(3), uint8(0), "$..a", `"x"`)
	f.Add(uint8(40), uint8(1), uint8(1), "$..*", `[1]`)
	f.Add(uint8(200), uint8(1), uint8(2), "$..[*]..[*]", `null`)
	f.Add(uint8(2), uint8(200), uint8(0), "$[*][*][*]", `"`+strings.Repeat("y", 1000)+`"`)
	f.Add(uint8(10), uint8(4), uint8(1), "$..['a','b']..[0,1,2]", `{}`)
	f.Fuzz(func(t *testing.T, depth, fan, action uint8, path, value string) {
		if len(path) > 200 || len(value) > 4096 || !json.Valid([]byte(value)) {
			return
		}
		doc := genDoc(int(depth)%80, int(fan)%12)
		edit := option.MITMBodyRewriteEdit{Path: path, Value: value}
		switch action % 3 {
		case 0:
			edit.Action = EditJSONSet
		case 1:
			edit.Action = EditJSONDelete
		default:
			edit.Action = EditJSONAppend
		}
		set, err := Compile(context.Background(), bodyOptions(option.MITMBodyRewriteRule{Pattern: ".", Scope: "response", ContentTypes: []string{"x"}, Edits: []option.MITMBodyRewriteEdit{edit}}))
		if err != nil {
			return
		}
		const limit = 1 << 20
		start := time.Now()
		res := set.Plan("https", "h", "/").ApplyBody("response", "x", "", doc, limit)
		if time.Since(start) > 20*time.Second {
			t.Fatalf("path %q took %v", path, time.Since(start))
		}
		if res.Changed && (len(res.Data) > limit || !json.Valid(res.Data)) {
			t.Fatalf("path %q gave %d bytes, valid=%v", path, len(res.Data), json.Valid(res.Data))
		}
		if !res.Changed && !bytes.Equal(res.Data, doc) {
			t.Fatal("unchanged result differs")
		}
	})
}

func genDoc(depth, fan int) []byte {
	var b bytes.Buffer
	var build func(d int)
	budget := 20000
	build = func(d int) {
		budget--
		if d <= 0 || budget <= 0 {
			b.WriteString(`{"a":1,"b":[1,2]}`)
			return
		}
		b.WriteByte('[')
		for i := 0; i < max(fan, 1); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if i == 0 {
				b.WriteString(`{"a":`)
				build(d - 1)
				b.WriteByte('}')
			} else {
				b.WriteString(`"s"`)
			}
		}
		b.WriteByte(']')
	}
	build(depth)
	return b.Bytes()
}
