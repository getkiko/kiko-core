package script

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/dop251/goja"
)

const (
	// MaxUngzip is the largest output of $utils.ungzip.
	MaxUngzip   = 64 << 20
	ungzipChunk = 1 << 20
)

// installUtilsNatives registers the natives behind $utils.
func (e *vmEntry) installUtilsNatives(setNative func(string, func(goja.FunctionCall) goja.Value)) {
	rt := e.rt
	setNative("ungzip", func(call goja.FunctionCall) goja.Value {
		in, ok := bytesOf(call.Argument(0))
		if !ok {
			panic(rt.NewTypeError("$utils.ungzip needs an ArrayBuffer or a typed array"))
		}
		cs := e.cs
		if cs == nil {
			panic(rt.NewTypeError("$utils is not available"))
		}
		zr, err := gzip.NewReader(bytes.NewReader(in))
		if err != nil {
			panic(rt.NewTypeError("$utils.ungzip: " + err.Error()))
		}
		// Two passes keep the memory exact: the first only counts the output (bounded by the
		// hard cap and by what the call may still allocate), the second fills a buffer of
		// that size, which is charged before it is allocated.
		chunk := make([]byte, ungzipChunk)
		limit := min(int64(MaxUngzip), AllocationLimit-cs.charged)
		var total int64
		for {
			if cs.interrupted() != "" {
				panic(rt.NewTypeError("$utils.ungzip: interrupted"))
			}
			n, err := zr.Read(chunk)
			total += int64(n)
			if total > limit {
				e.overLimit()
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				panic(rt.NewTypeError("$utils.ungzip: " + err.Error()))
			}
		}
		if !cs.charge(total) {
			e.overLimit()
		}
		out := make([]byte, total)
		if err := zr.Reset(bytes.NewReader(in)); err != nil {
			panic(rt.NewTypeError("$utils.ungzip: " + err.Error()))
		}
		if _, err := io.ReadFull(zr, out); err != nil && total > 0 {
			panic(rt.NewTypeError("$utils.ungzip: " + err.Error()))
		}
		return e.newUint8Array(out)
	})
}
