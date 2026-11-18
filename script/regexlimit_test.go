package script

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRegexCollectingOperationsAreBounded: operations that build one object per match used
// to take gigabytes on a big string. Above the input limit they are refused quickly, below
// it ordinary use works.
func TestRegexCollectingOperationsAreBounded(t *testing.T) {
	m := newTestManager(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for name, src := range map[string]string{
		"match g 30MiB":     `'a'.repeat(30*1024*1024).match(/a/g)`,
		"match g 60MiB":     `'a'.repeat(60*1024*1024).match(/a/g)`,
		"replace fn":        `'a'.repeat(30*1024*1024).replace(/a/g, function (x) { return x })`,
		"matchAll":          `var n = 0; for (var x of 'a'.repeat(30*1024*1024).matchAll(/a/g)) n++;`,
		"replaceAll fn":     `'a'.repeat(30*1024*1024).replaceAll(/a/g, function (x) { return 'b' })`,
		"split regex":       `'a'.repeat(30*1024*1024).split(/a/)`,
		"just over the cap": `'a'.repeat(1024*1024+1).match(/a/g)`,
		"two near the cap":  `var s = 'a'.repeat(1024*1024); s.match(/a/g); s.match(/a/g); s.match(/a/g); s.match(/a/g); s.match(/a/g)`,
	} {
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			res := runOne(t, m, genericConfig("r", src), nil)
			require.Equal(t, ActionLimit, res.Action, res.Error)
			require.Less(t, time.Since(started), 8*time.Second)
		})
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	require.Less(t, int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(400<<20), "heap after refused operations")
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(3<<30), "bytes allocated by refused operations")
}

func TestRegexOrdinaryUseStillWorks(t *testing.T) {
	m := newTestManager(t)
	cfg := httpConfig("ok", PhaseResponse, `
var b = $response.body;
var n = b.match(/./g).length;
var parts = b.split(/,/).length;
var up = b.replace(/[a-z]/g, function (c) { return c.toUpperCase() });
var all = Array.from(b.matchAll(/b/g)).length;
$done({headers: {'X-N': String(n), 'X-Parts': String(parts), 'X-All': String(all)}, body: up});`)
	cfg.RequiresBody = true
	res := runOne(t, m, cfg, respInput(200, "ab,cb,db"))
	require.Equal(t, ActionModify, res.Action, res.Error)
	require.Equal(t, "8", headerValue(res.Headers, "X-N"))
	require.Equal(t, "3", headerValue(res.Headers, "X-Parts"))
	require.Equal(t, "3", headerValue(res.Headers, "X-All"))
	require.Equal(t, "AB,CB,DB", string(res.Body))

	// A 256 KiB body with a collecting regex is within the allowance.
	res = runOne(t, m, genericConfig("big", `var s = 'ab'.repeat(128*1024); $done({n: s.match(/a/g).length, r: s.replace(/a/g, 'x').length})`), nil)
	require.Equal(t, ActionNone, res.Action, res.Error)
	require.JSONEq(t, `{"n":131072,"r":262144}`, res.Output)
}

func genericConfig(tag, src string) Config {
	return Config{Tag: tag, Type: PhaseGeneric, Source: src}
}
