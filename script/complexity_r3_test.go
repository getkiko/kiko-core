package script

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func desyncDepth(k, n int) string {
	var b strings.Builder
	b.WriteString("x={}/")
	for i := 0; i < k; i++ {
		b.WriteString(strings.Repeat("(", n))
		b.WriteString("\"" + strings.Repeat(")", n) + "\"")
	}
	b.WriteString("/1")
	return b.String()
}

// TestCheckSourceAmbiguousSlash: "}", ")" and "++" before a "/" can mean division or the start
// of a regular expression; the scan follows both readings, so neither can hide the nesting or
// the chain from it.
func TestCheckSourceAmbiguousSlash(t *testing.T) {
	cases := map[string]string{
		"depth k=130":        desyncDepth(130, 1900),
		"depth k=250":        desyncDepth(250, 1900),
		"depth after ++":     "a++ /" + strings.TrimPrefix(desyncDepth(130, 1900), "x={}/"),
		"depth after paren":  "x=(1)/" + strings.TrimPrefix(desyncDepth(130, 1900), "x={}/"),
		"depth after --":     "a-- /" + strings.TrimPrefix(desyncDepth(130, 1900), "x={}/"),
		"depth in templates": "x={}/" + strings.Repeat("(", 30000) + "`)`" + strings.Repeat("(", 30000) + "/1",
		"chain":              "x={}/" + strings.Repeat("1+", 100000) + "1/1",
		"chain after ++":     "a++/" + strings.Repeat("1+", 100000) + "1/1",
		"chain after paren":  "x=(1)/" + strings.Repeat("1+", 100000) + "1/1",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			require.Error(t, CheckSource(src, ScriptLimits))
			require.Error(t, compileSource(src))
			require.Less(t, time.Since(started), time.Second)
		})
	}
	t.Run("eval chain", func(t *testing.T) {
		started := time.Now()
		require.Error(t, CheckSource("x={}/"+strings.Repeat("1+", 31000)+"1/1", EvalLimits))
		require.Error(t, CheckSource(desyncDepth(100, 299), EvalLimits))
		require.Less(t, time.Since(started), time.Second)
	})
}

// TestEvalRefusesDesyncedSource: the same shapes given to eval and Function in a running
// script are refused without the compile running.
func TestEvalRefusesDesyncedSource(t *testing.T) {
	m := newTestManager(t)
	for name, src := range map[string]string{
		"chain": "x={}/" + strings.Repeat("1+", 31000) + "1/1",
		"depth": desyncDepth(100, 299),
	} {
		js := "var s=" + strconv.Quote(src) + "; var r='none'; try{ eval(s) }catch(e){ r='refused' } try{ Function(s) }catch(e){ r+='+refused' } $done({headers:{'X-R':r}})"
		cfg := httpConfig("h", PhaseRequest, js)
		cfg.Timeout = time.Second
		started := time.Now()
		res := runOne(t, m, cfg, reqInput("https://e/"))
		require.Equal(t, ActionModify, res.Action, "%s: %s", name, res.Error)
		require.Equal(t, "refused+refused", headerValue(res.Headers, "X-R"), name)
		require.Less(t, time.Since(started), time.Second, name)
	}
}

// TestCompileSlotsBoundAbandonedCompiles: compiles that overrun are abandoned but keep their
// slot until goja returns, so more of them are refused instead of piling up.
func TestCompileSlotsBoundAbandonedCompiles(t *testing.T) {
	oldTimeout, oldWait := CompileTimeout, CompileBusyWait
	defer func() { CompileTimeout, CompileBusyWait = oldTimeout, oldWait }()
	CompileTimeout, CompileBusyWait = 50*time.Millisecond, 100*time.Millisecond
	// About 10k terms is a compile of several hundred milliseconds.
	src := "var x=" + strings.Repeat("1+", 40000) + "1;"
	var errs []error
	for range 4 {
		_, err := compileProgram("s", src)
		errs = append(errs, err)
	}
	busy := 0
	for _, err := range errs {
		require.Error(t, err)
		if strings.Contains(err.Error(), "busy") {
			busy++
		}
	}
	require.Positive(t, busy, "%v", errs)
	require.Eventually(t, func() bool { return len(compileSlots) == 0 }, 120*time.Second, 100*time.Millisecond)
}

// syntheticMinified builds a source of about size bytes in the style of a minified bundle:
// many short functions with calls, member access, conditionals and strings.
func syntheticMinified(size int) string {
	var b strings.Builder
	b.WriteString("var m={};")
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "m.f%d=function(a,b){var c=a&&b?a.x[%d]+b.y.z:(a||b)/%d;if(c>1){return c-1}else{for(var i=0;i<c;i++){a.p(i,'k%d',{v:c*2})}}return[c,a.q(b),\"s%d\"].join('-')};", i, i%7, i%9+1, i, i)
	}
	return b.String()
}

func TestLargeLegitSourcesAreAccepted(t *testing.T) {
	src := syntheticMinified(MaxSourceSize - 4096)
	require.Less(t, len(src), MaxSourceSize)
	started := time.Now()
	require.NoError(t, CheckSource(src, ScriptLimits))
	scan := time.Since(started)
	started = time.Now()
	require.NoError(t, compileSource(src))
	t.Logf("synthetic %d bytes: openers/operators ok, scan %s, compile %s", len(src), scan, time.Since(started))
	require.Less(t, scan, 2*time.Second)

	// The same shape with long arithmetic and many divisions after ")" and "}".
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, "var v%d=(%d+1)/2+(%d)/3;if(v%d){}\n/x%d/.test('a');\n", i, i, i, i, i)
	}
	require.NoError(t, CheckSource(b.String(), ScriptLimits))
	require.NoError(t, compileSource(b.String()))
}

// genExpr builds an expression whose bracket nesting is exactly depth, mixing in strings and
// regular expressions full of brackets and quotes, and divisions after ")" and "++".
func genExpr(rng *rand.Rand, depth int) string {
	atoms := []string{
		`1`, `"(([["`, `')'`, "`]]}}`", `/'[(]/.source`, `/[/*]/.source`, `/"\//.source`, `a++/1`, `a--/2/1`,
		`"/*"`, `'//'`, `"it's"`,
	}
	if depth == 0 {
		return atoms[rng.Intn(len(atoms))]
	}
	inner := genExpr(rng, depth-1)
	switch rng.Intn(6) {
	case 0:
		return "(" + inner + ")"
	case 1:
		return "[" + inner + "]"
	case 2:
		return "f(" + inner + ")"
	case 3:
		return "({a:" + inner + "})"
	case 4:
		// A division after ")" next to a nested part.
		return "(" + inner + ")/1/(1)"
	default:
		return "(" + inner + ")+" + genExpr(rng, rng.Intn(depth))
	}
}

// TestCheckSourceDepthAgreesWithConstruction: for programs built to a known nesting depth,
// the scan accepts at that depth and refuses one below, even though strings and regular
// expressions inside contain brackets, quotes and slashes.
func TestCheckSourceDepthAgreesWithConstruction(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 1500; i++ {
		depth := 1 + rng.Intn(14)
		expr := genExpr(rng, depth)
		src := "var a=1,f=function(x){return x};\nvar r=" + expr + ";\n"
		require.NoError(t, compileSource(src), "generator produced an invalid program: %q", src)
		want := nesting(expr)
		limits := SourceLimits{Length: 1 << 20, Depth: want, Chain: 100000, Openers: 100000, Operators: 100000}
		require.NoError(t, CheckSource(src, limits), "depth %d: %q", want, src)
		limits.Depth = want - 1
		if want > 0 {
			require.Error(t, CheckSource(src, limits), "depth %d should be refused at %d: %q", want, want-1, src)
		}
	}
}

// nesting measures the bracket depth of a generated expression the way the generator built
// it: brackets that are inside a quoted atom are not structure. The atoms are known.
func nesting(expr string) int {
	for _, atom := range []string{`"(([["`, `')'`, "`]]}}`", `/'[(]/.source`, `/[/*]/.source`, `/"\//.source`, `"/*"`, `'//'`, `"it's"`} {
		expr = strings.ReplaceAll(expr, atom, "1")
	}
	depth, deepest := 0, 0
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '(', '[', '{':
			depth++
			deepest = max(deepest, depth)
		case ')', ']', '}':
			depth--
		}
	}
	return deepest
}

// TestCheckSourceNeverFooledByRandomMixes: random mixes of the confusing tokens either fail
// goja's own parse or, when they compile, are accepted by the scan only if their true nesting
// (measured with goja on a copy with small limits applied through the scan) is within bounds.
// Here the property is the cheap half: no panic, no hang, and a source the scan accepts under
// tiny limits compiles quickly.
func TestCheckSourceNeverFooledByRandomMixes(t *testing.T) {
	pieces := []string{"}", ")", "]", "(", "[", "{", "++", "--", "/", "/", "//", "/*", "*/", `"`, `'`, "`", "${", `"/"`, `'"'`,
		`/[)]/`, `/'/`, "a", "1", "+", ";", ",", "\n", " ", "return ", "x=", "typeof ", "=>"}
	rng := rand.New(rand.NewSource(21))
	tiny := SourceLimits{Length: 1 << 16, Depth: 6, Chain: 12, Openers: 40, Operators: 80}
	accepted := 0
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := 1 + rng.Intn(30); n > 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		src := b.String()
		started := time.Now()
		if CheckSource(src, tiny) != nil {
			continue
		}
		accepted++
		_ = compileSource(src)
		require.Less(t, time.Since(started), time.Second, "%q", src)
	}
	require.Positive(t, accepted)
}

type stmtAtom struct {
	src   string
	depth int
}

// stmtAtoms are valid statements whose first "/" after ")", "}" or "++" divides or starts a
// regular expression depending on what precedes it, with decoy brackets and quotes inside.
var stmtAtoms = []stmtAtom{
	{`if(a)/'[(]/.test("x");`, 1},
	{"function g1_@(){}\n/\"[)]/.test(\"x\");", 1},
	{`var g2=function(){return 1}/1;`, 1},
	{`var g3=class{}/1;`, 1},
	{"class G4_@{}\n/'[{]/.test(\"x\");", 1},
	{"{}\n/'/.test(\"x\");", 1},
	{`var o={a:1}/2;`, 1},
	{`while(0)/"[(]/.test("x");`, 1},
	{"var t=`${(1)/2}`+\"`(((\";", 2},
	{`x=a++/1;`, 0},
	{"x=a--\n/2/1;", 0},
	{`for(;0;)/[(]/.test(1);`, 1},
	{`var h=(function(){return 2})()/1;`, 2},
	{`var k=async function(){}/1;`, 1},
	{"async function k2_@(){}\n/'/.test(1);", 1},
	{`try{}catch(e){}` + "\n" + `/'[(]/.test(1);`, 1},
	{`switch(a){case 1:break}` + "\n" + `/"[(]/.test(1);`, 1},
	{`var fa=(1)/(2)/(3)+[1][0]/2;`, 1},
	{`x=typeof /'[(]/;`, 0},
	{`x=[/'/,/"/][0]/1;`, 1},
	{`if(a){x=1}else/'[(]/.test(1);`, 1},
	{`label:{x=1}` + "\n" + `/'[(]/.test(1);`, 1},
}

func genStmts(rng *rand.Rand, wraps int) (string, int) {
	var b strings.Builder
	deepest := 0
	for n := 1 + rng.Intn(4); n > 0; n-- {
		atom := stmtAtoms[rng.Intn(len(stmtAtoms))]
		b.WriteString(strings.ReplaceAll(atom.src, "@", strconv.Itoa(rng.Intn(1<<30))))
		b.WriteString("\n")
		deepest = max(deepest, atom.depth)
	}
	body := b.String()
	for ; wraps > 0; wraps-- {
		body = "(function(){\n" + body + "\n})();\n"
		deepest += 2
	}
	return body, deepest
}

// TestCheckSourceStatementDepthAgreesWithConstruction: programs mixing statements whose "/"
// reads differently are measured exactly: accepted at their depth, refused one below.
func TestCheckSourceStatementDepthAgreesWithConstruction(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 3000; i++ {
		body, depth := genStmts(rng, rng.Intn(6))
		src := "var a=1,x;\n" + body
		require.NoError(t, compileSource(src), "generator produced an invalid program: %q", src)
		limits := SourceLimits{Length: 1 << 20, Depth: depth, Chain: 100000, Openers: 100000, Operators: 100000}
		require.NoError(t, CheckSource(src, limits), "depth %d: %q", depth, src)
		if depth > 0 {
			limits.Depth = depth - 1
			require.Error(t, CheckSource(src, limits), "depth %d should be refused: %q", depth, src)
		}
	}
}
