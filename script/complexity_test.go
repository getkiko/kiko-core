package script

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func compileSource(src string) error {
	_, err := compileSet([]Config{{Tag: "a", Type: PhaseRequest, Pattern: ".*", Source: src}}, nil)
	return err
}

// TestCheckSourceRegexLiteralsCannotHideNesting: a regular expression literal that looks
// like a comment, a string or an escape must not make the scanner skip the rest.
func TestCheckSourceRegexLiteralsCannotHideNesting(t *testing.T) {
	deep := strings.Repeat("(", 300000)
	for name, src := range map[string]string{
		"class with slash and star": `/[/*]/` + deep,
		"escaped slash":             `/a\//` + deep,
		"quote":                     `/'/` + deep,
		"quote after statement":     "var a = 1;\nx = /\"/;" + deep,
		"division then regex":       `a / b; /[/*]/` + deep,
		"long chain after quote":    `/'/;var x=1` + strings.Repeat("+1", 400000),
		"unterminated comment":      `/* ` + deep,
		"unterminated string":       "'abc" + deep,
		"unterminated regex":        "x = /abc" + deep,
	} {
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			require.Error(t, CheckSource(src, ScriptLimits))
			require.Error(t, compileSource(src))
			require.Less(t, time.Since(started), time.Second)
		})
	}
	// The eval limits refuse the same shapes.
	require.Error(t, CheckSource(`/'/`+strings.Repeat("(", 5000), EvalLimits))
}

func TestCheckSourceLegitRegexes(t *testing.T) {
	for name, src := range map[string]string{
		"comment-like":     `var a = /\/\*/.test(x);`,
		"quote":            `var b = /"/g; var c = /'/.test("it's");`,
		"division":         `var a = 6, b = 3, c = 2; var d = a/b/c;`,
		"class":            `var r = /[/]+[\]/]/i; r.test("/");`,
		"after return":     `function f(s){ return /'/.test(s) }`,
		"after paren":      `if (/"/.test(x)) { y = 1 }`,
		"after comma":      `var l = [/a/, /b'/g, /"c/m];`,
		"template":         "var t = `${6/3/1} it's ${/x'/.source}`;",
		"division in call": `var n = f(8)/2/1;`,
		"comment lookalike": `var u = "http://x/*y"; // trailing ' quote
var v = 1; /* block ' */ var w = 2;`,
		"regex after brace": "function f(){}\n/'/.test('x');",
		"object division":   `var o = {a: 4}; var q = o.a/2/1;`,
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, CheckSource(src, ScriptLimits))
			require.NoError(t, compileSource("var x = ''; "+src))
		})
	}
}

func TestCheckSourceLimitsUnchanged(t *testing.T) {
	require.Equal(t, 5000, ScriptLimits.Chain)
	require.Equal(t, MaxSourceDepth, ScriptLimits.Depth)
	require.Equal(t, 64<<10, EvalLimits.Length)
	require.Error(t, CheckSource("1"+strings.Repeat("+1", 5001), ScriptLimits))
	require.NoError(t, CheckSource("1"+strings.Repeat("+1", 4900), ScriptLimits))
	require.Error(t, CheckSource(strings.Repeat("(", 2001)+strings.Repeat(")", 2001), ScriptLimits))
}

// TestCheckSourceRandomMixes feeds random mixes of regexes, comments, strings, templates and
// brackets to the scanner and the compiler: neither may panic or hang, and a source the
// scanner accepts compiles (or fails) quickly.
func TestCheckSourceRandomMixes(t *testing.T) {
	pieces := []string{
		`/a/`, `/[/*]/`, `/\//`, `/'/`, `/"/g`, `/*`, `*/`, `//`, "\n", `'`, `"`, "`", "${", "}", "(", ")", "[", "]", "{",
		"/", "+", "1", "x", ";", ",", `\`, "return ", "typeof ", " ", "=", "a/b", "'s'", "`t`", "/* c */",
	}
	rng := rand.New(rand.NewSource(7))
	deadline := time.Now().Add(20 * time.Second)
	for i := 0; i < 4000 && time.Now().Before(deadline); i++ {
		var b strings.Builder
		for n := rng.Intn(24); n >= 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		src := b.String()
		started := time.Now()
		_ = CheckSource(src, ScriptLimits)
		_ = compileSource(src)
		require.Less(t, time.Since(started), 2*time.Second, "%q", src)
	}
}
