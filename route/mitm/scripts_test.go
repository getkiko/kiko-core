package mitm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func scriptDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "http"), 0o755))
	write := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "http", name), []byte(content), 0o644))
	}
	write("ok.js", `$done({});`)
	write("empty.js", "  \n")
	write("syntax.js", `var = ;`)
	write("deep.js", strings.Repeat("(", script.MaxSourceDepth+1)+strings.Repeat(")", script.MaxSourceDepth+1))
	write("big.js", "//"+strings.Repeat("x", script.MaxSourceSize)+"\n$done({});")
	t.Chdir(dir)
}

func req(tag string) option.ScriptOptions {
	return option.ScriptOptions{Tag: tag, Type: "http-request", Pattern: `^https://a\.test/`, SourcePath: "http/ok.js"}
}

func mem(n int64) *byteformats.Bytes {
	var out byteformats.Bytes
	if err := json.Unmarshal([]byte(`"`+itoa64(n)+`B"`), &out); err != nil {
		panic(err)
	}
	return &out
}

func memory(text string) *byteformats.MemoryBytes {
	var out byteformats.MemoryBytes
	if err := json.Unmarshal([]byte(`"`+text+`"`), &out); err != nil {
		panic(err)
	}
	return &out
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestScriptValidation(t *testing.T) {
	scriptDir(t)
	engine := newTestEngine(t, context.Background(), nil)
	bad := func(name string, o option.ScriptOptions, want string) {
		t.Run(name, func(t *testing.T) {
			_, err := engine.ReloadScripts([]option.ScriptOptions{o}, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), want)
		})
	}
	with := func(f func(*option.ScriptOptions)) option.ScriptOptions {
		o := req("a")
		f(&o)
		return o
	}
	bad("empty tag", with(func(o *option.ScriptOptions) { o.Tag = "" }), "tag must be")
	bad("tag charset", with(func(o *option.ScriptOptions) { o.Tag = "a b" }), "tag must be")
	bad("tag length", with(func(o *option.ScriptOptions) { o.Tag = strings.Repeat("a", 65) }), "tag must be")
	bad("missing type", with(func(o *option.ScriptOptions) { o.Type = "" }), "missing type")
	bad("unknown type", with(func(o *option.ScriptOptions) { o.Type = "x" }), "unknown type")
	for _, kind := range []string{"rule", "dns"} {
		bad("rule type with pattern "+kind, with(func(o *option.ScriptOptions) { o.Type = kind }), "take no pattern and no body")
	}
	bad("no pattern", with(func(o *option.ScriptOptions) { o.Pattern = "" }), "pattern is required")
	bad("invalid regex", with(func(o *option.ScriptOptions) { o.Pattern = "(" }), "invalid pattern")
	bad("long pattern", with(func(o *option.ScriptOptions) { o.Pattern = strings.Repeat("a", script.MaxPatternLength+1) }), "pattern too long")
	cronOf := func(expr string) option.ScriptOptions {
		return with(func(o *option.ScriptOptions) { o.Type, o.Pattern, o.Cron = "cron", "", expr })
	}
	bad("cron missing", cronOf(""), "cron is required")
	bad("cron blank", cronOf("  "), "cron is required")
	bad("cron six fields", cronOf("0 0 0 * * *"), "5 fields")
	bad("cron question mark", cronOf("0 0 ? * *"), "invalid")
	bad("cron pattern", with(func(o *option.ScriptOptions) { o.Type, o.Cron = "cron", "* * * * *" }), "no pattern")
	bad("cron on request", with(func(o *option.ScriptOptions) { o.Cron = "* * * * *" }), "only for cron")
	bad("cron on generic", with(func(o *option.ScriptOptions) { o.Type, o.Pattern, o.Cron = "generic", "", "* * * * *" }), "only for cron")
	bad("cron long timeout", with(func(o *option.ScriptOptions) {
		o.Type, o.Pattern, o.Cron, o.Timeout = "cron", "", "* * * * *", badoption.Duration(61*time.Second)
	}), "timeout must be")
	bad("generic pattern", with(func(o *option.ScriptOptions) { o.Type = "generic" }), "no pattern")
	bad("no source", with(func(o *option.ScriptOptions) { o.SourcePath = "" }), "missing source_path")
	bad("absolute source", with(func(o *option.ScriptOptions) { o.SourcePath = "/etc/passwd" }), "must be relative")
	bad("parent source", with(func(o *option.ScriptOptions) { o.SourcePath = "http/../../x.js" }), "must not contain ..")
	bad("missing file", with(func(o *option.ScriptOptions) { o.SourcePath = "http/none.js" }), "read source_path")
	bad("empty file", with(func(o *option.ScriptOptions) { o.SourcePath = "http/empty.js" }), "source is empty")
	bad("syntax error", with(func(o *option.ScriptOptions) { o.SourcePath = "http/syntax.js" }), "compile")
	bad("deep nesting", with(func(o *option.ScriptOptions) { o.SourcePath = "http/deep.js" }), "nested more deeply")
	bad("big source", with(func(o *option.ScriptOptions) { o.SourcePath = "http/big.js" }), "source larger")
	bad("binary without body", with(func(o *option.ScriptOptions) { o.BinaryBody = true }), "binary_body needs requires_body")
	bad("max_size zero", with(func(o *option.ScriptOptions) { o.MaxSize = mem(0) }), "max_size")
	bad("max_size huge", with(func(o *option.ScriptOptions) { o.MaxSize = mem(33 << 20) }), "max_size")
	bad("negative timeout", with(func(o *option.ScriptOptions) { o.Timeout = badoption.Duration(-time.Second) }), "timeout must be positive")
	bad("long timeout", with(func(o *option.ScriptOptions) { o.Timeout = badoption.Duration(31 * time.Second) }), "timeout must be")
	bad("long argument", with(func(o *option.ScriptOptions) { o.Argument = strings.Repeat("a", script.MaxArgumentSize+1) }), "argument too long")

	t.Run("duplicate tag", func(t *testing.T) {
		_, err := engine.ReloadScripts([]option.ScriptOptions{req("a"), req("a")}, nil)
		require.ErrorContains(t, err, "duplicate tag")
	})
	t.Run("too many", func(t *testing.T) {
		var list []option.ScriptOptions
		for i := 0; i <= option.MaxScripts; i++ {
			list = append(list, req("s"+itoa64(int64(i))))
		}
		_, err := engine.ReloadScripts(list, nil)
		require.ErrorContains(t, err, "too many scripts")
	})
	t.Run("generic timeout may reach 60s", func(t *testing.T) {
		o := with(func(o *option.ScriptOptions) {
			o.Type, o.Pattern, o.Timeout = "generic", "", badoption.Duration(60*time.Second)
		})
		commit, err := engine.ReloadScripts([]option.ScriptOptions{o}, nil)
		require.NoError(t, err)
		commit()
		require.Equal(t, 60*time.Second, engine.Scripts().Current().Lookup("a").Config().Timeout)
	})
	t.Run("cron maps", func(t *testing.T) {
		o := with(func(o *option.ScriptOptions) {
			o.Type, o.Pattern, o.Cron, o.Timeout = "cron", "", "*/5 * * * mon-fri", badoption.Duration(60*time.Second)
		})
		commit, err := engine.ReloadScripts([]option.ScriptOptions{o}, nil)
		require.NoError(t, err)
		commit()
		cfg := engine.Scripts().Current().Lookup("a").Config()
		require.Equal(t, script.PhaseCron, cfg.Type)
		require.Equal(t, "*/5 * * * mon-fri", cfg.Cron)
		require.Equal(t, 60*time.Second, cfg.Timeout)
		require.False(t, engine.Scripts().Current().HasHTTP())
	})
	t.Run("defaults", func(t *testing.T) {
		mitm := &option.MITMOptions{HTTPRewrite: &option.MITMHTTPRewriteOptions{MaxBodySize: memory("64KB")}}
		commit, err := engine.ReloadScripts([]option.ScriptOptions{req("a")}, mitm)
		require.NoError(t, err)
		commit()
		cfg := engine.Scripts().Current().Lookup("a").Config()
		require.EqualValues(t, 64<<10, cfg.MaxSize)
		require.Equal(t, script.DefaultTimeout, cfg.Timeout)
		explicit := req("a")
		explicit.MaxSize = mem(1 << 20)
		commit, err = engine.ReloadScripts([]option.ScriptOptions{explicit}, mitm)
		require.NoError(t, err)
		commit()
		require.EqualValues(t, 1<<20, engine.Scripts().Current().Lookup("a").Config().MaxSize)
	})
	t.Run("disabled is not compiled", func(t *testing.T) {
		off := false
		o := with(func(o *option.ScriptOptions) { o.Enabled, o.SourcePath = &off, "http/none.js" })
		commit, err := engine.ReloadScripts([]option.ScriptOptions{o}, nil)
		require.NoError(t, err)
		commit()
		require.True(t, engine.Scripts().Current().Empty())
		// ...but its shape is still checked.
		o.Pattern = ""
		_, err = engine.ReloadScripts([]option.ScriptOptions{o}, nil)
		require.Error(t, err)
	})
	t.Run("a failed reload changes nothing", func(t *testing.T) {
		commit, err := engine.ReloadScripts([]option.ScriptOptions{req("keep")}, nil)
		require.NoError(t, err)
		commit()
		_, err = engine.ReloadScripts([]option.ScriptOptions{req("keep"), with(func(o *option.ScriptOptions) { o.Pattern = "(" })}, nil)
		require.Error(t, err)
		require.NotNil(t, engine.Scripts().Current().Lookup("keep"))
	})
}

func TestScriptOptionsJSON(t *testing.T) {
	content := `{"scripts": [{"tag": "t", "type": "http-response", "enabled": false, "pattern": "^https://", "source_path": "http/ok.js", "requires_body": true, "binary_body": true, "max_size": "1MiB", "timeout": "10s", "argument": "k=v"}]}`
	var options option.Options
	require.NoError(t, json.Unmarshal([]byte(content), &options))
	require.Len(t, options.Scripts, 1)
	s := options.Scripts[0]
	require.Equal(t, "t", s.Tag)
	require.False(t, *s.Enabled)
	require.EqualValues(t, 1<<20, s.MaxSize.Value())
	require.Equal(t, 10*time.Second, time.Duration(s.Timeout))
	out, err := json.Marshal(options)
	require.NoError(t, err)
	require.Contains(t, string(out), `"source_path":"http/ok.js"`)
	// Unknown fields are refused.
	require.Error(t, json.Unmarshal([]byte(`{"scripts": [{"tag": "t", "bogus": 1}]}`), &options))
}

func TestScriptsSkipInternalConnections(t *testing.T) {
	engine := newTestEngine(t, context.Background(), nil)
	require.Nil(t, engine.scriptsFor(&adapter.InboundContext{Internal: true}))
	require.Same(t, engine.scripts, engine.scriptsFor(&adapter.InboundContext{}))
}
