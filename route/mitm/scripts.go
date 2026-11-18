package mitm

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"
)

// Scripts returns the script manager: the HTTP hooks run its scripts, and the host attaches
// the persistent store, notification sink and run history to it.
func (e *Engine) Scripts() *script.Manager {
	return e.scripts
}

// ScriptHub returns the hub that keeps the recent console lines and notifications of scripts.
func (e *Engine) ScriptHub() *script.Hub {
	return e.scriptHub
}

// ReloadScripts validates and compiles the top-level "scripts" and returns the function that
// makes them current. Nothing changes until the function is called; in-flight script calls
// finish on the set they started with. mitm supplies the default body limit
// (http_rewrite.max_body_size).
func (e *Engine) ReloadScripts(options []option.ScriptOptions, mitm *option.MITMOptions) (func(), error) {
	defaultMax := int64(rewrite.DefaultMaxBodySize)
	if rw := common.PtrValueOrDefault(mitm).HTTPRewrite; rw != nil && rw.MaxBodySize != nil {
		defaultMax = int64(rw.MaxBodySize.Value())
	}
	configs, err := CompileScriptConfigs(e.ctx, options, defaultMax)
	if err != nil {
		return nil, err
	}
	set, err := e.scripts.Compile(configs)
	if err != nil {
		return nil, err
	}
	return func() {
		e.scripts.Swap(set)
	}, nil
}

// CompileScriptConfigs turns script options into runtime configs: it validates every field,
// reads the source files and applies the defaults. defaultMaxSize is the max_size of scripts
// that set none. Disabled scripts are checked for shape but their files are not read.
func CompileScriptConfigs(ctx context.Context, options []option.ScriptOptions, defaultMaxSize int64) ([]script.Config, error) {
	if len(options) > option.MaxScripts {
		return nil, E.New("too many scripts (at most ", option.MaxScripts, ")")
	}
	seen := make(map[string]bool, len(options))
	configs := make([]script.Config, 0, len(options))
	for i, o := range options {
		name := o.Tag
		if name == "" {
			name = "#" + strconv.Itoa(i+1)
		}
		cfg, err := compileScriptOption(ctx, o, defaultMaxSize)
		if err != nil {
			return nil, E.Cause(err, "scripts ", name)
		}
		if seen[o.Tag] {
			return nil, E.New("scripts ", name, ": duplicate tag")
		}
		seen[o.Tag] = true
		configs = append(configs, cfg)
	}
	return configs, nil
}

func compileScriptOption(ctx context.Context, o option.ScriptOptions, defaultMaxSize int64) (script.Config, error) {
	cfg := script.Config{
		Tag:          o.Tag,
		Pattern:      o.Pattern,
		RequiresBody: o.RequiresBody,
		BinaryBody:   o.BinaryBody,
		Argument:     o.Argument,
		Cron:         o.Cron,
		Disabled:     o.Enabled != nil && !*o.Enabled,
	}
	if !script.ValidTag(o.Tag) {
		return cfg, E.New("tag must be 1-", script.MaxTagLength, " characters of A-Z a-z 0-9 . _ -")
	}
	switch o.Type {
	case option.ScriptTypeHTTPRequest:
		cfg.Type = script.PhaseRequest
	case option.ScriptTypeHTTPResponse:
		cfg.Type = script.PhaseResponse
	case option.ScriptTypeGeneric:
		cfg.Type = script.PhaseGeneric
	case option.ScriptTypeCron:
		cfg.Type = script.PhaseCron
	case option.ScriptTypeRule:
		cfg.Type = script.PhaseRule
	case option.ScriptTypeDNS:
		cfg.Type = script.PhaseDNS
	case "":
		return cfg, E.New("missing type")
	default:
		return cfg, E.New("unknown type: ", o.Type)
	}
	if cfg.Type == script.PhaseCron {
		if strings.TrimSpace(o.Cron) == "" {
			return cfg, E.New("cron is required")
		}
		if o.Pattern != "" {
			return cfg, E.New("cron scripts take no pattern")
		}
		if err := script.ValidCron(o.Cron); err != nil {
			return cfg, E.New("invalid cron: ", err.Error())
		}
	} else if o.Cron != "" {
		return cfg, E.New("cron is only for cron scripts")
	}
	if (cfg.Type == script.PhaseRule || cfg.Type == script.PhaseDNS) && (o.RequiresBody || o.BinaryBody || o.Pattern != "") {
		return cfg, E.New(o.Type, " scripts take no pattern and no body")
	}
	if o.BinaryBody && !o.RequiresBody {
		return cfg, E.New("binary_body needs requires_body")
	}
	if o.MaxSize != nil {
		size := int64(o.MaxSize.Value())
		if size <= 0 || size > script.MaxMaxSize {
			return cfg, E.New("max_size must be between 1 and ", script.MaxMaxSize, " bytes")
		}
		cfg.MaxSize = size
	} else if defaultMaxSize > 0 {
		cfg.MaxSize = min(defaultMaxSize, script.MaxMaxSize)
	}
	if o.Timeout < 0 {
		return cfg, E.New("timeout must be positive")
	}
	cfg.Timeout = time.Duration(o.Timeout)
	if o.SourcePath == "" {
		return cfg, E.New("missing source_path")
	}
	cfg.SourceName = o.SourcePath
	if cfg.Disabled {
		// Shape only: a disabled script keeps its file unread and unchecked.
		if (cfg.Type == script.PhaseRequest || cfg.Type == script.PhaseResponse) && strings.TrimSpace(cfg.Pattern) == "" {
			return cfg, E.New("pattern is required")
		}
		return cfg, nil
	}
	source, err := readScriptFile(ctx, o.SourcePath)
	if err != nil {
		return cfg, err
	}
	cfg.Source = source
	return cfg, nil
}

func readScriptFile(ctx context.Context, path string) (string, error) {
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		return "", E.New("source_path must be relative")
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return "", E.New("source_path must not contain ..")
		}
	}
	file, err := filemanager.OpenFile(ctx, path, os.O_RDONLY, 0)
	if err != nil {
		return "", E.Cause(err, "read source_path")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", E.Cause(err, "read source_path")
	}
	if info.Size() > script.MaxSourceSize {
		return "", E.New("source larger than ", script.MaxSourceSize>>20, " MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, script.MaxSourceSize+1))
	if err != nil {
		return "", E.Cause(err, "read source_path")
	}
	if len(data) > script.MaxSourceSize {
		return "", E.New("source larger than ", script.MaxSourceSize>>20, " MiB")
	}
	return string(data), nil
}

// scriptLogger sends console output of scripts to the engine logger.
type scriptLogger struct {
	logger logger.ContextLogger
}

func (l scriptLogger) Log(entry script.LogEntry) {
	message := "script " + entry.Script + ": " + entry.Message
	switch entry.Level {
	case "error":
		l.logger.Error(message)
	case "warn":
		l.logger.Warn(message)
	case "info":
		l.logger.Info(message)
	default:
		l.logger.Debug(message)
	}
}
