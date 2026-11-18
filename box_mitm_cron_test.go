package box_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/script"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const cronScriptsJSON = `"scripts": [{"tag": "tick", "type": "cron", "cron": "* * * * *", "source_path": "scripts/tick.js"}]`

func cronSchedulerGoroutines() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	return strings.Count(string(buf), "script.(*scheduler).loop")
}

func writeCronScript(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts", "tick.js"), []byte(`$done({});`), 0o644))
	t.Chdir(dir)
}

// A box that fails to build must not leave a scheduler behind.
func TestCronNotStartedWhenNewFails(t *testing.T) {
	writeCronScript(t)
	before := cronSchedulerGoroutines()
	config := `{"outbounds": [{"type": "socks", "tag": "bad", "server": "127.0.0.1", "server_port": 1, "version": "9"}], "route": {"final": "bad"}, ` + cronScriptsJSON + `}`
	ctx := include.Context(context.Background())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	_, err = box.New(box.Options{Context: ctx, Options: options})
	require.Error(t, err)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, before, cronSchedulerGoroutines())
}

// New alone does not schedule; Start does; Close stops it.
func TestCronStartsWithTheBox(t *testing.T) {
	writeCronScript(t)
	before := cronSchedulerGoroutines()
	config := `{"outbounds": [{"type": "direct", "tag": "direct"}], ` + cronScriptsJSON + `}`
	ctx := include.Context(context.Background())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	provider, ok := service.FromContext[adapter.MITMEngine](ctx).(interface{ Scripts() *script.Manager })
	require.True(t, ok)
	status := func() script.Status { return provider.Scripts().Current().Status()[0] }
	require.Equal(t, before, cronSchedulerGoroutines())
	require.True(t, status().NextRun.IsZero())
	require.NoError(t, instance.Start())
	require.Eventually(t, func() bool { return !status().NextRun.IsZero() }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, before+1, cronSchedulerGoroutines())
	require.NoError(t, instance.Close())
	require.Eventually(t, func() bool { return cronSchedulerGoroutines() == before }, 5*time.Second, 10*time.Millisecond)
}
