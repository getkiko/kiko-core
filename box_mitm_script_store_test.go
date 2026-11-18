package box_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func countScripts() []map[string]any {
	return []map[string]any{
		{"tag": "counter", "type": "http-request", "pattern": `^https://example\.com/\w+/count$`, "source_path": "scripts/count.js"},
	}
}

func scriptManagerOf(t *testing.T, b *rewriteBox) *script.Manager {
	t.Helper()
	engine := service.FromContext[adapter.MITMEngine](b.ctx)
	provider, ok := engine.(adapter.MITMScriptProvider)
	require.True(t, ok)
	return provider.Scripts()
}

func countOnce(t *testing.T, f *scriptFixture) string {
	t.Helper()
	response, data := f.do(f.client(false), "GET", "/h1/count", "", nil)
	require.Equal(t, 200, response.StatusCode)
	return string(data)
}

// TestMITMScriptPersistentStoreSurvivesRestart: a script writes $persistentStore in one run,
// the next run reads it, and both survive a restart of the core when a cache file exists.
func TestMITMScriptPersistentStoreSurvivesRestart(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	f := newScriptFixtureCache(t, countScripts(), cachePath)

	require.Equal(t, "1", countOnce(t, f))
	require.Equal(t, "2", countOnce(t, f))
	manager := scriptManagerOf(t, f.box)
	info, ok := manager.Store().(script.StoreInfo)
	require.True(t, ok)
	require.True(t, info.Persistent(), "a cache file selects the persistent store")
	value, found, err := manager.Store().Get("counter", "n")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "2", value)
	value, found, _ = manager.Store().Get(script.SharedNamespace, "last")
	require.True(t, found)
	require.Equal(t, "run-2", value)

	// Notifications and console lines of the live runs reached the hub.
	engine := service.FromContext[adapter.MITMEngine](f.box.ctx).(adapter.MITMScriptProvider)
	require.Eventually(t, func() bool { return len(engine.ScriptHub().NotificationsAfter(0, 0)) == 2 }, 2*time.Second, 10*time.Millisecond)
	logs := engine.ScriptHub().LogsAfter(0, 0)
	require.NotEmpty(t, logs)
	require.Equal(t, "counter", logs[0].Script)
	require.Equal(t, "count 1", logs[0].Message)

	require.NoError(t, f.box.instance.Close())
	f.box = startRewriteBox(t, f.config(countScripts()))
	require.Equal(t, "3", countOnce(t, f), "the counter continues after the restart")
	manager = scriptManagerOf(t, f.box)
	value, found, _ = manager.Store().Get(script.SharedNamespace, "last")
	require.True(t, found)
	require.Equal(t, "run-3", value)
	// Run history and the hub start empty in a new core.
	require.EqualValues(t, 1, manager.Current().Status()[0].Runs)
}

// TestMITMScriptStoreWithoutCacheFile: the store falls back to memory and does not survive.
func TestMITMScriptStoreWithoutCacheFile(t *testing.T) {
	f := newScriptFixtureCache(t, countScripts(), "")
	require.Equal(t, "1", countOnce(t, f))
	require.Equal(t, "2", countOnce(t, f))
	info, ok := scriptManagerOf(t, f.box).Store().(script.StoreInfo)
	require.True(t, ok)
	require.False(t, info.Persistent())

	require.NoError(t, f.box.instance.Close())
	f.box = startRewriteBox(t, f.config(countScripts()))
	require.Equal(t, "1", countOnce(t, f), "memory store starts empty after a restart")
}
