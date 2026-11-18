package mitm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func TestEngineCapturePersistFollowsOptions(t *testing.T) {
	ca := writeTestCA(t)
	dir := filepath.Join(t.TempDir(), "capture")
	options := fileOptions(ca, true, []string{"a.test"}, nil)
	options.Capture = &option.MITMCaptureOptions{Persist: &option.MITMCapturePersistOptions{Path: dir}}
	engine := newTestEngine(t, t.Context(), options)

	record := func(path string) {
		x := engine.Capture().NewExchange(&flow.ConnectionInfo{ID: "c"})
		x.RequestHead(flow.RequestHead{Method: "GET", Scheme: "https", Authority: "a.test", Path: path, Proto: "h2",
			Headers: []flow.Header{{Name: "Authorization", Value: "Bearer engine-secret"}}})
		x.ResponseHead(200, nil)
		x.Finish(nil)
	}
	// Off by default: nothing is created.
	record("/off")
	_, err := os.Stat(dir)
	require.True(t, os.IsNotExist(err))

	options.Capture.Persist = &option.MITMCapturePersistOptions{
		Enabled: true, Path: dir, Retention: badoption.Duration(time.Hour), RedactHeaders: []string{"X-Mine"},
	}
	commit, err := engine.Reload(options)
	require.NoError(t, err)
	commit()
	record("/on")
	require.Eventually(t, func() bool { return engine.Capture().PersistStats().Written == 1 }, 5*time.Second, 5*time.Millisecond)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		require.False(t, strings.Contains(string(data), "engine-secret"))
	}

	// A reload with an invalid section is rejected before anything changes.
	options.Capture.Persist = &option.MITMCapturePersistOptions{Enabled: true}
	_, err = engine.Reload(options)
	require.Error(t, err)
	require.True(t, engine.Capture().PersistStats().Enabled)

	options.Capture.Persist = &option.MITMCapturePersistOptions{Path: dir}
	commit, err = engine.Reload(options)
	require.NoError(t, err)
	commit()
	require.False(t, engine.Capture().PersistStats().Enabled)
	require.NoError(t, engine.Close())
}
