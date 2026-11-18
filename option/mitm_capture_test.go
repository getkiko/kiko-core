package option

import (
	"testing"
	"time"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestMITMCaptureResolve(t *testing.T) {
	defaults, err := (*MITMCaptureOptions)(nil).Resolve()
	require.NoError(t, err)
	require.Equal(t, MITMCaptureSettings{Enabled: true, MaxBody: 512 << 10, MaxMemory: 64 << 20, MaxRecords: 5000}, defaults)

	var options MITMOptions
	require.NoError(t, json.Unmarshal([]byte(`{"capture":{"enabled":false,"body":true,"max_body":"1MiB","max_memory":"8MiB","max_records":100}}`), &options))
	settings, err := options.Capture.Resolve()
	require.NoError(t, err)
	require.Equal(t, MITMCaptureSettings{Enabled: false, Body: true, MaxBody: 1 << 20, MaxMemory: 8 << 20, MaxRecords: 100}, settings)

	for _, bad := range []string{`{"max_body":"0 B"}`, `{"max_body":"1GiB"}`, `{"max_memory":"10KiB"}`, `{"max_records":-1}`, `{"max_records":9999999}`} {
		var capture MITMCaptureOptions
		require.NoError(t, json.Unmarshal([]byte(bad), &capture), bad)
		_, err = capture.Resolve()
		require.Error(t, err, bad)
	}
}

func TestMITMCapturePersistResolve(t *testing.T) {
	// Absent or empty: off.
	settings, err := (*MITMCaptureOptions)(nil).Resolve()
	require.NoError(t, err)
	require.False(t, settings.Persist.Enabled)

	var options MITMOptions
	require.NoError(t, json.Unmarshal([]byte(`{"capture":{"persist":{"enabled":true,"path":"/data/capture"}}}`), &options))
	settings, err = options.Capture.Resolve()
	require.NoError(t, err)
	require.Equal(t, MITMCapturePersistSettings{
		Enabled: true, Path: "/data/capture", MaxBytes: 256 << 20, MaxRecords: 20000, Retention: 168 * time.Hour,
	}, settings.Persist)

	options = MITMOptions{}
	require.NoError(t, json.Unmarshal([]byte(`{"capture":{"persist":{"enabled":true,"path":"/d","max_bytes":"8MiB","max_records":10,"retention":"2h","body":true,"redact_headers":["X-Mine"," X-Other "]}}}`), &options))
	settings, err = options.Capture.Resolve()
	require.NoError(t, err)
	require.Equal(t, MITMCapturePersistSettings{
		Enabled: true, Path: "/d", MaxBytes: 8 << 20, MaxRecords: 10, Retention: 2 * time.Hour, Body: true, RedactHeaders: []string{"X-Mine", "X-Other"},
	}, settings.Persist)

	for _, bad := range []string{
		`{"persist":{"enabled":true}}`,
		`{"persist":{"enabled":true,"path":"/d","max_bytes":"1KiB"}}`,
		`{"persist":{"enabled":true,"path":"/d","max_records":-1}}`,
		`{"persist":{"enabled":true,"path":"/d","max_records":99999999}}`,
		`{"persist":{"enabled":true,"path":"/d","retention":"1s"}}`,
		`{"persist":{"enabled":true,"path":"/d","redact_headers":["bad name"]}}`,
		`{"persist":{"enabled":true,"path":"/d","redact_headers":[""]}}`,
	} {
		var capture MITMCaptureOptions
		require.NoError(t, json.Unmarshal([]byte(bad), &capture), bad)
		_, err = capture.Resolve()
		require.Error(t, err, bad)
	}
	// A disabled section needs no path.
	var capture MITMCaptureOptions
	require.NoError(t, json.Unmarshal([]byte(`{"persist":{"enabled":false}}`), &capture))
	_, err = capture.Resolve()
	require.NoError(t, err)
}
