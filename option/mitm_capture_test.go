package option

import (
	"testing"

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
