//go:build unix

package mitm

import (
	"context"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnabledEngineDisablesCoreDumps(t *testing.T) {
	newTestEngine(t, context.Background(), managedOptions(true, []string{"a.test"}))
	var limit syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_CORE, &limit))
	require.Zero(t, limit.Cur)
	require.Zero(t, limit.Max)
}
