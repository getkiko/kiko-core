//go:build !with_utls

package mitm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Builds without uTLS always use standard TLS, whatever the fingerprint.
func TestUpstreamFingerprintsStandard(t *testing.T) {
	standard := captureHello(t, "none").signature()
	for _, fingerprint := range []string{"", "chrome", "safari", "firefox"} {
		hello := captureHello(t, fingerprint)
		require.False(t, hello.hasGREASE(), fingerprint)
		require.Equal(t, standard, hello.signature(), fingerprint)
	}
}
