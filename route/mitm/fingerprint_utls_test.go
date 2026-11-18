//go:build with_utls

package mitm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpstreamFingerprints(t *testing.T) {
	chrome := captureHello(t, "chrome")
	require.True(t, chrome.hasGREASE())
	defaultHello := captureHello(t, "")
	require.True(t, defaultHello.hasGREASE())
	require.Equal(t, chrome.signature(), defaultHello.signature())

	safari := captureHello(t, "safari")
	firefox := captureHello(t, "firefox")
	none := captureHello(t, "none")
	signatures := map[string]string{
		"chrome":  chrome.signature(),
		"safari":  safari.signature(),
		"firefox": firefox.signature(),
		"none":    none.signature(),
	}
	for first, firstSignature := range signatures {
		for second, secondSignature := range signatures {
			if first < second {
				require.NotEqual(t, firstSignature, secondSignature, "%s and %s share a ClientHello", first, second)
			}
		}
	}
}
