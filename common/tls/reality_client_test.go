//go:build with_utls

package tls

import (
	"bytes"
	"net"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestRealityClientHelloCarriesHybridKeyShare(t *testing.T) {
	for _, fingerprint := range []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
		randomizedFingerprint,
	} {
		t.Run(fingerprint.Client+"-"+fingerprint.Version, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			uConn, err := buildRealityHandshakeState(client, &utls.Config{ServerName: "example.com"}, fingerprint)
			require.NoError(t, err)
			var curves *utls.SupportedCurvesExtension
			var shares *utls.KeyShareExtension
			for _, extension := range uConn.Extensions {
				if value, ok := extension.(*utls.SupportedCurvesExtension); ok {
					curves = value
				}
				if value, ok := extension.(*utls.KeyShareExtension); ok {
					shares = value
				}
			}
			require.NotNil(t, curves)
			require.NotNil(t, shares)
			require.True(t, containsRealityCurve(curves.Curves))
			require.True(t, containsRealityKeyShare(shares.KeyShares))
			var hybridShare *utls.KeyShare
			for index := range shares.KeyShares {
				share := &shares.KeyShares[index]
				if share.Group == utls.X25519MLKEM768 {
					hybridShare = share
					break
				}
				require.NotEqual(t, utls.X25519, share.Group)
			}
			require.NotNil(t, hybridShare)
			require.Len(t, hybridShare.Data, 1216)
			require.NotNil(t, uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe)
			require.Equal(t, uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe.PublicKey().Bytes(), hybridShare.Data[1184:])
			require.True(t, bytes.Contains(uConn.HandshakeState.Hello.Raw, hybridShare.Data))
			for _, share := range shares.KeyShares {
				if share.Group == utls.X25519 {
					require.NotNil(t, uConn.HandshakeState.State13.KeyShareKeys.Ecdhe)
					require.Equal(t, uConn.HandshakeState.State13.KeyShareKeys.Ecdhe.PublicKey().Bytes(), share.Data)
				}
			}
		})
	}
}
