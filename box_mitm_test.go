package box_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/authority"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type mitmTestCA struct {
	certificatePath string
	keyPath         string
	certificatePEM  []byte
}

func writeMITMTestCA(t testing.TB) mitmTestCA {
	t.Helper()
	certificatePEM, keyPEM, err := authority.Generate("Kiko Box Test CA", 24*time.Hour)
	require.NoError(t, err)
	directory := t.TempDir()
	ca := mitmTestCA{
		certificatePath: filepath.Join(directory, "ca.pem"),
		keyPath:         filepath.Join(directory, "ca.key"),
		certificatePEM:  certificatePEM,
	}
	require.NoError(t, os.WriteFile(ca.certificatePath, certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(ca.keyPath, keyPEM, 0o600))
	return ca
}

func mitmSection(ca mitmTestCA, enabled bool, include ...string) string {
	content, _ := json.Marshal(map[string]any{
		"enabled": enabled,
		"certificate": map[string]any{
			"source":           "file",
			"certificate_path": ca.certificatePath,
			"key_path":         ca.keyPath,
		},
		"hostnames": map[string]any{"include": include},
	})
	return string(content)
}

// withTopLevel adds a top-level key to a configuration object.
func withTopLevel(config string, key string, value string) string {
	index := strings.LastIndex(config, "}")
	return config[:index] + `, "` + key + `": ` + value + "\n}"
}

func liveTLSMetadata(serverName string) *adapter.InboundContext {
	return &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Protocol:    C.ProtocolTLS,
		Domain:      serverName,
		Destination: M.ParseSocksaddr("10.0.0.1:443"),
	}
}

func TestLiveApplyMITM(t *testing.T) {
	ca := writeMITMTestCA(t)
	ctx, instance := startLiveBox(t, withTopLevel(liveBaseConfig, "mitm", mitmSection(ca, false, "a.test")))
	engine := service.FromContext[adapter.MITMEngine](ctx)
	require.NotNil(t, engine)
	require.False(t, engine.Status().Enabled)
	require.Nil(t, engine.Decide(liveTLSMetadata("a.test")))

	result, err := applyLive(t, ctx, withTopLevel(liveBaseConfig, "mitm", mitmSection(ca, true, "a.test")))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.False(t, result.RestartRequired)
	require.Same(t, engine, service.FromContext[adapter.MITMEngine](ctx))
	status := engine.Status()
	require.True(t, status.Enabled)
	require.False(t, status.AuthorityPending)
	require.NotEmpty(t, status.AuthorityFingerprint)
	require.True(t, engine.Decide(liveTLSMetadata("a.test")).Pending())

	result, err = applyLive(t, ctx, withTopLevel(liveBaseConfig, "mitm", mitmSection(ca, true, "b.test")))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Same(t, engine, service.FromContext[adapter.MITMEngine](ctx))
	require.Nil(t, engine.Decide(liveTLSMetadata("a.test")))
	require.True(t, engine.Decide(liveTLSMetadata("b.test")).Pending())
	require.Equal(t, status.AuthorityFingerprint, engine.Status().AuthorityFingerprint)

	// Invalid decryption options fail the whole apply and change nothing.
	oldRules := instance.Router().Rules()
	invalid := strings.Replace(liveBaseConfig, `"outbound": "d1"}`, `"outbound": "d2"}`, 1)
	result, err = applyLive(t, ctx, withTopLevel(invalid, "mitm", mitmSection(ca, true, "*")))
	require.Error(t, err)
	require.False(t, result.Applied)
	require.Equal(t, oldRules, instance.Router().Rules())
	require.True(t, engine.Decide(liveTLSMetadata("b.test")).Pending())
	missing := mitmTestCA{certificatePath: ca.certificatePath, keyPath: filepath.Join(t.TempDir(), "missing.key")}
	_, err = applyLive(t, ctx, withTopLevel(liveBaseConfig, "mitm", mitmSection(missing, true, "c.test")))
	require.Error(t, err)
	require.Nil(t, engine.Decide(liveTLSMetadata("c.test")))
	require.True(t, engine.Decide(liveTLSMetadata("b.test")).Pending())
	// Unknown keys are rejected by the decoder.
	_, err = applyLive(t, ctx, withTopLevel(liveBaseConfig, "mitm", `{"enabled": true, "capture_all": true}`))
	require.Error(t, err)

	// Removing the section disables decryption.
	result, err = applyLive(t, ctx, liveBaseConfig)
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.False(t, engine.Status().Enabled)
	require.Nil(t, engine.Decide(liveTLSMetadata("b.test")))
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestMITMMixedInbound(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "upstream "+request.URL.Path)
	}))
	defer upstream.Close()
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
	upstreamPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))
	ca := writeMITMTestCA(t)
	proxyPort := freePort(t)
	certificateSection, _ := json.Marshal(map[string]any{"certificate": []string{upstreamPEM}})
	build := func(routeRules string) string {
		return `{
  "log": {"disabled": true},
  "certificate": ` + string(certificateSection) + `,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}` + routeRules + `], "final": "direct"},
  "mitm": ` + mitmSection(ca, true, "example.com:"+strconv.Itoa(upstreamPort)) + `
}`
	}
	ctx, _ := startLiveBox(t, build(""))

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certificatePEM))
	roots.AddCert(upstream.Certificate())
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	require.NoError(t, err)
	newClient := func() *http.Client {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
			},
		}
	}
	target := "https://127.0.0.1:" + strconv.Itoa(upstreamPort)
	get := func(client *http.Client, path string) (*http.Response, string) {
		response, err := client.Get(target + path)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		return response, string(body)
	}

	client := newClient()
	for _, path := range []string{"/one", "/two"} {
		response, body := get(client, path)
		require.Equal(t, "upstream "+path, body)
		require.Equal(t, "Kiko Box Test CA", response.TLS.PeerCertificates[0].Issuer.CommonName)
	}
	engine := service.FromContext[adapter.MITMEngine](ctx)
	require.Equal(t, 1, engine.Status().LeafCacheSize)

	// A skip override passes the connection through with the real certificate.
	result, err := applyLive(t, ctx, build(`, {"domain": ["example.com"], "action": "route-options", "mitm": "skip"}`))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	response, body := get(newClient(), "/three")
	require.Equal(t, "upstream /three", body)
	require.True(t, response.TLS.PeerCertificates[0].Equal(upstream.Certificate()))
}
