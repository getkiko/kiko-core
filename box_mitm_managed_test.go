package box_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/authority"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestMITMManagedAuthority(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "upstream "+request.URL.Path)
	}))
	defer upstream.Close()
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
	upstreamPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))
	proxyPort := freePort(t)
	apiPort := freePort(t)
	certificateSection, _ := json.Marshal(map[string]any{"certificate": []string{upstreamPEM}})
	mitmSection, _ := json.Marshal(map[string]any{
		"enabled":     true,
		"certificate": map[string]any{"source": "managed"},
		"hostnames":   map[string]any{"include": []string{"example.com:" + strconv.Itoa(upstreamPort)}},
	})
	ctx, _ := startLiveBox(t, `{
  "log": {"disabled": true},
  "certificate": `+string(certificateSection)+`,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(proxyPort)+`}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "services": [{"type": "api", "tag": "api", "listen": "127.0.0.1", "listen_port": `+strconv.Itoa(apiPort)+`, "secret": "test-secret"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"},
  "mitm": `+string(mitmSection)+`
}`)
	engine := service.FromContext[adapter.MITMEngine](ctx)
	require.True(t, engine.Status().AuthorityPending)

	rootPEM, rootKeyPEM, err := authority.Generate("Kiko Managed Root", 365*24*time.Hour)
	require.NoError(t, err)
	rootBlock, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	require.NoError(t, err)
	chainPEM, keyPKCS8, err := authority.IssueIntermediate(rootPEM, rootKeyPEM, "Kiko Managed Intermediate", authority.IntermediateValidity)
	require.NoError(t, err)
	interBlock, _ := pem.Decode(chainPEM)
	intermediate, err := x509.ParseCertificate(interBlock.Bytes)
	require.NoError(t, err)
	rootSum := sha256.Sum256(root.Raw)
	interSum := sha256.Sum256(intermediate.Raw)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	roots.AddCert(upstream.Certificate())
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	require.NoError(t, err)
	get := func(path string) (*http.Response, string) {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
			},
		}
		response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(upstreamPort) + path)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		return response, string(body)
	}

	// Before the push the connection passes through with the upstream certificate.
	response, body := get("/before")
	require.Equal(t, "upstream /before", body)
	require.True(t, response.TLS.PeerCertificates[0].Equal(upstream.Certificate()))

	conn, err := daemon.NewRemoteClient(daemon.RemoteClientOptions{ServerURL: "http://127.0.0.1:" + strconv.Itoa(apiPort), Secret: "test-secret"})
	require.NoError(t, err)
	defer conn.Close()
	client := mitmapi.NewMITMClient(conn)
	requestCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, err := client.SetAuthority(requestCtx, &mitmapi.SetAuthorityRequest{
		CertChainPem:    chainPEM,
		KeyPkcs8:        keyPKCS8,
		RootFingerprint: hex.EncodeToString(rootSum[:]),
		NotAfter:        intermediate.NotAfter.Unix(),
	})
	require.NoError(t, err)
	require.False(t, status.AuthorityPending)

	response, body = get("/after")
	require.Equal(t, "upstream /after", body)
	peerChain := response.TLS.PeerCertificates
	require.Len(t, peerChain, 2)
	require.Equal(t, "Kiko Managed Intermediate", peerChain[0].Issuer.CommonName)
	require.True(t, peerChain[1].Equal(intermediate))
	intermediates := x509.NewCertPool()
	intermediates.AddCert(peerChain[1])
	onlyRoot := x509.NewCertPool()
	onlyRoot.AddCert(root)
	_, err = peerChain[0].Verify(x509.VerifyOptions{DNSName: "example.com", Roots: onlyRoot, Intermediates: intermediates})
	require.NoError(t, err)

	status, err = client.GetStatus(requestCtx, &emptypb.Empty{})
	require.NoError(t, err)
	require.True(t, status.Enabled)
	require.False(t, status.AuthorityPending)
	require.Equal(t, hex.EncodeToString(interSum[:]), status.AuthorityFingerprint)
	require.Equal(t, hex.EncodeToString(rootSum[:]), status.RootFingerprint)
	require.Equal(t, intermediate.NotAfter.Unix(), status.AuthorityNotAfter)
	require.Equal(t, "managed", status.CertificateSource)
	require.Equal(t, uint32(1), status.LeafCacheSize)
}

func TestMITMRejectsPublicDebugListen(t *testing.T) {
	build := func(listen string, enabled bool) string {
		return withTopLevel(withTopLevel(liveBaseConfig, "experimental", `{"debug": {"listen": "`+listen+`"}}`),
			"mitm", `{"enabled": `+strconv.FormatBool(enabled)+`, "hostnames": {"include": ["a.test"]}}`)
	}
	newBox := func(content string) error {
		ctx := include.Context(context.Background())
		options, err := sJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		if err == nil {
			instance.Close()
		}
		return err
	}
	for _, listen := range []string{"0.0.0.0:0", ":0", "192.168.1.2:0", "[::]:0", "example.com:0"} {
		require.ErrorContains(t, newBox(build(listen, true)), "debug.listen", listen)
		require.NoError(t, newBox(build(listen, false)), listen)
	}
	for _, listen := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		require.NoError(t, newBox(build(listen, true)), listen)
	}

	// Enabling decryption live keeps the same rule.
	port := strconv.Itoa(freePort(t))
	ctx, _ := startLiveBox(t, build("0.0.0.0:"+port, false))
	_, err := applyLive(t, ctx, build("0.0.0.0:"+port, true))
	require.ErrorContains(t, err, "debug.listen")
	require.False(t, service.FromContext[adapter.MITMEngine](ctx).Status().Enabled)
}
