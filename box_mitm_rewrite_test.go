package box_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	h2relay "github.com/sagernet/sing-box/common/mitm/h2"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type rewriteOrigin struct {
	server *httptest.Server
	port   int
	hits   atomic.Int32
}

func newRewriteOrigin(t *testing.T, kind string) *rewriteOrigin {
	origin := &rewriteOrigin{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin.hits.Add(1)
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Origin-Saw", r.Header.Get("X-Kiko"))
		_, _ = io.WriteString(w, r.Proto+" "+r.Host+r.URL.RequestURI())
	})
	switch kind {
	case "plain":
		origin.server = httptest.NewServer(handler)
	case "h2":
		origin.server = httptest.NewUnstartedServer(handler)
		origin.server.EnableHTTP2 = true
		origin.server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
		origin.server.StartTLS()
	default:
		origin.server = httptest.NewTLSServer(handler)
	}
	t.Cleanup(origin.server.Close)
	origin.port = origin.server.Listener.Addr().(*net.TCPAddr).Port
	return origin
}

func rewriteRules(dict string) map[string]any {
	return map[string]any{
		"url": []map[string]any{
			{"id": "dict", "pattern": `^https?://example\.com(:\d+)?/dict`, "action": dict},
			{"id": "img", "pattern": `^https?://example\.com(:\d+)?/img`, "action": "reject-img"},
			{"id": "r200", "pattern": `^https?://example\.com(:\d+)?/r200`, "action": "reject-200"},
			{"id": "arr", "pattern": `^https?://example\.com(:\d+)?/arr`, "action": "reject-array"},
			{"id": "found", "pattern": `^(https?)://example\.com(:\d+)?/old/(\w+)`, "action": "302", "target": "$1://example.com/new/$3"},
			{"id": "temp", "pattern": `^(https?)://example\.com(:\d+)?/tmp/(?P<name>\w+)`, "action": "307", "target": "${1}://example.com/moved/${name}"},
			{"id": "drop", "pattern": `^https?://example\.com(:\d+)?/drop`, "action": "reject"},
		},
		"map_local": []map[string]any{
			{"id": "mock", "pattern": `^https?://example\.com(:\d+)?/mock$`, "status": 201, "body": "hello", "headers": []map[string]string{{"name": "X-Mock", "value": "1"}}},
			{"id": "mockb", "pattern": `^https?://example\.com(:\d+)?/mockb`, "body_base64": "AAEC/w==", "headers": []map[string]string{{"name": "Content-Type", "value": "application/octet-stream"}}},
		},
		"headers": []map[string]any{
			{"id": "req", "pattern": `^https?://example\.com(:\d+)?/hdr`, "scope": "request", "operations": []map[string]string{{"action": "add", "name": "X-Kiko", "value": "1"}}},
			{"id": "resp", "pattern": `^https?://example\.com(:\d+)?/hdr`, "scope": "response", "operations": []map[string]string{
				{"action": "delete", "name": "Server"}, {"action": "add", "name": "X-Seen", "value": "yes"}}},
		},
	}
}

func rewriteBoxConfig(ca mitmTestCA, trustedPEM string, proxyPort int, include string, rules map[string]any) string {
	var section map[string]any
	_ = json.Unmarshal([]byte(mitmSection(ca, true, strings.Split(include, ",")...)), &section)
	section["http_rewrite"] = rules
	section["capture"] = map[string]any{"enabled": true, "body": true}
	mitm, _ := json.Marshal(section)
	trusted, _ := json.Marshal(map[string]any{"certificate": []string{trustedPEM}})
	return `{
  "log": {"disabled": true},
  "certificate": ` + string(trusted) + `,
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}, {"action": "route-options", "override_address": "127.0.0.1"}], "final": "direct"},
  "mitm": ` + string(mitm) + `
}`
}

type rewriteBox struct {
	ctx      context.Context
	instance *box.Box
	traffic  *trafficcontrol.Manager
	manager  *capture.Manager
}

func startRewriteBox(t *testing.T, config string) *rewriteBox {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	traffic := trafficcontrol.NewManager()
	instance.Router().AppendTracker(traffic)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })
	engine := service.FromContext[adapter.MITMEngine](ctx)
	return &rewriteBox{ctx: ctx, instance: instance, traffic: traffic, manager: engine.(adapter.MITMCaptureProvider).Capture()}
}

func (b *rewriteBox) records(t *testing.T, authority string) []capture.Record {
	t.Helper()
	var out []capture.Record
	require.Eventually(t, func() bool {
		out = out[:0]
		for _, r := range b.manager.List(capture.Filter{Limit: 500}).Records {
			if r.State == capture.StateInProgress {
				return false
			}
			if r.Authority == authority {
				out = append(out, r)
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)
	return out
}

func (b *rewriteBox) find(t *testing.T, path string) capture.Record {
	t.Helper()
	var found capture.Record
	require.Eventually(t, func() bool {
		for _, r := range b.manager.List(capture.Filter{Limit: 500}).Records {
			if r.Path == path && r.State != capture.StateInProgress {
				found = r
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, path)
	return found
}

func rewriteClient(t *testing.T, proxyPort int, roots *x509.CertPool, serverName string) *http.Client {
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	require.NoError(t, err)
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: serverName},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Timeout:       20 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type fetched struct {
	response *http.Response
	body     string
}

func fetch(t *testing.T, client *http.Client, base string, host string, path string) fetched {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, base+path, nil)
	require.NoError(t, err)
	request.Host = host
	response, err := client.Do(request)
	require.NoError(t, err, path)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return fetched{response, string(body)}
}

// exerciseRewrites runs every rule category against base and checks what the client got.
func exerciseRewrites(t *testing.T, client *http.Client, base string, host string, origin *rewriteOrigin, scheme string, proto string) {
	t.Helper()
	for path, want := range map[string]struct {
		status      int
		contentType string
		body        string
	}{
		"/dict":  {200, "application/json", "{}"},
		"/img":   {200, "image/gif", string(rewrite.TinyGIF)},
		"/r200":  {200, "text/plain", ""},
		"/arr":   {200, "application/json", "[]"},
		"/mock":  {201, "text/plain; charset=utf-8", "hello"},
		"/mockb": {200, "application/octet-stream", "\x00\x01\x02\xff"},
	} {
		got := fetch(t, client, base, host, path)
		require.Equal(t, want.status, got.response.StatusCode, path)
		require.Equal(t, want.contentType, got.response.Header.Get("Content-Type"), path)
		require.Equal(t, want.body, got.body, path)
		require.Equal(t, proto, got.response.Proto, path)
	}
	require.Equal(t, "1", fetch(t, client, base, host, "/mock").response.Header.Get("X-Mock"))
	got := fetch(t, client, base, host, "/old/abc?x=1")
	require.Equal(t, 302, got.response.StatusCode)
	require.Equal(t, scheme+"://example.com/new/abc", got.response.Header.Get("Location"))
	got = fetch(t, client, base, host, "/tmp/zed")
	require.Equal(t, 307, got.response.StatusCode)
	require.Equal(t, scheme+"://example.com/moved/zed", got.response.Header.Get("Location"))
	require.Zero(t, origin.hits.Load(), "local answers reach the origin")

	request, _ := http.NewRequest(http.MethodGet, base+"/drop", nil)
	request.Host = host
	if response, err := client.Do(request); err == nil {
		response.Body.Close()
		// The HTTP proxy inbound turns a dropped upstream connection into a 502 of its own.
		require.Equal(t, "http", scheme)
		require.Equal(t, http.StatusBadGateway, response.StatusCode)
	}
	require.Zero(t, origin.hits.Load())

	got = fetch(t, client, base, host, "/hdr")
	require.Equal(t, 1, int(origin.hits.Load()))
	require.Equal(t, proto+" "+host+"/hdr", got.body)
	require.Equal(t, "1", got.response.Header.Get("X-Origin-Saw"))
	require.Empty(t, got.response.Header.Get("Server"))
	require.Equal(t, "yes", got.response.Header.Get("X-Seen"))
	got = fetch(t, client, base, host, "/plain")
	require.Equal(t, proto+" "+host+"/plain", got.body)
	require.Equal(t, "nginx", got.response.Header.Get("Server"))
	require.Empty(t, got.response.Header.Get("X-Seen"))
	require.Equal(t, 2, int(origin.hits.Load()))
}

func hitRules(r capture.Record) map[string]bool {
	out := map[string]bool{}
	for _, hit := range r.Rewrites {
		out[hit.Rule+"/"+hit.Kind] = true
	}
	return out
}

func TestMITMRewriteEndToEnd(t *testing.T) {
	if !h2relay.Supported {
		t.Skip("h2 relay needs Go 1.26")
	}
	h1Origin := newRewriteOrigin(t, "h1")
	h2Origin := newRewriteOrigin(t, "h2")
	plainOrigin := newRewriteOrigin(t, "plain")
	trustedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h1Origin.server.Certificate().Raw}))
	ca := writeMITMTestCA(t)
	proxyPort := freePort(t)
	included := "example.com:" + strconv.Itoa(h1Origin.port) + ",example.com:" + strconv.Itoa(h2Origin.port)
	b := startRewriteBox(t, rewriteBoxConfig(ca, trustedPEM, proxyPort, included, rewriteRules("reject-dict")))
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certificatePEM))

	t.Run("tls h1", func(t *testing.T) {
		client := rewriteClient(t, proxyPort, roots, "example.com")
		// Only the h1 origin is reached through ALPN http/1.1: ask for it.
		client.Transport.(*http.Transport).ForceAttemptHTTP2 = false
		base := "https://127.0.0.1:" + strconv.Itoa(h1Origin.port)
		exerciseRewrites(t, client, base, "example.com", h1Origin, "https", "HTTP/1.1")
		record := b.find(t, "/dict")
		require.True(t, record.Rewritten)
		require.Equal(t, "https", record.Scheme)
		require.Equal(t, map[string]bool{"dict/url": true}, hitRules(record))
		hdr := b.find(t, "/hdr")
		require.Equal(t, map[string]bool{"req/header": true, "resp/header": true}, hitRules(hdr))
		require.NotEmpty(t, hdr.Rewrites[0].Changes)
		require.False(t, b.find(t, "/plain").Rewritten)
		drop := b.find(t, "/drop")
		require.Equal(t, "reject", drop.Rewrites[0].Action)
	})

	t.Run("tls h2", func(t *testing.T) {
		client := rewriteClient(t, proxyPort, roots, "example.com")
		base := "https://127.0.0.1:" + strconv.Itoa(h2Origin.port)
		exerciseRewrites(t, client, base, "example.com", h2Origin, "https", "HTTP/2.0")
		var h2Records int
		for _, r := range b.manager.List(capture.Filter{Limit: 500}).Records {
			if r.Proto == "h2" && r.Rewritten {
				h2Records++
			}
		}
		require.Equal(t, 11, h2Records)
	})

	t.Run("plain http", func(t *testing.T) {
		client := rewriteClient(t, proxyPort, roots, "")
		host := "example.com:" + strconv.Itoa(plainOrigin.port)
		exerciseRewrites(t, client, "http://"+host, host, plainOrigin, "http", "HTTP/1.1")
		var plain int
		for _, r := range b.manager.List(capture.Filter{Limit: 500}).Records {
			if r.Scheme == "http" && r.Rewritten {
				plain++
				require.Equal(t, "example.com:"+strconv.Itoa(plainOrigin.port), r.Authority)
			}
		}
		require.Equal(t, 11, plain)
	})

	t.Run("live reload on a keep-alive connection", func(t *testing.T) {
		client := rewriteClient(t, proxyPort, roots, "example.com")
		client.Transport.(*http.Transport).ForceAttemptHTTP2 = false
		base := "https://127.0.0.1:" + strconv.Itoa(h1Origin.port)
		reused := func(path string) (string, bool) {
			var wasReused bool
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { wasReused = info.Reused }}
			request, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, base+path, nil)
			request.Host = "example.com"
			response, err := client.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			return string(body), wasReused
		}
		body, _ := reused("/dict")
		require.Equal(t, "{}", body)
		result, err := applyLive(t, b.ctx, rewriteBoxConfig(ca, trustedPEM, proxyPort, included, rewriteRules("reject-array")))
		require.NoError(t, err)
		require.True(t, result.Applied, result.Reason)
		body, wasReused := reused("/dict")
		require.Equal(t, "[]", body)
		require.True(t, wasReused, "the keep-alive connection must survive the reload")

		// A set that fails to compile changes nothing.
		broken := rewriteRules("reject-dict")
		broken["url"] = []map[string]any{{"pattern": "([", "action": "reject"}}
		_, err = applyLive(t, b.ctx, rewriteBoxConfig(ca, trustedPEM, proxyPort, included, broken))
		require.Error(t, err)
		body, _ = reused("/dict")
		require.Equal(t, "[]", body)

		// Removing the rules turns the exchange into a plain relay.
		before := h1Origin.hits.Load()
		result, err = applyLive(t, b.ctx, rewriteBoxConfig(ca, trustedPEM, proxyPort, included, map[string]any{}))
		require.NoError(t, err)
		require.True(t, result.Applied, result.Reason)
		body, wasReused = reused("/dict")
		require.Equal(t, "HTTP/1.1 example.com/dict", body)
		require.True(t, wasReused)
		require.Equal(t, before+1, h1Origin.hits.Load())
	})

	t.Run("connection level reject", func(t *testing.T) {
		rules := map[string]any{"url": []map[string]any{
			{"id": "whole", "pattern": `^https://(example|blocked)\.test(:\d+)?/`, "action": "reject"},
			{"id": "wholeex", "pattern": `^https://example\.com(:\d+)?/`, "action": "reject"},
			{"id": "path", "pattern": `^https://paths\.test/ads`, "action": "reject"},
		}}
		result, err := applyLive(t, b.ctx, rewriteBoxConfig(ca, trustedPEM, proxyPort, included, rules))
		require.NoError(t, err)
		require.True(t, result.Applied, result.Reason)
		rejected := func(domain string) int64 {
			var total int64
			for _, c := range b.traffic.ClosedConnections() {
				if c.Metadata.Domain == domain && c.Rejects != nil {
					total += c.Rejects.Load()
				}
			}
			return total
		}
		base := "https://127.0.0.1:" + strconv.Itoa(h1Origin.port)

		// An undecrypted host is refused at CONNECT time, before any dial.
		blocked := rewriteClient(t, proxyPort, roots, "blocked.test")
		_, err = blocked.Get(base + "/anything")
		require.Error(t, err)
		require.Eventually(t, func() bool { return rejected("blocked.test") > 0 }, 5*time.Second, 10*time.Millisecond)
		before := h1Origin.hits.Load()

		// A path-specific rule cannot refuse the host: its connection goes through.
		other := rewriteClient(t, proxyPort, roots, "paths.test")
		_, err = other.Get(base + "/anything")
		require.Error(t, err, "the origin certificate does not name paths.test")
		require.Zero(t, rejected("paths.test"))

		// A decrypted host keeps its connection: the request is dropped inside it.
		decrypted := rewriteClient(t, proxyPort, roots, "example.com")
		request, _ := http.NewRequest(http.MethodGet, base+"/x", nil)
		request.Host = "example.com"
		if response, getErr := decrypted.Do(request); getErr == nil {
			response.Body.Close()
			t.Fatal("request should be dropped")
		}
		require.Zero(t, rejected("example.com"))
		require.Equal(t, before, h1Origin.hits.Load())
		dropped := b.find(t, "/x")
		require.Equal(t, "wholeex", dropped.Rewrites[0].Rule)

		// Once the host leaves the include list it is refused at connection level.
		result, err = applyLive(t, b.ctx, rewriteBoxConfig(ca, trustedPEM, proxyPort, "other.test", rules))
		require.NoError(t, err)
		require.True(t, result.Applied, result.Reason)
		undecrypted := rewriteClient(t, proxyPort, roots, "example.com")
		_, err = undecrypted.Get(base + "/y")
		require.Error(t, err)
		require.Eventually(t, func() bool { return rejected("example.com") > 0 }, 5*time.Second, 10*time.Millisecond)
		require.Equal(t, before, h1Origin.hits.Load())
	})

}
