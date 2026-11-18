package box_test

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	h2relay "github.com/sagernet/sing-box/common/mitm/h2"
	"github.com/sagernet/sing-box/route"

	"github.com/stretchr/testify/require"
)

// scriptOrigin answers the paths the script tests use.
type scriptOrigin struct {
	server *httptest.Server
	port   int
	hits   atomic.Int32
	// release lets the sse handler finish.
	release chan struct{}
}

func newScriptOrigin(t *testing.T, secure bool) *scriptOrigin {
	origin := &scriptOrigin{release: make(chan struct{})}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin.hits.Add(1)
		name := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		switch name {
		case "echo":
			data, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			headers := map[string]string{}
			for k := range r.Header {
				headers[k] = r.Header.Get(k)
			}
			out, _ := json.Marshal(map[string]any{"method": r.Method, "path": r.URL.RequestURI(), "headers": headers, "body": string(data), "length": r.ContentLength})
			w.Write(out)
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Add("Set-Cookie", "a=1")
			w.Header().Add("Set-Cookie", "b=2")
			io.WriteString(w, `{"ads":[1,2],"keep":true}`)
		case "gz":
			var packed bytes.Buffer
			zw := gzip.NewWriter(&packed)
			zw.Write([]byte(`{"ads":[1,2],"keep":true}`))
			zw.Close()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(packed.Bytes())
		case "notmod":
			w.WriteHeader(http.StatusNotModified)
		case "empty":
			w.Header().Set("Content-Type", "application/json")
		case "big":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Origin", "big")
			io.WriteString(w, `{"ads":"`+strings.Repeat("a", 3000)+`"}`)
		case "sse":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: one\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-origin.release:
			case <-time.After(5 * time.Second):
			}
			io.WriteString(w, "data: two\n\n")
		default:
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "origin "+r.Host+r.URL.RequestURI())
		}
	})
	if secure {
		origin.server = httptest.NewUnstartedServer(handler)
		origin.server.EnableHTTP2 = true
		origin.server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
		origin.server.StartTLS()
	} else {
		origin.server = httptest.NewServer(handler)
	}
	t.Cleanup(origin.server.Close)
	origin.port = origin.server.Listener.Addr().(*net.TCPAddr).Port
	return origin
}

type scriptFixture struct {
	t         *testing.T
	box       *rewriteBox
	origin    *scriptOrigin
	plain     *scriptOrigin
	ca        mitmTestCA
	trusted   string
	proxyPort int
	include   string
	roots     *x509.CertPool
	// cachePath, when set, enables the cache file there (persistent $persistentStore).
	cachePath string
}

// scriptFiles are the scripts of the end to end tests, by file name.
var scriptFiles = map[string]string{
	"req_mutate.js": `
var h = $request.headers;
h['X-Script'] = 'hello';
var body = JSON.parse($request.body || '{}');
body.added = 'by-script';
body.id = $request.id ? 'has-id' : 'no-id';
$done({headers: h, body: JSON.stringify(body)});`,
	"mock.js": `$done({response: {status: 201, headers: {'X-Mock': 'yes', 'Content-Type': 'application/json'}, body: JSON.stringify({mock: true, url: $request.url})}});`,
	"resp_mutate.js": `
var h = $response.headers;
h['X-Resp-Script'] = 'ok';
h['Set-Cookie'] = 'only=1';
var b = JSON.parse($response.body);
delete b.ads;
b.status = $response.status;
$done({status: 203, headers: h, body: JSON.stringify(b)});`,
	"abort.js":  `$done({abort: true});`,
	"throws.js": `throw new Error('script failure');`,
	"slow.js":   `while (true) {}`,
	"header_only.js": `
var h = $response.headers;
h['X-Header-Only'] = typeof $response.body;
$done({headers: h});`,
	"body_stream.js": `$done({body: 'never'});`,
	"url.js":         `$done({url: $request.url.replace('/via/', '/moved/')});`,
	"async.js": `
setTimeout(function () {
  Promise.resolve().then(function () { $done({headers: Object.assign($request.headers, {'X-Async': 'done'})}); });
}, 30);`,
	"parse.js":   `JSON.parse($response.body); $done({});`,
	"req_hdr.js": `var h = $response.headers; h['X-Saw'] = $request.headers['X-Probe'] + '|' + $request.method; $done({headers: h});`,
	"noop.js":    `var x = 1;`,
	"v2.js":      `var h = $response.headers; h['X-Version'] = '2'; $done({headers: h});`,
	"v1.js":      `var h = $response.headers; h['X-Version'] = '1'; $done({headers: h});`,
	"global.js":  `if (typeof leaked !== 'undefined') { throw new Error('state leaked'); } leaked = 1; $done({});`,
	"count.js": `
var n = parseInt($persistentStore.read('n') || '0', 10) + 1;
$persistentStore.write(String(n), 'n');
$persistentStore.write('run-' + n, '@shared/last');
console.log('count ' + n);
$notification.post('counted', '', String(n));
$done({response: {status: 200, body: String(n)}});`,
}

func writeScripts(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scripts"), 0o755))
	for name, content := range scriptFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts", name), []byte(content), 0o644))
	}
	t.Chdir(dir)
}

func scriptsJSON(t *testing.T, scripts []map[string]any) string {
	out, err := json.Marshal(scripts)
	require.NoError(t, err)
	return string(out)
}

func (f *scriptFixture) config(scripts []map[string]any) string {
	rules := map[string]any{"max_body_size": "2KB"}
	config := rewriteBoxConfig(f.ca, f.trusted, f.proxyPort, f.include, rules)
	if f.cachePath != "" {
		cache, _ := json.Marshal(map[string]any{"cache_file": map[string]any{"enabled": true, "path": f.cachePath}})
		config = withTopLevel(config, "experimental", string(cache))
	}
	if scripts == nil {
		return config
	}
	return withTopLevel(config, "scripts", scriptsJSON(f.t, scripts))
}

func newScriptFixture(t *testing.T, scripts []map[string]any) *scriptFixture {
	return newScriptFixtureCache(t, scripts, "")
}

func newScriptFixtureCache(t *testing.T, scripts []map[string]any, cachePath string) *scriptFixture {
	if !h2relay.Supported {
		t.Skip("h2 relay needs Go 1.26")
	}
	writeScripts(t)
	route.MITMInternalAllowLoopback = true
	t.Cleanup(func() { route.MITMInternalAllowLoopback = false })
	f := &scriptFixture{t: t, cachePath: cachePath}
	f.origin = newScriptOrigin(t, true)
	f.plain = newScriptOrigin(t, false)
	f.trusted = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.origin.server.Certificate().Raw}))
	f.ca = writeMITMTestCA(t)
	f.proxyPort = freePort(t)
	f.include = "example.com:" + strconv.Itoa(f.origin.port)
	f.roots = x509.NewCertPool()
	require.True(t, f.roots.AppendCertsFromPEM(f.ca.certificatePEM))
	f.box = startRewriteBox(t, f.config(scripts))
	return f
}

func (f *scriptFixture) client(h2 bool) *http.Client {
	client := rewriteClient(f.t, f.proxyPort, f.roots, "example.com")
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = h2
	transport.DisableCompression = true
	return client
}

func (f *scriptFixture) do(client *http.Client, method, path string, body string, header http.Header) (*http.Response, []byte) {
	f.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+path, reader)
	require.NoError(f.t, err)
	request.Host = "example.com"
	for k, v := range header {
		request.Header[k] = v
	}
	response, err := client.Do(request)
	require.NoError(f.t, err, path)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	require.NoError(f.t, err, path)
	return response, data
}

func scriptHits(r capture.Record) map[string]flow.RewriteHit {
	out := map[string]flow.RewriteHit{}
	for _, hit := range r.Rewrites {
		if hit.Kind == "script" {
			out[hit.Rule] = hit
		}
	}
	return out
}

func baseScripts() []map[string]any {
	return []map[string]any{
		{"tag": "req-mutate", "type": "http-request", "pattern": `^https://example\.com/\w+/echo`, "source_path": "scripts/req_mutate.js", "requires_body": true},
		{"tag": "mock", "type": "http-request", "pattern": `^https://example\.com/\w+/mock`, "source_path": "scripts/mock.js"},
		{"tag": "resp-mutate", "type": "http-response", "pattern": `^https://example\.com/\w+/(json|gz)$`, "source_path": "scripts/resp_mutate.js", "requires_body": true},
		{"tag": "abort", "type": "http-request", "pattern": `^https://example\.com/\w+/abort$`, "source_path": "scripts/abort.js"},
		{"tag": "resp-abort", "type": "http-response", "pattern": `^https://example\.com/\w+/abortresp`, "source_path": "scripts/abort.js"},
		{"tag": "throws", "type": "http-request", "pattern": `^https://example\.com/\w+/throw`, "source_path": "scripts/throws.js"},
		{"tag": "slow", "type": "http-request", "pattern": `^https://example\.com/\w+/slow`, "source_path": "scripts/slow.js", "timeout": "300ms"},
		{"tag": "stream-body", "type": "http-response", "pattern": `^https://example\.com/\w+/sse`, "source_path": "scripts/body_stream.js", "requires_body": true},
		{"tag": "stream-header", "type": "http-response", "pattern": `^https://example\.com/\w+/sse`, "source_path": "scripts/header_only.js"},
		{"tag": "big-body", "type": "http-response", "pattern": `^https://example\.com/\w+/big`, "source_path": "scripts/body_stream.js", "requires_body": true, "max_size": "1KB"},
		{"tag": "big-header", "type": "http-response", "pattern": `^https://example\.com/\w+/big`, "source_path": "scripts/header_only.js"},
		{"tag": "url", "type": "http-request", "pattern": `^https://example\.com/\w+/via/`, "source_path": "scripts/url.js"},
		{"tag": "async", "type": "http-request", "pattern": `^https://example\.com/\w+/async`, "source_path": "scripts/async.js"},
		{"tag": "nobody", "type": "http-response", "pattern": `^https://example\.com/\w+/(notmod|empty)$`, "source_path": "scripts/parse.js", "requires_body": true},
		{"tag": "reqhdr", "type": "http-response", "pattern": `^https://example\.com/\w+/reqhdr$`, "source_path": "scripts/req_hdr.js"},
		{"tag": "global", "type": "http-request", "pattern": `^https://example\.com/\w+/global`, "source_path": "scripts/global.js"},
	}
}

func TestMITMScriptEndToEnd(t *testing.T) {
	f := newScriptFixture(t, baseScripts())
	for _, tc := range []struct {
		prefix string
		h2     bool
		proto  string
	}{{"h1", false, "HTTP/1.1"}, {"h2", true, "HTTP/2.0"}} {
		t.Run(tc.prefix, func(t *testing.T) {
			client := f.client(tc.h2)
			do := func(method, name, body string, header http.Header) (*http.Response, []byte) {
				response, data := f.do(client, method, "/"+tc.prefix+"/"+name, body, header)
				require.Equal(t, tc.proto, response.Proto)
				return response, data
			}
			hits := func(name string) map[string]flow.RewriteHit {
				return scriptHits(f.box.find(t, "/"+tc.prefix+"/"+name))
			}

			t.Run("request mutate", func(t *testing.T) {
				response, data := do("POST", "echo", `{"user":"u"}`, http.Header{"Content-Type": {"application/json"}})
				require.Equal(t, 200, response.StatusCode)
				var echoed struct {
					Headers map[string]string
					Body    string
					Length  int64
				}
				require.NoError(t, json.Unmarshal(data, &echoed))
				require.Equal(t, "hello", echoed.Headers["X-Script"])
				var sent map[string]any
				require.NoError(t, json.Unmarshal([]byte(echoed.Body), &sent))
				require.Equal(t, "by-script", sent["added"])
				require.Equal(t, "has-id", sent["id"])
				require.Equal(t, "u", sent["user"])
				require.EqualValues(t, len(echoed.Body), echoed.Length)
				hit := hits("echo")["req-mutate"]
				require.Equal(t, "modify", hit.Action)
				require.Equal(t, "request", hit.Side)
				require.NotNil(t, hit.Run)
				require.Equal(t, "http-request", hit.Run.Phase)
				require.Greater(t, hit.Run.Duration, time.Duration(0))
			})

			t.Run("mock response", func(t *testing.T) {
				before := f.origin.hits.Load()
				response, data := do("GET", "mock", "", nil)
				require.Equal(t, 201, response.StatusCode)
				require.Equal(t, "yes", response.Header.Get("X-Mock"))
				require.Contains(t, string(data), `"mock":true`)
				require.Equal(t, before, f.origin.hits.Load(), "the origin must not be asked")
				require.Equal(t, "respond", hits("mock")["mock"].Action)
			})

			t.Run("response mutate", func(t *testing.T) {
				response, data := do("GET", "json", "", nil)
				require.Equal(t, 203, response.StatusCode)
				require.Equal(t, "ok", response.Header.Get("X-Resp-Script"))
				require.Equal(t, []string{"only=1"}, response.Header.Values("Set-Cookie"))
				require.JSONEq(t, `{"keep":true,"status":200}`, string(data))
				require.Equal(t, strconv.Itoa(len(data)), response.Header.Get("Content-Length"))
				require.Equal(t, "modify", hits("json")["resp-mutate"].Action)
			})

			t.Run("gzip response", func(t *testing.T) {
				response, data := do("GET", "gz", "", nil)
				require.Equal(t, 203, response.StatusCode)
				require.Equal(t, "gzip", response.Header.Get("Content-Encoding"))
				zr, err := gzip.NewReader(bytes.NewReader(data))
				require.NoError(t, err)
				plain, err := io.ReadAll(zr)
				require.NoError(t, err)
				require.JSONEq(t, `{"keep":true,"status":200}`, string(plain))
			})

			t.Run("abort", func(t *testing.T) {
				before := f.origin.hits.Load()
				request, err := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+tc.prefix+"/abort", nil)
				require.NoError(t, err)
				request.Host = "example.com"
				response, err := client.Do(request)
				if err == nil {
					response.Body.Close()
				}
				require.Error(t, err)
				require.Equal(t, before, f.origin.hits.Load())
				require.Equal(t, "abort", hits("abort")["abort"].Action)
			})

			t.Run("abort a response", func(t *testing.T) {
				request, err := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+tc.prefix+"/abortresp", nil)
				require.NoError(t, err)
				request.Host = "example.com"
				response, err := client.Do(request)
				if err == nil {
					_, err = io.ReadAll(response.Body)
					response.Body.Close()
				}
				require.Error(t, err)
				require.Equal(t, "abort", hits("abortresp")["resp-abort"].Action)
			})

			t.Run("error isolation", func(t *testing.T) {
				response, data := do("GET", "throw", "", nil)
				require.Equal(t, 200, response.StatusCode)
				require.Contains(t, string(data), "/"+tc.prefix+"/throw")
				hit := hits("throw")["throws"]
				require.Equal(t, "error", hit.Action)
				require.Contains(t, hit.Run.Error, "script failure")
			})

			t.Run("timeout isolation", func(t *testing.T) {
				start := time.Now()
				response, _ := do("GET", "slow", "", nil)
				require.Equal(t, 200, response.StatusCode)
				require.Less(t, time.Since(start), 5*time.Second)
				require.Equal(t, "timeout", hits("slow")["slow"].Action)
			})

			t.Run("no state leaks between calls", func(t *testing.T) {
				for i := 0; i < 3; i++ {
					response, _ := do("GET", "global", "", nil)
					require.Equal(t, 200, response.StatusCode)
				}
				require.Equal(t, "none", hits("global")["global"].Action)
			})

			t.Run("async", func(t *testing.T) {
				response, data := do("GET", "async", "", nil)
				require.Equal(t, 200, response.StatusCode)
				require.Contains(t, string(data), "origin")
				require.Equal(t, "modify", hits("async")["async"].Action)
			})

			t.Run("url change", func(t *testing.T) {
				_, data := do("GET", "via/x", "", nil)
				require.Contains(t, string(data), "/"+tc.prefix+"/moved/x")
				require.Equal(t, "modify", hits("moved/x")["url"].Action)
			})

			t.Run("streaming is skipped", func(t *testing.T) {
				request, err := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+tc.prefix+"/sse", nil)
				require.NoError(t, err)
				request.Host = "example.com"
				resp, err := client.Do(request)
				require.NoError(t, err)
				defer resp.Body.Close()
				// The first event arrives before the origin finishes: the body streams.
				buf := make([]byte, len("data: one\n\n"))
				_, err = io.ReadFull(resp.Body, buf)
				require.NoError(t, err)
				require.Equal(t, "data: one\n\n", string(buf))
				require.Equal(t, "undefined", resp.Header.Get("X-Header-Only"))
				f.origin.release <- struct{}{}
				rest, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.Equal(t, "data: two\n\n", string(rest))
				h := hits("sse")
				require.Equal(t, "skipped", h["stream-body"].Action)
				require.Equal(t, "stream", h["stream-body"].Run.Reason)
				require.Equal(t, "modify", h["stream-header"].Action)
			})

			t.Run("bodyless responses skip body scripts", func(t *testing.T) {
				for i := 0; i < 60; i++ {
					response, _ := do("GET", "notmod", "", nil)
					require.Equal(t, 304, response.StatusCode)
				}
				for i := 0; i < 3; i++ {
					response, _ := do("GET", "empty", "", nil)
					require.Equal(t, 200, response.StatusCode)
				}
				require.Equal(t, "skipped", hits("notmod")["nobody"].Action)
				require.Equal(t, "skipped", hits("empty")["nobody"].Action)
			})

			t.Run("response scripts see the request headers", func(t *testing.T) {
				response, _ := do("GET", "reqhdr", "", http.Header{"X-Probe": {"probe-value"}})
				require.Equal(t, "probe-value|GET", response.Header.Get("X-Saw"))
			})

			t.Run("size is skipped", func(t *testing.T) {
				response, data := do("GET", "big", "", nil)
				require.Equal(t, "undefined", response.Header.Get("X-Header-Only"))
				require.Contains(t, string(data), "aaaa")
				h := hits("big")
				require.Equal(t, "skipped", h["big-body"].Action)
				require.Equal(t, "size", h["big-body"].Run.Reason)
				require.Equal(t, "modify", h["big-header"].Action)
			})
		})
	}
}

func TestMITMScriptAutoPause(t *testing.T) {
	f := newScriptFixture(t, []map[string]any{
		{"tag": "bad", "type": "http-request", "pattern": `^https://example\.com/h1/`, "source_path": "scripts/throws.js"},
	})
	client := f.client(false)
	for i := 0; i < 60; i++ {
		response, _ := f.do(client, "GET", "/h1/p"+strconv.Itoa(i), "", nil)
		require.Equal(t, 200, response.StatusCode)
	}
	require.Equal(t, "error", scriptHits(f.box.find(t, "/h1/p0"))["bad"].Action)
	require.Equal(t, "paused", scriptHits(f.box.find(t, "/h1/p59"))["bad"].Action)
}

func TestMITMScriptHotReload(t *testing.T) {
	f := newScriptFixture(t, []map[string]any{
		{"tag": "ver", "type": "http-response", "pattern": `^https://example\.com/h1/`, "source_path": "scripts/v1.js"},
	})
	client := f.client(false)
	version := func(path string) string {
		response, _ := f.do(client, "GET", path, "", nil)
		return response.Header.Get("X-Version")
	}
	require.Equal(t, "1", version("/h1/a"))
	result, err := applyLive(t, f.box.ctx, f.config([]map[string]any{
		{"tag": "ver", "type": "http-response", "pattern": `^https://example\.com/h1/`, "source_path": "scripts/v2.js"},
	}))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Equal(t, "2", version("/h1/b"))

	// A script that does not compile changes nothing.
	_, err = applyLive(t, f.box.ctx, f.config([]map[string]any{
		{"tag": "ver", "type": "http-response", "pattern": `(`, "source_path": "scripts/v1.js"},
	}))
	require.Error(t, err)
	_, err = applyLive(t, f.box.ctx, f.config([]map[string]any{
		{"tag": "ver", "type": "http-response", "pattern": `^https://example\.com/h1/`, "source_path": "scripts/missing.js"},
	}))
	require.Error(t, err)
	require.Equal(t, "2", version("/h1/c"))

	// Removing the scripts section removes the scripts.
	result, err = applyLive(t, f.box.ctx, f.config(nil))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.Equal(t, "", version("/h1/d"))
}

func TestMITMScriptPlainHTTP(t *testing.T) {
	f := newScriptFixture(t, []map[string]any{
		{"tag": "plain-req", "type": "http-request", "pattern": `^http://example\.com:\d+/p/echo`, "source_path": "scripts/req_mutate.js", "requires_body": true},
		{"tag": "plain-resp", "type": "http-response", "pattern": `^http://example\.com:\d+/p/`, "source_path": "scripts/v1.js"},
		{"tag": "https-only", "type": "http-response", "pattern": `^https://`, "source_path": "scripts/v2.js"},
	})
	client := rewriteClient(t, f.proxyPort, f.roots, "")
	host := "example.com:" + strconv.Itoa(f.plain.port)
	request, err := http.NewRequest(http.MethodPost, "http://"+host+"/p/echo", strings.NewReader(`{"user":"u"}`))
	require.NoError(t, err)
	request.Host = host
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	require.Equal(t, "1", response.Header.Get("X-Version"), "the https-only script must not run")
	var echoed struct {
		Headers map[string]string
		Body    string
	}
	require.NoError(t, json.Unmarshal(data, &echoed))
	require.Equal(t, "hello", echoed.Headers["X-Script"])
	require.Contains(t, echoed.Body, "by-script")
}

func TestMITMScriptRequestBodyLimits(t *testing.T) {
	f := newScriptFixture(t, []map[string]any{
		{"tag": "req-mutate", "type": "http-request", "pattern": `^https://example\.com/\w+/echo`, "source_path": "scripts/req_mutate.js", "requires_body": true, "max_size": "1KB"},
	})
	for _, h2 := range []bool{false, true} {
		prefix := "h1"
		if h2 {
			prefix = "h2"
		}
		client := f.client(h2)
		big := `{"user":"` + strings.Repeat("u", 5000) + `"}`
		_, data := f.do(client, "POST", "/"+prefix+"/echo", big, http.Header{"Content-Type": {"application/json"}})
		var echoed struct {
			Body    string
			Headers map[string]string
		}
		require.NoError(t, json.Unmarshal(data, &echoed))
		require.Equal(t, big, echoed.Body, prefix+": a body over the limit passes unmodified")
		require.Empty(t, echoed.Headers["X-Script"])
		hit := scriptHits(f.box.find(t, "/"+prefix+"/echo"))["req-mutate"]
		require.Equal(t, "skipped", hit.Action)
		require.Equal(t, "size", hit.Run.Reason)
	}
}
