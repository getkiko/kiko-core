package box_test

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/body"
	h2relay "github.com/sagernet/sing-box/common/mitm/h2"
	"github.com/sagernet/sing-box/route"

	"github.com/stretchr/testify/require"
)

// bodyOrigin serves the bodies the rewrite tests need; the path is /h1/<name> or /h2/<name>.
type bodyOrigin struct {
	server  *httptest.Server
	port    int
	hits    atomic.Int32
	release chan struct{}
	grpcIn  chan string
}

func newBodyOrigin(t *testing.T, secure bool) *bodyOrigin {
	origin := &bodyOrigin{release: make(chan struct{}), grpcIn: make(chan string, 4)}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin.hits.Add(1)
		name := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		flush := func() { w.(http.Flusher).Flush() }
		switch name {
		case "text":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "hello hello")
		case "gz":
			var packed bytes.Buffer
			zw := gzip.NewWriter(&packed)
			zw.Write([]byte("hello hello"))
			zw.Close()
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(packed.Bytes())
		case "br":
			packed, err := body.Encode("br", []byte("hello hello"))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "br")
			w.Write(packed)
		case "big":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "5000")
			io.WriteString(w, strings.Repeat("a", 5000))
		case "bigchunk":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, strings.Repeat("a", 2500))
			flush()
			io.WriteString(w, strings.Repeat("a", 2500))
		case "chunked":
			w.Header().Set("Content-Type", "text/html")
			for _, part := range []string{"hel", "lo ", "hello"} {
				io.WriteString(w, part)
				flush()
				time.Sleep(10 * time.Millisecond)
			}
		case "sse":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: hello 1\n\n")
			flush()
			select {
			case <-origin.release:
			case <-time.After(5 * time.Second):
			}
			io.WriteString(w, "data: hello 2\n\n")
		case "grpc":
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(200)
			io.WriteString(w, "hello frame 1")
			flush()
			select {
			case <-origin.release:
			case <-time.After(5 * time.Second):
			}
			io.WriteString(w, "hello frame 2")
		case "grpcup":
			buf := make([]byte, 5)
			io.ReadFull(r.Body, buf)
			origin.grpcIn <- string(buf)
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(200)
			io.Copy(io.Discard, r.Body)
		case "echo":
			data, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Req-Length", strconv.FormatInt(r.ContentLength, 10))
			w.Header().Set("X-Req-Encoding", strings.Join(r.TransferEncoding, ","))
			w.Write(data)
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

// seenOrigin reports what an internal rewrite target saw.
type seenOrigin struct {
	server *httptest.Server
	port   int
	hits   atomic.Int32
}

func newSeenOrigin(t *testing.T, secure bool) *seenOrigin {
	origin := &seenOrigin{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin.hits.Add(1)
		sni := "-"
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "sni=%s proto=%s host=%s uri=%s x=%s", sni, r.Proto, r.Host, r.RequestURI, r.Header.Get("X-Rule"))
	})
	if secure {
		origin.server = httptest.NewTLSServer(handler)
	} else {
		origin.server = httptest.NewServer(handler)
	}
	t.Cleanup(origin.server.Close)
	origin.port = origin.server.Listener.Addr().(*net.TCPAddr).Port
	return origin
}

type bodyFixture struct {
	t         *testing.T
	box       *rewriteBox
	ca        mitmTestCA
	trusted   string
	proxyPort int
	include   string
	origin    *bodyOrigin
	plain     *bodyOrigin
	roots     *x509.CertPool
	other     *seenOrigin
	otherHTTP *seenOrigin
	rules     func(extra map[string]any) map[string]any
}

func bodyBoxConfig(f *bodyFixture, rules map[string]any) string {
	var section map[string]any
	_ = json.Unmarshal([]byte(mitmSection(f.ca, true, strings.Split(f.include, ",")...)), &section)
	section["http_rewrite"] = rules
	section["capture"] = map[string]any{"enabled": true, "body": true}
	section["upstream"] = map[string]any{"skip_verify": []string{"other.example:" + strconv.Itoa(f.other.port)}}
	mitm, _ := json.Marshal(section)
	trusted, _ := json.Marshal(map[string]any{"certificate": []string{f.trusted}})
	return `{
  "log": {"disabled": true},
  "certificate": ` + string(trusted) + `,
  "dns": {"servers": [{"type": "hosts", "tag": "hosts", "predefined": {"other.example": "127.0.0.1", "example.com": "127.0.0.1"}}], "final": "hosts"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(f.proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}, {"action": "route-options", "override_address": "127.0.0.1"}], "final": "direct", "default_domain_resolver": "hosts"},
  "mitm": ` + string(mitm) + `
}`
}

func newBodyFixture(t *testing.T) *bodyFixture {
	if !h2relay.Supported {
		t.Skip("h2 relay needs Go 1.26")
	}
	f := &bodyFixture{t: t}
	// The test origins listen on loopback, which internal rewrites refuse by default.
	route.MITMInternalAllowLoopback = true
	t.Cleanup(func() { route.MITMInternalAllowLoopback = false })
	f.origin = newBodyOrigin(t, true)
	f.plain = newBodyOrigin(t, false)
	f.other = newSeenOrigin(t, true)
	f.otherHTTP = newSeenOrigin(t, false)
	f.trusted = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.origin.server.Certificate().Raw}))
	f.ca = writeMITMTestCA(t)
	f.proxyPort = freePort(t)
	f.include = "example.com:" + strconv.Itoa(f.origin.port)
	f.roots = x509.NewCertPool()
	require.True(t, f.roots.AppendCertsFromPEM(f.ca.certificatePEM))
	f.rules = func(extra map[string]any) map[string]any {
		rules := map[string]any{
			"max_body_size": "1KB",
			"body": []map[string]any{
				{"id": "resp-text", "pattern": `^https?://example\.com(:\d+)?/`, "scope": "response",
					"edits": []map[string]any{{"action": "replace-regex", "regex": "hello", "value": "bye"}}},
				{"id": "resp-stream", "pattern": `^https://example\.com/`, "scope": "response", "content_types": []string{"event-stream", "grpc"},
					"edits": []map[string]any{{"action": "replace-regex", "regex": "hello", "value": "bye"}}},
				{"id": "req-json", "pattern": `^https://example\.com/\w+/echo`, "scope": "request", "content_types": []string{"json"},
					"edits": []map[string]any{{"action": "json-set", "path": "$.user", "value": `"rewritten"`}}},
				{"id": "req-grpc", "pattern": `^https://example\.com/\w+/grpcup`, "scope": "request", "content_types": []string{"grpc"},
					"edits": []map[string]any{{"action": "replace-regex", "regex": "a", "value": "b"}}},
			},
			"url": []map[string]any{
				{"id": "to-https", "pattern": `^https://example\.com/(\w+)/via-https/(.*)`, "action": "header",
					"target": "https://other.example:" + strconv.Itoa(f.other.port) + "/in/$2"},
				{"id": "to-http", "pattern": `^https://example\.com/(\w+)/via-http/(.*)`, "action": "header",
					"target": "http://other.example:" + strconv.Itoa(f.otherHTTP.port) + "/in/$2"},
				{"id": "same", "pattern": `^https://example\.com/(\w+)/same/(.*)`, "action": "header",
					"target": "https://example.com/$1/moved/$2"},
				{"id": "dead", "pattern": `^https://example\.com/(\w+)/dead`, "action": "header",
					"target": "https://other.example:1/never"},
				{"id": "plain-hop", "pattern": `^http://example\.com:\d+/hop/(.*)`, "action": "header",
					"target": "http://other.example:" + strconv.Itoa(f.otherHTTP.port) + "/via/$1"},
				{"id": "plain-to-https", "pattern": `^http://example\.com:\d+/up/(.*)`, "action": "header",
					"target": "https://other.example:" + strconv.Itoa(f.other.port) + "/up/$1"},
			},
			"headers": []map[string]any{
				{"id": "mark", "pattern": `^https?://other\.example`, "scope": "request",
					"operations": []map[string]string{{"action": "add", "name": "X-Rule", "value": "seen"}}},
			},
		}
		for k, v := range extra {
			rules[k] = v
		}
		return rules
	}
	f.box = startRewriteBox(t, bodyBoxConfig(f, f.rules(nil)))
	return f
}

func (f *bodyFixture) client(h2 bool) *http.Client {
	client := rewriteClient(f.t, f.proxyPort, f.roots, "example.com")
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = h2
	transport.DisableCompression = true
	return client
}

func (f *bodyFixture) get(client *http.Client, prefix string, path string, header http.Header) (*http.Response, []byte) {
	f.t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+prefix+"/"+path, nil)
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

func TestMITMBodyRewriteEndToEnd(t *testing.T) {
	f := newBodyFixture(t)
	for _, tc := range []struct {
		prefix string
		h2     bool
		proto  string
	}{{"h1", false, "HTTP/1.1"}, {"h2", true, "HTTP/2.0"}} {
		t.Run(tc.prefix, func(t *testing.T) {
			client := f.client(tc.h2)
			get := func(path string, header http.Header) (*http.Response, []byte) {
				response, data := f.get(client, tc.prefix, path, header)
				require.Equal(t, tc.proto, response.Proto)
				return response, data
			}

			t.Run("content length", func(t *testing.T) {
				response, data := get("text", nil)
				require.Equal(t, "bye bye", string(data))
				require.EqualValues(t, 7, response.ContentLength)
				hit := f.box.find(t, "/"+tc.prefix+"/text").Rewrites
				require.Len(t, hit, 1)
				require.Equal(t, "body", hit[0].Kind)
				require.Equal(t, "edit", hit[0].Action)
				require.Equal(t, "resp-text", hit[0].Rule)
			})

			t.Run("gzip", func(t *testing.T) {
				response, data := get("gz", nil)
				require.Equal(t, "gzip", response.Header.Get("Content-Encoding"))
				require.Equal(t, strconv.Itoa(len(data)), response.Header.Get("Content-Length"))
				zr, err := gzip.NewReader(bytes.NewReader(data))
				require.NoError(t, err)
				plain, err := io.ReadAll(zr)
				require.NoError(t, err)
				require.Equal(t, "bye bye", string(plain))
			})

			t.Run("gzip decoded by a transparent client", func(t *testing.T) {
				transparent := f.client(tc.h2)
				transparent.Transport.(*http.Transport).DisableCompression = false
				_, data := f.get(transparent, tc.prefix, "gz", nil)
				require.Equal(t, "bye bye", string(data))
			})

			t.Run("brotli", func(t *testing.T) {
				response, data := get("br", nil)
				require.Equal(t, "br", response.Header.Get("Content-Encoding"))
				require.Equal(t, strconv.Itoa(len(data)), response.Header.Get("Content-Length"))
				decoded, err := body.Decode("br", bytes.NewReader(data), body.Limits{MaxOutput: 1 << 20})
				require.NoError(t, err)
				require.Equal(t, "bye bye", string(decoded))
			})

			t.Run("chunked response", func(t *testing.T) {
				response, data := get("chunked", nil)
				require.Equal(t, "bye bye", string(data))
				require.Equal(t, "7", response.Header.Get("Content-Length"))
				require.Empty(t, response.TransferEncoding)
			})

			t.Run("over the limit passes through", func(t *testing.T) {
				_, data := get("big", nil)
				require.Equal(t, strings.Repeat("a", 5000), string(data))
				hit := f.box.find(t, "/"+tc.prefix+"/big").Rewrites
				require.Len(t, hit, 1)
				require.Equal(t, "skipped", hit[0].Action)
				require.Equal(t, "size", hit[0].Target)
				_, data = get("bigchunk", nil)
				require.Equal(t, strings.Repeat("a", 5000), string(data))
				hit = f.box.find(t, "/"+tc.prefix+"/bigchunk").Rewrites
				require.Len(t, hit, 1)
				require.Equal(t, "size", hit[0].Target)
			})

			t.Run("event stream is not buffered", func(t *testing.T) {
				for _, name := range []string{"sse", "grpc"} {
					f.origin.release = make(chan struct{})
					request, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+tc.prefix+"/"+name, nil)
					request.Host = "example.com"
					start := time.Now()
					response, err := client.Do(request)
					require.NoError(t, err)
					first := make([]byte, 13)
					if name == "sse" {
						first = make([]byte, 15)
					}
					_, err = io.ReadFull(response.Body, first)
					require.NoError(t, err)
					require.Less(t, time.Since(start), 3*time.Second, name)
					require.Contains(t, string(first), "hello", "streams are not rewritten")
					close(f.origin.release)
					rest, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					require.Contains(t, string(rest), "hello")
					response.Body.Close()
					hit := f.box.find(t, "/"+tc.prefix+"/"+name).Rewrites
					require.NotEmpty(t, hit)
					require.Equal(t, "skipped", hit[0].Action)
					require.Equal(t, "stream", hit[0].Target)
				}
			})

			t.Run("grpc request stream is not buffered", func(t *testing.T) {
				reader, writer := io.Pipe()
				request, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+tc.prefix+"/grpcup", reader)
				request.Host = "example.com"
				request.Header.Set("Content-Type", "application/grpc")
				done := make(chan error, 1)
				go func() {
					response, err := client.Do(request)
					if err == nil {
						response.Body.Close()
					}
					done <- err
				}()
				writer.Write([]byte("aaaaa"))
				select {
				case got := <-f.origin.grpcIn:
					require.Equal(t, "aaaaa", got)
				case <-time.After(5 * time.Second):
					t.Fatal("first request message held back")
				}
				writer.Close()
				require.NoError(t, <-done)
			})

			t.Run("json request body", func(t *testing.T) {
				payload := `{"user":"u","n":12345678901234567890,"f":1.50}`
				for _, chunked := range []bool{false, true} {
					var reader io.Reader = strings.NewReader(payload)
					if chunked {
						reader = io.MultiReader(strings.NewReader(payload[:10]), strings.NewReader(payload[10:]))
					}
					request, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1:"+strconv.Itoa(f.origin.port)+"/"+tc.prefix+"/echo", reader)
					request.Host = "example.com"
					request.Header.Set("Content-Type", "application/json")
					response, err := client.Do(request)
					require.NoError(t, err)
					data, _ := io.ReadAll(response.Body)
					response.Body.Close()
					want := `{"user":"rewritten","n":12345678901234567890,"f":1.50}`
					require.Equal(t, want, string(data))
					require.Equal(t, strconv.Itoa(len(want)), response.Header.Get("X-Req-Length"), "origin sees the corrected length")
					require.Empty(t, response.Header.Get("X-Req-Encoding"), "no chunked framing next to the length")
				}
			})

			t.Run("internal rewrite", func(t *testing.T) {
				before := f.origin.hits.Load()
				_, data := get("via-https/a/b?q=1", nil)
				sni := fmt.Sprintf("sni=other.example proto=HTTP/1.1 host=other.example:%d uri=/in/a/b?q=1 x=seen", f.other.port)
				require.Equal(t, sni, string(data))
				_, data = get("via-http/c", nil)
				require.Equal(t, fmt.Sprintf("sni=- proto=HTTP/1.1 host=other.example:%d uri=/in/c x=seen", f.otherHTTP.port), string(data))
				_, data = get("same/p", nil)
				require.Equal(t, "origin example.com/"+tc.prefix+"/moved/p", string(data))
				require.Equal(t, before+1, f.origin.hits.Load(), "only the same-origin rewrite reaches the original origin")
				record := f.box.find(t, "/in/a/b?q=1")
				require.Equal(t, "url", record.Rewrites[0].Kind)
				require.Equal(t, "header", record.Rewrites[0].Action)
				require.Equal(t, fmt.Sprintf("other.example:%d", f.other.port), record.Authority)
				// The connection keeps working for ordinary requests afterwards.
				_, data = get("after", nil)
				require.Equal(t, "origin example.com/"+tc.prefix+"/after", string(data))
			})

			t.Run("internal rewrite failure", func(t *testing.T) {
				before := f.origin.hits.Load()
				response, _ := get("dead", nil)
				require.Equal(t, http.StatusBadGateway, response.StatusCode)
				require.Equal(t, before, f.origin.hits.Load(), "never falls back to the original host")
			})
		})
	}
}

func TestMITMBodyRewritePlainHTTP(t *testing.T) {
	f := newBodyFixture(t)
	client := rewriteClient(t, f.proxyPort, f.roots, "")
	host := "example.com:" + strconv.Itoa(f.plain.port)
	fetchPlain := func(path string) (*http.Response, string) {
		request, _ := http.NewRequest(http.MethodGet, "http://"+host+path, nil)
		request.Host = host
		response, err := client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response, string(data)
	}
	response, data := fetchPlain("/p/text")
	require.Equal(t, "bye bye", data)
	require.EqualValues(t, 7, response.ContentLength)
	_, data = fetchPlain("/hop/x")
	require.Equal(t, fmt.Sprintf("sni=- proto=HTTP/1.1 host=other.example:%d uri=/via/x x=seen", f.otherHTTP.port), data)
	_, data = fetchPlain("/up/y")
	require.Equal(t, fmt.Sprintf("sni=other.example proto=HTTP/1.1 host=other.example:%d uri=/up/y x=seen", f.other.port), data)
	_, data = fetchPlain("/p/after")
	require.Equal(t, "origin "+host+"/p/after", data)
}

func TestMITMBodyRewriteHotUpdate(t *testing.T) {
	f := newBodyFixture(t)
	client := f.client(false)
	request := func() (string, bool) {
		response, data := f.get(client, "h1", "text", nil)
		_ = response
		return string(data), true
	}
	got, _ := request()
	require.Equal(t, "bye bye", got)
	next := f.rules(map[string]any{"body": []map[string]any{
		{"id": "resp-text", "pattern": `^https?://example\.com(:\d+)?/`, "scope": "response",
			"edits": []map[string]any{{"action": "replace-regex", "regex": "hello", "value": "ciao"}}},
	}})
	result, err := applyLive(t, f.box.ctx, bodyBoxConfig(f, next))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	got, _ = request()
	require.Equal(t, "ciao ciao", got)

	// A set that does not compile changes nothing.
	broken := f.rules(map[string]any{"body": []map[string]any{
		{"id": "bad", "pattern": `^https://example\.com/`, "scope": "response",
			"edits": []map[string]any{{"action": "replace-regex", "regex": "(", "value": "x"}}},
	}})
	_, err = applyLive(t, f.box.ctx, bodyBoxConfig(f, broken))
	require.Error(t, err)
	got, _ = request()
	require.Equal(t, "ciao ciao", got)

	result, err = applyLive(t, f.box.ctx, bodyBoxConfig(f, map[string]any{}))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	got, _ = request()
	require.Equal(t, "hello hello", got)
}

func TestMITMInternalRewriteRefusesLocalResolution(t *testing.T) {
	f := newBodyFixture(t)
	route.MITMInternalAllowLoopback = false
	client := f.client(false)
	response, _ := f.get(client, "h1", "via-http/c", nil)
	require.Equal(t, http.StatusBadGateway, response.StatusCode)
	require.Zero(t, f.otherHTTP.hits.Load(), "a name that resolves to loopback must not be reached")
}
