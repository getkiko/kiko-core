package box_test

// Soak harness for the MITM relay. It is skipped unless KIKO_SOAK_ROLE is set. Three
// processes of the same test binary run the roles origin, proxy and load, so the RSS of the
// proxy process excludes the load generator and the origin. scripts/mitm-soak.sh starts them.
//
//	KIKO_SOAK_DIR       shared directory (ports, certificates, CSV files)
//	KIKO_SOAK_DURATION  how long proxy and load run (default 10m)
//	KIKO_SOAK_INTERVAL  sampling period (default 30s)
//	KIKO_SOAK_CONC      load workers (default 100)
//	KIKO_SOAK_THINK     longest think time between a worker's requests (default 100ms)
//	KIKO_SOAK_SKIPVERIFY  skip upstream certificate verification (macOS SecTrust leak A/B)

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/authority"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/route/mitm"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/coder/websocket"
)

func soakEnvDuration(name string, fallback time.Duration) time.Duration {
	if value := os.Getenv(name); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return fallback
}

func soakEnvInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return value
	}
	return fallback
}

func soakWaitFile(path string, limit time.Duration) ([]byte, error) {
	deadline := time.Now().Add(limit)
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for %s", path)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func soakWriteAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func TestMITMSoak(t *testing.T) {
	role := os.Getenv("KIKO_SOAK_ROLE")
	if role == "" {
		t.Skip("set KIKO_SOAK_ROLE to run the soak harness")
	}
	dir := os.Getenv("KIKO_SOAK_DIR")
	if dir == "" {
		t.Fatal("KIKO_SOAK_DIR is required")
	}
	switch role {
	case "origin":
		soakOrigin(t, dir)
	case "proxy":
		soakProxy(t, dir)
	case "load":
		soakLoad(t, dir)
	default:
		t.Fatalf("unknown role %q", role)
	}
}

// ---- origin ----

func soakOriginHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok hello hello")
	})
	jsonBody := func(pad int) []byte {
		out, _ := json.Marshal(map[string]any{"ads": []int{1, 2, 3}, "keep": true, "pad": strings.Repeat("p", pad)})
		return out
	}
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonBody(rand.Intn(4096)))
	})
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		var packed bytes.Buffer
		zw := gzip.NewWriter(&packed)
		_, _ = zw.Write(jsonBody(rand.Intn(64 << 10)))
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(packed.Bytes())
	})
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "X-Sum")
		flusher := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			_, _ = io.WriteString(w, strings.Repeat("hello ", 1+rand.Intn(2000)))
			flusher.Flush()
		}
		w.Header().Set("X-Sum", "5")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		n = min(max(n, 0), 8<<20)
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Query().Get("chunked") == "" {
			w.Header().Set("Content-Length", strconv.Itoa(n))
		}
		buf := bytes.Repeat([]byte("0123456789abcdef"), 4096)
		for n > 0 {
			k := min(n, len(buf))
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(map[string]any{"length": len(data), "body": string(data[:min(len(data), 256)])})
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/hc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hc origin")
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "data: hello %d\n\n", i)
			flusher.Flush()
			time.Sleep(30 * time.Millisecond)
		}
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 100; i++ {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		conn.SetReadLimit(4 << 20)
		defer conn.CloseNow()
		for {
			typ, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err = conn.Write(r.Context(), typ, data); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello from "+r.URL.Path)
	})
	return mux
}

func soakOrigin(t *testing.T, dir string) {
	secure := httptest.NewUnstartedServer(soakOriginHandler())
	secure.Config.ErrorLog = log.New(io.Discard, "", 0)
	secure.EnableHTTP2 = true
	secure.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	secure.StartTLS()
	defer secure.Close()
	plain := httptest.NewUnstartedServer(soakOriginHandler())
	plain.Config.ErrorLog = log.New(io.Discard, "", 0)
	plain.Start()
	defer plain.Close()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw})
	for name, data := range map[string][]byte{
		"origin.pem":  pemBytes,
		"plain.port":  []byte(strconv.Itoa(plain.Listener.Addr().(*net.TCPAddr).Port)),
		"origin.port": []byte(strconv.Itoa(secure.Listener.Addr().(*net.TCPAddr).Port)),
	} {
		if err := soakWriteAtomic(filepath.Join(dir, name), data); err != nil {
			t.Fatal(err)
		}
	}
	// Run until the proxy is done.
	for {
		if _, err := os.Stat(filepath.Join(dir, "load.done")); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}

// ---- proxy ----

var soakScripts = map[string]string{
	"resp.js": `
var h = $response.headers;
h['X-Resp-Script'] = 'ok';
var b = JSON.parse($response.body);
delete b.ads;
b.status = $response.status;
$done({headers: h, body: JSON.stringify(b)});`,
	"req.js": `
var h = $request.headers;
h['X-Script'] = 'hello';
var b = {};
try { b = JSON.parse($request.body || '{}'); } catch (e) {}
b.added = 'by-script';
$done({headers: h, body: JSON.stringify(b)});`,
	"hc.js": `
$httpClient.get({url: 'http://rebind.test:%PLAIN%/hc', timeout: 5}, function (err, resp, data) {
  $persistentStore.write(String((parseInt($persistentStore.read('n') || '0', 10) + 1) % 1000), 'n');
  $done({response: {status: 200, headers: {'Content-Type': 'text/plain'}, body: err ? 'err ' + err : 'hc ' + data}});
});`,
	"async.js": `
setTimeout(function () { $done({headers: Object.assign($request.headers, {'X-Async': 'done'})}); }, 20);`,
	"burn.js": `
var a = []; for (var i = 0; i < 20000; i++) a.push({i: i, s: 'x' + i});
$done({headers: Object.assign($request.headers, {'X-Burn': String(a.length)})});`,
}

func soakProxy(t *testing.T, dir string) {
	duration := soakEnvDuration("KIKO_SOAK_DURATION", 10*time.Minute)
	interval := soakEnvDuration("KIKO_SOAK_INTERVAL", 30*time.Second)
	originPEM, err := soakWaitFile(filepath.Join(dir, "origin.pem"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	originPort, _ := soakWaitFile(filepath.Join(dir, "origin.port"), time.Minute)
	plainPort, _ := soakWaitFile(filepath.Join(dir, "plain.port"), time.Minute)
	certificatePEM, keyPEM, err := authority.Generate("Kiko Soak CA", 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"ca.pem": certificatePEM, "ca.key": keyPEM} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range soakScripts {
		content = strings.ReplaceAll(content, "%PLAIN%", string(plainPort))
		if err = os.WriteFile(filepath.Join(dir, "scripts", name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	hostname := "example.com:" + string(originPort)
	section := map[string]any{
		"enabled": true,
		"certificate": map[string]any{
			"source":           "file",
			"certificate_path": filepath.Join(dir, "ca.pem"),
			"key_path":         filepath.Join(dir, "ca.key"),
		},
		"hostnames": map[string]any{"include": []string{hostname}},
		"capture":   map[string]any{"enabled": true, "body": true},
		"http_rewrite": map[string]any{
			"max_body_size": "512KB",
			"url": []map[string]any{
				{"id": "r200", "pattern": `^https?://example\.com(:\d+)?/reject`, "action": "reject-200"},
				{"id": "found", "pattern": `^https://example\.com(:\d+)?/old/(\w+)`, "action": "302", "target": "https://example.com/new/$2"},
			},
			"map_local": []map[string]any{
				{"id": "mock", "pattern": `^https?://example\.com(:\d+)?/mock$`, "status": 201, "body": "hello"},
			},
			"headers": []map[string]any{
				{"id": "resp-h", "pattern": `^https?://example\.com(:\d+)?/`, "scope": "response", "operations": []map[string]string{{"action": "add", "name": "X-Soak", "value": "1"}}},
				{"id": "req-h", "pattern": `^https?://example\.com(:\d+)?/`, "scope": "request", "operations": []map[string]string{{"action": "add", "name": "X-Soak-Req", "value": "1"}}},
			},
			"body": []map[string]any{
				{"id": "text", "pattern": `^https?://example\.com(:\d+)?/(small|chunked|sse)`, "scope": "response",
					"edits": []map[string]any{{"action": "replace-regex", "regex": "hello", "value": "bye"}}},
				{"id": "json", "pattern": `^https?://example\.com(:\d+)?/(json|gz)`, "scope": "response", "content_types": []string{"json"},
					"edits": []map[string]any{{"action": "json-set", "path": "$.keep", "value": "false"}, {"action": "json-append", "path": "$.ads", "value": "4"}}},
			},
		},
	}
	if os.Getenv("KIKO_SOAK_SKIPVERIFY") != "" {
		// A/B for the macOS SecTrust leak: no upstream verification, no system trust calls.
		section["upstream"] = map[string]any{"skip_verify": []string{hostname}}
	}
	mitmJSON, _ := json.Marshal(section)
	trusted, _ := json.Marshal(map[string]any{"certificate": []string{string(originPEM)}})
	scripts, _ := json.Marshal([]map[string]any{
		{"tag": "resp", "type": "http-response", "pattern": `^https://example\.com(:\d+)?/(json|gz)$`, "source_path": "scripts/resp.js", "requires_body": true},
		{"tag": "req", "type": "http-request", "pattern": `^https://example\.com(:\d+)?/echo`, "source_path": "scripts/req.js", "requires_body": true},
		{"tag": "hc", "type": "http-request", "pattern": `^https://example\.com(:\d+)?/hc$`, "source_path": "scripts/hc.js"},
		{"tag": "async", "type": "http-request", "pattern": `^https://example\.com(:\d+)?/async`, "source_path": "scripts/async.js"},
		{"tag": "burn", "type": "http-request", "pattern": `^https://example\.com(:\d+)?/burn`, "source_path": "scripts/burn.js"},
	})
	config := `{
  "log": {"disabled": true},
  "certificate": ` + string(trusted) + `,
  "dns": {"servers": [{"type": "hosts", "tag": "hosts", "predefined": {"rebind.test": "127.0.0.1", "example.com": "127.0.0.1"}}], "final": "hosts"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(proxyPort) + `}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}, {"action": "route-options", "override_address": "127.0.0.1"}], "final": "direct", "default_domain_resolver": "hosts"},
  "mitm": ` + string(mitmJSON) + `,
  "scripts": ` + string(scripts) + `
}`
	route.MITMInternalAllowLoopback = true
	mitm.SetScriptHTTPAllowLocal(true)
	ctx := include.Context(context.Background())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	engine := service.FromContext[adapter.MITMEngine](ctx)
	captureManager := engine.(adapter.MITMCaptureProvider).Capture()
	if err = soakWriteAtomic(filepath.Join(dir, "proxy.port"), []byte(strconv.Itoa(proxyPort))); err != nil {
		t.Fatal(err)
	}

	csv, err := os.Create(filepath.Join(dir, "proxy.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer csv.Close()
	_, _ = fmt.Fprintln(csv, "elapsed_s,rss_kb,goroutines,heap_alloc_b,heap_inuse_b,sys_b,fds,num_gc,capture_records,capture_bytes,leaf_cache,heap_idle_b,heap_released_b,stack_inuse_b,mspan_b,gc_sys_b,other_sys_b")
	start := time.Now()
	sample := func() {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		stats := captureManager.Stats()
		_, _ = fmt.Fprintf(csv, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", int(time.Since(start).Seconds()), soakRSS(), runtime.NumGoroutine(),
			ms.HeapAlloc, ms.HeapInuse, ms.Sys, soakFDs(), ms.NumGC, stats.Records, stats.Bytes, engine.Status().LeafCacheSize,
			ms.HeapIdle, ms.HeapReleased, ms.StackInuse, ms.MSpanInuse, ms.GCSys, ms.OtherSys)
		_ = csv.Sync()
	}
	dump := func(name string) {
		if file, err := os.Create(filepath.Join(dir, name)); err == nil {
			_ = pprof.Lookup("goroutine").WriteTo(file, 1)
			file.Close()
		}
	}
	sample()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.After(duration)
	warm := time.After(min(10*time.Minute, duration/4))
loop:
	for {
		select {
		case <-ticker.C:
			sample()
		case <-warm:
			dump("goroutines-warm.txt")
		case <-deadline:
			break loop
		}
	}
	sample()
	dump("goroutines-end.txt")
	if file, err := os.Create(filepath.Join(dir, "heap-end.pprof")); err == nil {
		_ = pprof.Lookup("heap").WriteTo(file, 0)
		file.Close()
	}
	// Wait for the load generator to stop, then see what remains.
	for i := 0; i < 120; i++ {
		if _, err := os.Stat(filepath.Join(dir, "load.done")); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	time.Sleep(20 * time.Second)
	runtime.GC()
	sample()
	dump("goroutines-idle.txt")
	_ = instance.Close()
	time.Sleep(5 * time.Second)
	runtime.GC()
	sample()
	dump("goroutines-closed.txt")
	_ = soakWriteAtomic(filepath.Join(dir, "proxy.done"), []byte("1"))
}

func soakRSS() int64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return -1
	}
	value, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return value
}

func soakFDs() int {
	for _, path := range []string{"/proc/self/fd", "/dev/fd"} {
		if entries, err := os.ReadDir(path); err == nil {
			return len(entries) - 1
		}
	}
	return -1
}

// ---- load ----

type soakCounters struct {
	ok, failed, wsSessions, aborted atomic.Int64
	bytes                           atomic.Int64
	errors                          sync.Map // message -> *atomic.Int64
}

func (c *soakCounters) fail(op string, err error) {
	c.failed.Add(1)
	key := op + ": " + err.Error()
	if len(key) > 160 {
		key = key[:160]
	}
	counter, _ := c.errors.LoadOrStore(key, new(atomic.Int64))
	counter.(*atomic.Int64).Add(1)
}

func soakLoad(t *testing.T, dir string) {
	duration := soakEnvDuration("KIKO_SOAK_DURATION", 10*time.Minute)
	interval := soakEnvDuration("KIKO_SOAK_INTERVAL", 30*time.Second)
	workers := soakEnvInt("KIKO_SOAK_CONC", 100)
	think := soakEnvDuration("KIKO_SOAK_THINK", 100*time.Millisecond)
	proxyPort, err := soakWaitFile(filepath.Join(dir, "proxy.port"), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	originPort, _ := soakWaitFile(filepath.Join(dir, "origin.port"), time.Minute)
	caPEM, _ := soakWaitFile(filepath.Join(dir, "ca.pem"), time.Minute)
	originPEM, _ := soakWaitFile(filepath.Join(dir, "origin.pem"), time.Minute)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	roots.AppendCertsFromPEM(originPEM)
	proxyURL, _ := url.Parse("http://127.0.0.1:" + string(proxyPort))
	newTransport := func(h2 bool) *http.Transport {
		tr := &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			ForceAttemptHTTP2:   h2,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     20 * time.Second,
			TLSClientConfig:     &tls.Config{RootCAs: roots, ServerName: "example.com"},
		}
		if !h2 {
			tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		return tr
	}
	base := "https://example.com:" + string(originPort)
	var counters soakCounters
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var transportMu sync.RWMutex
	h1Transport, h2Transport := newTransport(false), newTransport(true)

	pick := func(r *rand.Rand, h2 bool) (method, path string, body []byte, validate func([]byte) error) {
		switch n := r.Intn(100); {
		case n < 18:
			return "GET", "/small", nil, func(b []byte) error {
				if !strings.Contains(string(b), "bye") {
					return fmt.Errorf("small body %q", b)
				}
				return nil
			}
		case n < 33:
			return "GET", "/json", nil, func(b []byte) error {
				var v map[string]any
				if err := json.Unmarshal(b, &v); err != nil {
					return err
				}
				if _, ok := v["ads"]; ok {
					return fmt.Errorf("ads not removed")
				}
				return nil
			}
		case n < 45:
			return "GET", "/gz", nil, func(b []byte) error {
				zr, err := gzip.NewReader(bytes.NewReader(b))
				if err != nil {
					return err
				}
				plain, err := io.ReadAll(zr)
				if err != nil {
					return err
				}
				return json.Unmarshal(plain, &map[string]any{})
			}
		case n < 53:
			return "GET", "/chunked", nil, nil
		case n < 63:
			size := []int{1 << 10, 64 << 10, 256 << 10, 1 << 20}[r.Intn(4)]
			chunked := ""
			if r.Intn(2) == 0 {
				chunked = "&chunked=1"
			}
			return "GET", fmt.Sprintf("/big?n=%d%s", size, chunked), nil, nil
		case n < 72:
			body := bytes.Repeat([]byte("a"), r.Intn(8<<10))
			payload, _ := json.Marshal(map[string]string{"user": string(body)})
			return "POST", "/echo", payload, nil
		case n < 76:
			return "POST", "/echo", bytes.Repeat([]byte("z"), 64<<10+r.Intn(1<<20)), nil
		case n < 80:
			return "GET", "/hc", nil, func(b []byte) error {
				if !strings.HasPrefix(string(b), "hc ") {
					return fmt.Errorf("hc body %q", b)
				}
				return nil
			}
		case n < 84:
			return "GET", "/sse", nil, nil
		case n < 87:
			return "GET", "/async", nil, nil
		case n < 88:
			return "GET", "/burn", nil, nil
		case n < 91:
			return "GET", "/mock", nil, nil
		case n < 94:
			return "GET", fmt.Sprintf("/reject/%d", r.Intn(100)), nil, nil
		case n < 96:
			return "GET", "/old/x", nil, nil
		default:
			return "GET", fmt.Sprintf("/other/%d", r.Intn(1000)), nil, nil
		}
	}

	httpWorker := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(int64(id) * 7919))
		h2 := id%2 == 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			transportMu.RLock()
			transport := h1Transport
			if h2 {
				transport = h2Transport
			}
			transportMu.RUnlock()
			client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			method, path, body, validate := pick(r, h2)
			ctx, cancel := context.WithCancel(context.Background())
			var reader io.Reader
			if body != nil {
				reader = bytes.NewReader(body)
			}
			request, _ := http.NewRequestWithContext(ctx, method, base+path, reader)
			response, err := client.Do(request)
			if err != nil {
				counters.fail(path[:min(len(path), 6)], err)
			} else {
				if r.Intn(40) == 0 && strings.HasPrefix(path, "/big") {
					// Abort mid-body.
					_, _ = io.CopyN(io.Discard, response.Body, 1024)
					cancel()
					response.Body.Close()
					counters.aborted.Add(1)
				} else {
					data, readErr := io.ReadAll(response.Body)
					response.Body.Close()
					counters.bytes.Add(int64(len(data)))
					switch {
					case readErr != nil:
						counters.fail(path[:min(len(path), 6)], readErr)
					case response.StatusCode >= 500:
						counters.fail(path[:min(len(path), 6)], fmt.Errorf("status %d", response.StatusCode))
					case validate != nil && response.StatusCode == 200:
						if verr := validate(data); verr != nil {
							counters.fail(path[:min(len(path), 6)], verr)
						} else {
							counters.ok.Add(1)
						}
					default:
						counters.ok.Add(1)
					}
				}
			}
			cancel()
			if r.Intn(200) == 0 {
				transport.CloseIdleConnections()
			}
			time.Sleep(time.Duration(r.Int63n(int64(think) + 1)))
		}
	}
	wsWorker := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(int64(id) * 104729))
		client := &http.Client{Transport: newTransport(false)}
		for {
			select {
			case <-stop:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			conn, _, err := websocket.Dial(ctx, "wss://example.com:"+string(originPort)+"/ws", &websocket.DialOptions{HTTPClient: client})
			if err != nil {
				counters.fail("ws-dial", err)
				cancel()
				time.Sleep(time.Second)
				continue
			}
			conn.SetReadLimit(4 << 20)
			messages := 1 + r.Intn(20)
			for i := 0; i < messages; i++ {
				payload := bytes.Repeat([]byte{byte('a' + i%26)}, []int{10, 1000, 30 << 10, 100 << 10}[r.Intn(4)])
				kind := websocket.MessageText
				if r.Intn(2) == 0 {
					kind = websocket.MessageBinary
				}
				if err = conn.Write(ctx, kind, payload); err != nil {
					counters.fail("ws-write", err)
					break
				}
				_, echo, readErr := conn.Read(ctx)
				if readErr != nil || len(echo) != len(payload) {
					counters.fail("ws-read", fmt.Errorf("%v len %d/%d", readErr, len(echo), len(payload)))
					break
				}
				counters.bytes.Add(int64(len(echo)))
				time.Sleep(time.Duration(r.Int63n(int64(think) + 1)))
			}
			if r.Intn(4) == 0 {
				_ = conn.CloseNow()
			} else {
				_ = conn.Close(websocket.StatusNormalClosure, "bye")
			}
			counters.wsSessions.Add(1)
			cancel()
			client.Transport.(*http.Transport).CloseIdleConnections()
		}
	}
	wsCount := max(workers/10, 3)
	for id := 0; id < workers; id++ {
		wg.Add(1)
		go httpWorker(id)
	}
	for id := 0; id < wsCount; id++ {
		wg.Add(1)
		go wsWorker(id)
	}

	csv, err := os.Create(filepath.Join(dir, "load.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer csv.Close()
	_, _ = fmt.Fprintln(csv, "elapsed_s,ok,failed,ws_sessions,aborted,mib,load_rss_kb")
	start := time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	end := time.After(duration)
	// Replace the transports now and then, so that idle connections of an old generation close
	// and new ones are dialed.
	rotate := time.NewTicker(5 * time.Minute)
	defer rotate.Stop()
	row := func() {
		_, _ = fmt.Fprintf(csv, "%d,%d,%d,%d,%d,%d,%d\n", int(time.Since(start).Seconds()), counters.ok.Load(), counters.failed.Load(),
			counters.wsSessions.Load(), counters.aborted.Load(), counters.bytes.Load()>>20, soakRSS())
		_ = csv.Sync()
	}
loop:
	for {
		select {
		case <-ticker.C:
			row()
		case <-rotate.C:
			transportMu.Lock()
			oldH1, oldH2 := h1Transport, h2Transport
			h1Transport, h2Transport = newTransport(false), newTransport(true)
			transportMu.Unlock()
			oldH1.CloseIdleConnections()
			oldH2.CloseIdleConnections()
		case <-end:
			break loop
		}
	}
	close(stop)
	wg.Wait()
	row()
	var summary strings.Builder
	fmt.Fprintf(&summary, "ok=%d failed=%d ws=%d aborted=%d\n", counters.ok.Load(), counters.failed.Load(), counters.wsSessions.Load(), counters.aborted.Load())
	counters.errors.Range(func(key, value any) bool {
		fmt.Fprintf(&summary, "%6d  %s\n", value.(*atomic.Int64).Load(), key)
		return true
	})
	_ = os.WriteFile(filepath.Join(dir, "load.summary.txt"), []byte(summary.String()), 0o644)
	_ = soakWriteAtomic(filepath.Join(dir, "load.done"), []byte("1"))
}
