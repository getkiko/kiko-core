package mitm

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func rewriteEngineOptions(ca testCA, enabled bool, rewrite *option.MITMHTTPRewriteOptions) *option.MITMOptions {
	options := fileOptions(ca, enabled, []string{"example.com"}, nil)
	options.HTTPRewrite = rewrite
	return options
}

func httpMetadata(host string, destination string) *adapter.InboundContext {
	metadata := tlsMetadata(host, destination)
	metadata.Protocol = C.ProtocolHTTP
	return metadata
}

func rejectDict(pattern string) *option.MITMHTTPRewriteOptions {
	return &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{{ID: "rule", Pattern: pattern, Action: "reject-dict"}}}
}

func TestDecidePlain(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, rejectDict(`^http://a\.test/`)))
	state := engine.Decide(httpMetadata("a.test", "10.0.0.1:80"))
	require.NotNil(t, state)
	require.Equal(t, adapter.MITMStatusPlain, state.Status())
	require.Equal(t, "plain", state.Status().String())
	require.True(t, state.Serves())
	require.False(t, state.Pending())
	status, reason := engine.Explain(httpMetadata("a.test", "10.0.0.1:80"))
	require.Equal(t, "plain", status)
	require.Empty(t, reason)

	// Hostname lists do not apply: the rule patterns select.
	require.NotNil(t, engine.Decide(httpMetadata("other.test", "10.0.0.1:80")))

	internal := httpMetadata("a.test", "10.0.0.1:80")
	internal.Internal = true
	require.Nil(t, engine.Decide(internal))
	status, reason = engine.Explain(internal)
	require.Equal(t, "skipped", status)
	require.Equal(t, ReasonInternal, reason)

	skipped := httpMetadata("a.test", "10.0.0.1:80")
	skipped.MITMOverride = C.MITMOverrideSkip
	require.Nil(t, engine.Decide(skipped))

	handled := httpMetadata("a.test", "10.0.0.1:80")
	handled.OutboundChain = []adapter.Outbound{&handlerOutbound{}}
	require.Nil(t, engine.Decide(handled))

	// TLS decisions are unchanged.
	require.Equal(t, adapter.MITMStatusPending, engine.Decide(tlsMetadata("example.com", "10.0.0.1:443")).Status())
}

func TestDecidePlainRequiresApplicableRule(t *testing.T) {
	ca := writeTestCA(t)
	for name, rewrite := range map[string]*option.MITMHTTPRewriteOptions{
		"none":       nil,
		"https only": rejectDict(`^https://a\.test/`),
	} {
		engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, rewrite))
		require.Nil(t, engine.Decide(httpMetadata("a.test", "10.0.0.1:80")), name)
		status, reason := engine.Explain(httpMetadata("a.test", "10.0.0.1:80"))
		require.Equal(t, "skipped", status, name)
		require.Equal(t, ReasonNotTLS, reason, name)
	}
	disabled := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, false, rejectDict(`.`)))
	require.Nil(t, disabled.Decide(httpMetadata("a.test", "10.0.0.1:80")))

	scoped := rewriteEngineOptions(ca, true, rejectDict(`.`))
	scoped.Sources = []string{"192.168.1.0/24"}
	engine := newTestEngine(t, context.Background(), scoped)
	outside := httpMetadata("a.test", "10.0.0.1:80")
	outside.Source = M.ParseSocksaddr("10.9.9.9:5000")
	require.Nil(t, engine.Decide(outside))
	inside := httpMetadata("a.test", "10.0.0.1:80")
	inside.Source = M.ParseSocksaddr("192.168.1.7:5000")
	require.NotNil(t, engine.Decide(inside))
}

func TestDecideMissWithRulesDoesNotAllocate(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, rejectDict(`^https://a\.test/`)))
	plain := httpMetadata("a.test", "10.0.0.1:80")
	other := tlsMetadata("www.example.org", "10.0.0.1:443")
	allocations := testing.AllocsPerRun(1000, func() {
		if engine.Decide(plain) != nil || engine.Decide(other) != nil {
			t.Fatal("unexpected match")
		}
	})
	require.Zero(t, allocations)
}

func TestReloadRewriteFailureKeepsOldRules(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, rejectDict(`^http://a\.test/`)))
	_, err := engine.Reload(rewriteEngineOptions(ca, true, rejectDict(`([`)))
	require.Error(t, err)
	_, err = engine.Reload(rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `.`, Action: "unknown"}},
	}))
	require.Error(t, err)
	require.NotNil(t, engine.Decide(httpMetadata("a.test", "10.0.0.1:80")))
	require.False(t, engine.rewriteSet().Empty())

	commit, err := engine.Reload(rewriteEngineOptions(ca, true, nil))
	require.NoError(t, err)
	require.False(t, engine.rewriteSet().Empty(), "applied before commit")
	commit()
	require.True(t, engine.rewriteSet().Empty())
	require.Nil(t, engine.Decide(httpMetadata("a.test", "10.0.0.1:80")))
}

func TestRejectHost(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{
		{ID: "host", Pattern: `^https://ads\.example\.com/`, Action: "reject"},
		{ID: "path", Pattern: `^https://api\.example\.com/ads/`, Action: "reject"},
		{ID: "soft", Pattern: `^https://soft\.example\.com/`, Action: "reject-200"},
	}}))
	id, ok := engine.RejectHost(tlsMetadata("ads.example.com", "10.0.0.1:443"))
	require.True(t, ok)
	require.Equal(t, "host", id)
	id, ok = engine.RejectHost(tlsMetadata("ADS.example.com.", "10.0.0.1:443"))
	require.True(t, ok, "normalized host")
	require.Equal(t, "host", id)
	for _, host := range []string{"api.example.com", "soft.example.com", "www.example.com", ""} {
		_, ok = engine.RejectHost(tlsMetadata(host, "10.0.0.1:443"))
		require.False(t, ok, host)
	}
	internal := tlsMetadata("ads.example.com", "10.0.0.1:443")
	internal.Internal = true
	_, ok = engine.RejectHost(internal)
	require.False(t, ok)
	if !raceEnabled {
		miss := tlsMetadata("www.example.com", "10.0.0.1:443")
		require.Zero(t, testing.AllocsPerRun(1000, func() { engine.RejectHost(miss) }))
	}

	disabled := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, false, &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `^https://ads\.example\.com/`, Action: "reject"}},
	}))
	_, ok = disabled.RejectHost(tlsMetadata("ads.example.com", "10.0.0.1:443"))
	require.False(t, ok)
}

type plainSession struct {
	client net.Conn
	state  *adapter.MITMState
	done   chan struct{}
}

func startPlainSession(t *testing.T, engine *Engine, upstreamAddress string) *plainSession {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	serverSide, err := listener.Accept()
	require.NoError(t, err)
	upstream, err := net.Dial("tcp", upstreamAddress)
	require.NoError(t, err)
	metadata := httpMetadata("example.com", "127.0.0.1:80")
	metadata.MITM = engine.Decide(metadata)
	require.NotNil(t, metadata.MITM)
	s := &plainSession{client: client, state: metadata.MITM, done: make(chan struct{})}
	go func() {
		engine.Serve(context.Background(), serverSide, upstream, testRedial(upstreamAddress, nil), metadata, N.CloseHandlerFunc(func(error) {}))
		close(s.done)
	}()
	return s
}

func TestServePlainRewritesAndHotSwaps(t *testing.T) {
	var reached int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.Header().Set("X-Seen", r.Header.Get("X-Kiko"))
		_, _ = io.WriteString(w, "upstream "+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{ID: "u", Pattern: `^http://example\.com/blocked`, Action: "reject-dict"}},
		Headers: []option.MITMHeaderRewriteRule{{ID: "h", Pattern: `^http://example\.com/`, Scope: "request",
			Operations: []option.MITMHeaderRewriteEdit{{Action: "add", Name: "X-Kiko", Value: "1"}}}},
	}))
	s := startPlainSession(t, engine, upstream.Listener.Addr().String())
	reader := bufio.NewReader(s.client)
	get := func(path string) (*http.Response, string) {
		_, err := io.WriteString(s.client, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		return response, string(body)
	}
	response, body := get("/blocked")
	require.Equal(t, "{}", body)
	require.Equal(t, "application/json", response.Header.Get("Content-Type"))
	response, body = get("/free")
	require.Equal(t, "upstream /free", body)
	require.Equal(t, "1", response.Header.Get("X-Seen"))
	require.Equal(t, 1, reached)
	require.Equal(t, int64(2), s.state.Requests())
	require.Equal(t, adapter.MITMStatusPlain, s.state.Status())

	// A reload applies to the connection in progress.
	commit, err := engine.Reload(rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{Pattern: `^http://example\.com/free`, Action: "reject-array"}},
	}))
	require.NoError(t, err)
	commit()
	_, body = get("/free")
	require.Equal(t, "[]", body)
	_, body = get("/blocked")
	require.Equal(t, "upstream /blocked", body)
	require.Equal(t, 2, reached)

	records := engine.Capture().List(capture.Filter{}).Records
	require.Len(t, records, 4)
	for _, r := range records {
		require.Equal(t, "http", r.Scheme)
	}
	s.client.Close()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
}

// TestServePlainWithoutReadDeadline: connections that cannot interrupt reads (upstream and
// redialed alike) still serve plain sessions, including a reload-free local reply followed by
// an upstream exchange.
func TestServePlainWithoutReadDeadline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream "+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	address := upstream.Listener.Addr().String()
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{
		URL: []option.MITMURLRewriteRule{{ID: "u", Pattern: `^http://example\.com/blocked`, Action: "reject-dict"}},
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	serverSide, err := listener.Accept()
	require.NoError(t, err)
	raw, err := net.Dial("tcp", address)
	require.NoError(t, err)
	metadata := httpMetadata("example.com", "127.0.0.1:80")
	metadata.MITM = engine.Decide(metadata)
	require.NotNil(t, metadata.MITM)
	done := make(chan struct{})
	go func() {
		engine.Serve(context.Background(), noDeadlineConn{serverSide}, noDeadlineConn{raw},
			testRedial(address, func(c net.Conn) net.Conn { return noDeadlineConn{c} }), metadata, N.CloseHandlerFunc(func(error) {}))
		close(done)
	}()
	reader := bufio.NewReader(client)
	for _, tc := range []struct{ path, want string }{{"/blocked", "{}"}, {"/free", "upstream /free"}, {"/blocked", "{}"}, {"/again", "upstream /again"}} {
		_, err := io.WriteString(client, "GET "+tc.path+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		response, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, tc.want, string(body))
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
}

func TestRejectHostPort(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{
		{ID: "host", Pattern: `^https://ads\.example\.com/`, Action: "reject"},
		{ID: "any", Pattern: `^https://any\.example\.com(:\d+)?/`, Action: "reject"},
		{ID: "port", Pattern: `^https://p\.example\.com:8443/`, Action: "reject"},
	}}))
	_, ok := engine.RejectHost(tlsMetadata("ads.example.com", "10.0.0.1:443"))
	require.True(t, ok)
	_, ok = engine.RejectHost(tlsMetadata("ads.example.com", "10.0.0.1:8443"))
	require.False(t, ok, "the rule names no port")
	id, ok := engine.RejectHost(tlsMetadata("any.example.com", "10.0.0.1:8443"))
	require.True(t, ok)
	require.Equal(t, "any", id)
	id, ok = engine.RejectHost(tlsMetadata("p.example.com", "10.0.0.1:8443"))
	require.True(t, ok)
	require.Equal(t, "port", id)
	_, ok = engine.RejectHost(tlsMetadata("p.example.com", "10.0.0.1:443"))
	require.False(t, ok)
}
