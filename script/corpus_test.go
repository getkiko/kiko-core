package script

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func corpusSource(t *testing.T, name string) string {
	data, err := os.ReadFile(filepath.Join("testdata", "community", name))
	require.NoError(t, err)
	return string(data)
}

func corpusConfig(t *testing.T, file string, phase Phase, body, binary bool, argument string) Config {
	return Config{Tag: file, Type: phase, Pattern: ".*", Source: corpusSource(t, file), SourceName: file, RequiresBody: body, BinaryBody: binary, Argument: argument}
}

func TestCommunityCorpus(t *testing.T) {
	store := NewMemoryStore()
	notes := &testNotifier{}
	m := NewManager(ManagerOptions{Store: store, Notifier: notes})
	defer m.Close()
	run := func(cfg Config, in *Input) *Result {
		require.NoError(t, m.Apply([]Config{cfg}))
		res := m.Run(context.Background(), m.Current().Lookup(cfg.Tag), in)
		require.Empty(t, res.Error, cfg.Tag)
		return res
	}

	t.Run("01 json remove ads", func(t *testing.T) {
		in := respInput(200, `{"code":0,"data":{"ad_config":{"x":1},"items":[{"id":1},{"id":2,"is_ad":true},{"id":3,"card_type":"ad"},{"id":4,"tags":["sponsored"]},{"id":5}]}}`)
		res := run(corpusConfig(t, "01_json_remove_ads.js", PhaseResponse, true, false, ""), in)
		require.Equal(t, ActionModify, res.Action)
		require.JSONEq(t, `{"code":0,"data":{"items":[{"id":1},{"id":5}],"total":2}}`, string(res.Body))
	})

	t.Run("02 base64 body", func(t *testing.T) {
		inner := base64.StdEncoding.EncodeToString([]byte(`{"nick":"café","vip":false}`))
		in := respInput(200, `{"payload":"`+inner+`","other":1}`)
		res := run(corpusConfig(t, "02_base64_body.js", PhaseResponse, true, false, ""), in)
		require.Equal(t, ActionModify, res.Action)
		require.Contains(t, string(res.Body), `"other":1`)
		// payload is base64 of {"nick":"café ✓","vip":true,"expire":4102444800}
		want := base64.StdEncoding.EncodeToString([]byte(`{"nick":"café ✓","vip":true,"expire":4102444800}`))
		require.Contains(t, string(res.Body), want)
	})

	t.Run("03 header injection", func(t *testing.T) {
		in := reqInput("https://x/", "User-Agent", "Mozilla/5.0", "If-None-Match", `"abc"`, "Accept", "*/*")
		res := run(corpusConfig(t, "03_header_inject.js", PhaseRequest, false, false, ""), in)
		require.Equal(t, ActionModify, res.Action)
		require.Equal(t, "Mozilla/5.0 MyApp/9.9.9", headerValue(res.Headers, "User-Agent"))
		require.Equal(t, "", headerValue(res.Headers, "If-None-Match"))
		require.Equal(t, "com.example.app", headerValue(res.Headers, "X-Requested-With"))
		require.Equal(t, "*/*", headerValue(res.Headers, "Accept"))
		// Already tagged: the user agent stays.
		in = reqInput("https://x/", "User-Agent", "MyApp/1.0 Mozilla")
		res = run(corpusConfig(t, "03_header_inject.js", PhaseRequest, false, false, ""), in)
		require.Equal(t, "MyApp/1.0 Mozilla", headerValue(res.Headers, "User-Agent"))
	})

	t.Run("04 url rewrite", func(t *testing.T) {
		res := run(corpusConfig(t, "04_url_rewrite.js", PhaseRequest, false, false, ""), reqInput("https://api.example.com/v1/users?id=3"))
		require.Equal(t, ActionModify, res.Action)
		require.Equal(t, "https://api2.example.com/v2/users?id=3", res.URL)
		require.Len(t, res.Logs, 1)
		res = run(corpusConfig(t, "04_url_rewrite.js", PhaseRequest, false, false, ""), reqInput("https://other.example.com/v1/users"))
		require.Equal(t, ActionNone, res.Action)
	})

	t.Run("05 mock response", func(t *testing.T) {
		res := run(corpusConfig(t, "05_mock_response.js", PhaseRequest, false, false, ""), reqInput("https://x/vip"))
		require.Equal(t, ActionRespond, res.Action)
		require.Equal(t, 200, res.Response.Status)
		require.Equal(t, "no-store", headerValue(res.Response.Headers, "Cache-Control"))
		require.JSONEq(t, `{"code":0,"message":"ok","data":{"vip":true,"level":9,"url":"https://x/vip"}}`, string(res.Response.Body))
	})

	t.Run("06 status override", func(t *testing.T) {
		res := run(corpusConfig(t, "06_status_override.js", PhaseResponse, false, false, ""), respInput(429, "", "Content-Type", "text/plain"))
		require.Equal(t, ActionModify, res.Action)
		require.Equal(t, 404, res.Status)
		require.Equal(t, "0", headerValue(res.Headers, "Retry-After"))
		res = run(corpusConfig(t, "06_status_override.js", PhaseResponse, false, false, ""), respInput(200, ""))
		require.Equal(t, ActionNone, res.Action)
	})

	t.Run("07 cookies", func(t *testing.T) {
		in := respInput(200, "", "Set-Cookie", "sid=1; Path=/; Secure; SameSite=None", "Set-Cookie", "t=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT; SameSite=Lax; Secure")
		res := run(corpusConfig(t, "07_cookie_manipulation.js", PhaseResponse, false, false, ""), in)
		require.Equal(t, ActionModify, res.Action)
		require.Equal(t, "sid=1; Path=/|t=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT|debug=1; Path=/", headerValue(res.Headers, "Set-Cookie"))
		res = run(corpusConfig(t, "07_cookie_manipulation.js", PhaseResponse, false, false, ""), respInput(200, ""))
		require.Equal(t, "debug=1; Path=/", headerValue(res.Headers, "Set-Cookie"))
	})

	t.Run("08 binary body", func(t *testing.T) {
		in := respInput(200, "")
		in.Response.Body = []byte("GIF87a\x01\x00\x01\x00\x00\x00\x00\x2c")
		res := run(corpusConfig(t, "08_binary_body.js", PhaseResponse, true, true, ""), in)
		require.Equal(t, ActionModify, res.Action)
		require.Equal(t, "GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b", string(res.Body))
		in.Response.Body = []byte("PNG-not-gif")
		res = run(corpusConfig(t, "08_binary_body.js", PhaseResponse, true, true, ""), in)
		require.Equal(t, ActionNone, res.Action)
		require.Len(t, res.Logs, 1)
	})

	t.Run("09 async", func(t *testing.T) {
		res := run(corpusConfig(t, "09_async_timeout.js", PhaseRequest, false, false, ""), reqInput("https://x/", "Accept", "*/*"))
		require.Equal(t, ActionModify, res.Action)
		require.Equal(t, "ABC", headerValue(res.Headers, "X-Token"))
		require.GreaterOrEqual(t, res.Duration.Milliseconds(), int64(35))
	})

	t.Run("10 argument", func(t *testing.T) {
		in := respInput(200, `{"ads":1,"banner":2,"keep":3}`)
		res := run(corpusConfig(t, "10_argument_parsing.js", PhaseResponse, true, false, "remove=ads,banner&flag=true"), in)
		require.Equal(t, ActionModify, res.Action)
		require.JSONEq(t, `{"keep":3,"flagged":true}`, string(res.Body))
	})

	t.Run("11 persistent store", func(t *testing.T) {
		cfg := corpusConfig(t, "11_persistent_counter.js", PhaseRequest, false, false, "")
		require.NoError(t, m.Apply([]Config{cfg}))
		sc := m.Current().Lookup(cfg.Tag)
		for i := 0; i < 4; i++ {
			require.Empty(t, m.Run(context.Background(), sc, reqInput("https://x/")).Error)
		}
		v, _, _ := store.Get(cfg.Tag, "counter")
		require.Equal(t, "4", v)
		require.Len(t, notes.n, 1)
		require.Equal(t, "https://example.com/counter", notes.n[0].URL)
	})
}
