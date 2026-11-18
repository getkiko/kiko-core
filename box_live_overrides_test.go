package box_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func liveOverridesConfig(path, localOverrides, inlineOverrides string) string {
	return `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "d1"},
    {"type": "direct", "tag": "d2"}
  ],
  "route": {
    "rule_set": [
      {"type": "local", "tag": "file", "format": "source", "path": ` + strconv.Quote(path) + localOverrides + `},
      {"type": "inline", "tag": "mine", "rules": [{"domain": ["i1.test", "i2.test"]}]` + inlineOverrides + `}
    ],
    "rules": [
      {"rule_set": ["file", "mine"], "outbound": "d2"}
    ],
    "final": "d1"
  }
}`
}

// Changed overrides reload the rule sets in place, without a restart.
func TestLiveApplyRuleSetOverridesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":3,"rules":[{"domain":["a.test","b.test"]}]}`), 0o644))
	ctx, _ := startLiveBox(t, liveOverridesConfig(path, "", ""))
	router := service.FromContext[adapter.Router](ctx)
	file, loaded := router.RuleSet("file")
	require.True(t, loaded)
	mine, loaded := router.RuleSet("mine")
	require.True(t, loaded)
	domain := func(name string) *adapter.InboundContext { return &adapter.InboundContext{Domain: name} }
	require.True(t, file.Match(domain("a.test")))
	require.True(t, mine.Match(domain("i1.test")))

	changed := liveOverridesConfig(path,
		`, "overrides": {"remove": {"domain": ["a.test"]}, "add": [{"domain": ["added.test"]}]}`,
		`, "overrides": {"remove": {"domain": "i1.test"}}`)
	result, err := applyLive(t, ctx, changed)
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	after, _ := router.RuleSet("file")
	require.Same(t, file, after)
	require.False(t, file.Match(domain("a.test")))
	require.True(t, file.Match(domain("b.test")))
	require.True(t, file.Match(domain("added.test")))
	require.False(t, mine.Match(domain("i1.test")))
	require.True(t, mine.Match(domain("i2.test")))

	// Overrides that do not build leave the configuration as it was.
	broken := strings.Replace(changed, `"add": [{"domain": ["added.test"]}]`, `"add": [{"domain_regex": ["("]}]`, 1)
	_, err = applyLive(t, ctx, broken)
	require.Error(t, err)
	require.True(t, file.Match(domain("added.test")))

	// Removing the overrides restores the source rules.
	result, err = applyLive(t, ctx, liveOverridesConfig(path, "", ""))
	require.NoError(t, err)
	require.True(t, result.Applied, result.Reason)
	require.True(t, file.Match(domain("a.test")))
	require.False(t, file.Match(domain("added.test")))
	require.True(t, mine.Match(domain("i1.test")))
}

// A rule set that fails to reload restores the ones reloaded before it.
func TestLiveApplyRuleSetReloadFailureRestores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":3,"rules":[{"domain":["a.test","b.test"]}]}`), 0o644))
	ctx, _ := startLiveBox(t, liveOverridesConfig(path, "", ""))
	router := service.FromContext[adapter.Router](ctx)
	file, _ := router.RuleSet("file")
	mine, _ := router.RuleSet("mine")
	domain := func(name string) *adapter.InboundContext { return &adapter.InboundContext{Domain: name} }

	_, err := applyLive(t, ctx, liveOverridesConfig(path,
		`, "overrides": {"remove": {"domain": ["a.test"]}}`,
		`, "overrides": {"add": [{"domain_regex": ["("]}]}`))
	require.Error(t, err)
	require.True(t, file.Match(domain("a.test")))
	require.True(t, mine.Match(domain("i1.test")))
}

// A remote rule set without saved content restarts the core for new
// overrides rather than downloading within the live apply.
func TestLiveApplyRemoteRuleSetOverridesWithoutCacheRestart(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain":["a.test","b.test"]}]}`))
	}))
	defer upstream.Close()
	config := func(overrides string) string {
		return `{
  "log": {"disabled": true},
  "outbounds": [{"type": "direct", "tag": "d1"}],
  "route": {
    "rule_set": [{"type": "remote", "tag": "web", "format": "source", "url": ` + strconv.Quote(upstream.URL+"/web.json") + overrides + `}],
    "rules": [{"rule_set": ["web"], "outbound": "d1"}],
    "final": "d1"
  }
}`
	}
	ctx, _ := startLiveBox(t, config(""))
	router := service.FromContext[adapter.Router](ctx)
	web, loaded := router.RuleSet("web")
	require.True(t, loaded)
	require.True(t, web.Match(&adapter.InboundContext{Domain: "a.test"}))
	result, err := applyLive(t, ctx, config(`, "overrides": {"remove": {"domain": ["a.test"]}}`))
	require.NoError(t, err)
	require.True(t, result.RestartRequired)
	require.Contains(t, result.Reason, "web")
	require.True(t, web.Match(&adapter.InboundContext{Domain: "a.test"}))
}
