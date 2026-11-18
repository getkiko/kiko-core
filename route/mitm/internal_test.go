package mitm

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/rewrite"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestInternalRewriteRefusesControlPorts(t *testing.T) {
	ca := writeTestCA(t)
	rules := &option.MITMHTTPRewriteOptions{URL: []option.MITMURLRewriteRule{
		{ID: "api", Pattern: `^https://example\.com/api`, Action: "header", Target: "http://127.0.0.1:9090/configs"},
		{ID: "other", Pattern: `^https://example\.com/other`, Action: "header", Target: "http://127.0.0.1:9091/x"},
		{ID: "remote", Pattern: `^https://example\.com/remote`, Action: "header", Target: "http://10.0.0.1:9090/x"},
		{ID: "name", Pattern: `^https://example\.com/name`, Action: "header", Target: "http://localhost:9090/x"},
		{ID: "hex", Pattern: `^https://example\.com/hex`, Action: "header", Target: "http://0x7f.1:9090/x"},
		{ID: "int", Pattern: `^https://example\.com/int`, Action: "header", Target: "http://2130706433:9090/x"},
		{ID: "oct", Pattern: `^https://example\.com/oct`, Action: "header", Target: "http://0177.0.0.1:9090/x"},
		{ID: "zero", Pattern: `^https://example\.com/zero`, Action: "header", Target: "http://0:9090/x"},
		{ID: "meta", Pattern: `^https://example\.com/meta`, Action: "header", Target: "http://169.254.169.254/latest"},
		{ID: "v6", Pattern: `^https://example\.com/six`, Action: "header", Target: "http://[::1]:9090/x"},
	}}
	engine := newTestEngine(t, context.Background(), rewriteEngineOptions(ca, true, rules))
	set := engine.rewriteSet()
	// Without known control endpoints only link-local targets are refused.
	require.NotNil(t, set.Plan("https", "example.com", "/api").Internal())
	require.Nil(t, set.Plan("https", "example.com", "/meta").Internal())

	engine.SetControlEndpoints("127.0.0.1:9090", ":9092", "")
	for target, refused := range map[string]bool{
		"/api": true, "/hex": true, "/int": true, "/oct": true, "/zero": true, "/meta": true, "/other": false, "/remote": false, "/name": true, "/six": true,
	} {
		var plan *rewrite.Plan = set.Plan("https", "example.com", target)
		if refused {
			require.Nil(t, plan.Internal(), target)
		} else {
			require.NotNil(t, plan.Internal(), target)
		}
	}
}
