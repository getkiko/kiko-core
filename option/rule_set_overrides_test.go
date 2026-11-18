package option

import (
	"context"
	"reflect"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestRuleSetOverridesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{"type":"remote","tag":"r","url":"https://example.com/r.srs","update_interval":"1d",
		  "overrides":{"add":[{"domain":"x.test"},{"type":"logical","mode":"or","rules":[{"ip_cidr":"1.1.1.1/32"}]}],
		               "remove":{"domain":["a.test"],"ip_cidr":["10.0.0.0/8","10.1.1.1"],"process_name":"curl"}}}`,
		`{"type":"local","tag":"l","path":"l.json","overrides":{"remove":{"domain_suffix":"b.test","source_ip_cidr":"192.168.0.0/16","package_name":"com.x","process_path":"/bin/x","domain_keyword":"k","domain_regex":"^r$"}}}`,
		`{"tag":"i","rules":[{"domain":"a.test"}],"overrides":{"add":[{"domain":"b.test"}]}}`,
	} {
		var ruleSet RuleSet
		require.NoError(t, json.UnmarshalContext(context.Background(), []byte(content), &ruleSet), content)
		require.NotNil(t, ruleSet.Overrides)
		encoded, err := json.Marshal(ruleSet)
		require.NoError(t, err)
		var again RuleSet
		require.NoError(t, json.UnmarshalContext(context.Background(), encoded, &again))
		require.Equal(t, ruleSet, again)
		reencoded, err := json.Marshal(again)
		require.NoError(t, err)
		require.JSONEq(t, string(encoded), string(reencoded))
	}

	var remote RuleSet
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"type":"remote","tag":"r","url":"https://example.com/r.srs",
		"overrides":{"add":[{"domain":"x.test"}],"remove":{"domain":["a.test"],"ip_cidr":["10.1.1.1"]}}}`), &remote))
	require.Equal(t, C.RuleSetTypeRemote, remote.Type)
	require.Equal(t, []string{"a.test"}, []string(remote.Overrides.Remove.Domain))
	require.Equal(t, []string{"10.1.1.1"}, []string(remote.Overrides.Remove.IPCIDR))
	require.Equal(t, []string{"x.test"}, []string(remote.Overrides.Add[0].DefaultOptions.Domain))
	require.False(t, remote.Overrides.IsEmpty())
	require.True(t, remote.Overrides.HasRemove())

	var plain RuleSet
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"type":"remote","tag":"r","url":"https://example.com/r.srs"}`), &plain))
	require.Nil(t, plain.Overrides)
	encoded, err := json.Marshal(plain)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "overrides")
}

func TestRuleSetOverridesRejectUnsupportedRemove(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{"tag":"i","rules":[{"domain":"a.test"}],"overrides":{"remove":{"port":[80]}}}`,
		`{"tag":"i","rules":[{"domain":"a.test"}],"overrides":{"remove":{"invert":true,"domain":"a.test"}}}`,
		`{"tag":"i","rules":[{"domain":"a.test"}],"overrides":{"remove":{"ip_cidr":["not-an-ip"]}}}`,
		`{"tag":"i","rules":[{"domain":"a.test"}],"overrides":{"add":[{}]}}`,
		`{"tag":"i","rules":[{"domain":"a.test"}],"overrides":{"unknown":1}}`,
	} {
		var ruleSet RuleSet
		require.Error(t, json.UnmarshalContext(context.Background(), []byte(content), &ruleSet), content)
	}
}

func TestRuleSetOverridesSchema(t *testing.T) {
	t.Parallel()
	content, err := schema.Generate(context.Background(), reflect.TypeFor[RuleSet]())
	require.NoError(t, err)
	require.Contains(t, string(content), `"RuleSetOverrides"`)
	require.Contains(t, string(content), `"overrides"`)
	require.Contains(t, string(content), `"source_ip_cidr"`)
}
