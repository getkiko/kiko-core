package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestDNSRuleActionRespondUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var action DNSRuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"respond"}`), &action)
	require.NoError(t, err)
	require.Equal(t, C.RuleActionTypeRespond, action.Action)
	require.Equal(t, DNSRouteActionOptions{}, action.RouteOptions)
}

func TestDNSRuleActionRespondRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	var action DNSRuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"respond","disable_cache":true}`), &action)
	require.ErrorContains(t, err, "unknown field")
}

func TestRouteOptionsActionMITM(t *testing.T) {
	t.Parallel()

	var action RuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"route-options","mitm":"skip"}`), &action)
	require.NoError(t, err)
	require.Equal(t, C.MITMOverrideSkip, action.RouteOptionsOptions.MITM)
	err = json.UnmarshalContext(context.Background(), []byte(`{"action":"route","outbound":"direct","mitm":"force"}`), &action)
	require.NoError(t, err)
	require.Equal(t, C.MITMOverrideForce, action.RouteOptions.MITM)
}
