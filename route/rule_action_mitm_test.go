package route

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

func TestRuleActionMITMOverride(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("router")
	action, err := R.NewRuleAction(logger, option.RuleAction{
		Action:              C.RuleActionTypeRouteOptions,
		RouteOptionsOptions: option.RouteOptionsActionOptions{MITM: C.MITMOverrideSkip},
	})
	require.NoError(t, err)
	require.Equal(t, C.MITMOverrideSkip, action.(*R.RuleActionRouteOptions).MITM)
	require.Equal(t, "route-options(mitm=skip)", action.String())
	_, err = R.NewRuleAction(logger, option.RuleAction{
		Action:              C.RuleActionTypeRouteOptions,
		RouteOptionsOptions: option.RouteOptionsActionOptions{MITM: "always"},
	})
	require.Error(t, err)
}
