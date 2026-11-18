package clashapi

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/x/list"
	"go4.org/netipx"
)

type statusTestRuleSet struct {
	tag       string
	updatedAt int64
}

func (s statusTestRuleSet) Name() string                                                { return s.tag }
func (statusTestRuleSet) StartContext(context.Context, *adapter.HTTPStartContext) error { return nil }
func (statusTestRuleSet) Metadata() adapter.RuleSetMetadata                             { return adapter.RuleSetMetadata{} }
func (statusTestRuleSet) ExtractIPSet() []*netipx.IPSet                                 { return nil }
func (statusTestRuleSet) IncRef()                                                       {}
func (statusTestRuleSet) DecRef()                                                       {}
func (statusTestRuleSet) Cleanup()                                                      {}
func (statusTestRuleSet) RegisterCallback(adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	return nil
}
func (statusTestRuleSet) UnregisterCallback(*list.Element[adapter.RuleSetUpdateCallback]) {}
func (statusTestRuleSet) Close() error                                                    { return nil }
func (statusTestRuleSet) Match(*adapter.InboundContext) bool                              { return false }
func (statusTestRuleSet) String() string                                                  { return "" }
func (s statusTestRuleSet) LastUpdatedAtMillis() int64                                    { return s.updatedAt }

func TestRuleSetStatusesIncludeLastUpdatedAtMillis(t *testing.T) {
	got := ruleSetStatuses([]adapter.RuleSet{
		statusTestRuleSet{tag: "geosite-cn", updatedAt: 1_792_720_440_000},
	})
	if len(got) != 1 || got[0].Tag != "geosite-cn" || got[0].LastUpdatedAt != 1_792_720_440_000 {
		t.Fatalf("unexpected rule-set statuses: %+v", got)
	}
}
