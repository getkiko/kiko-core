package rule

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
)

func TestRuleActionSniffOverrideDestination(t *testing.T) {
	var actionOptions option.RuleAction
	err := json.Unmarshal([]byte(`{
		"action": "sniff",
		"sniffer": "tls",
		"override_destination": true
	}`), &actionOptions)
	if err != nil {
		t.Fatal(err)
	}
	if actionOptions.Action != C.RuleActionTypeSniff {
		t.Fatalf("unexpected action type: %s", actionOptions.Action)
	}
	if !actionOptions.SniffOptions.OverrideDestination {
		t.Fatal("override_destination was not decoded")
	}

	action, err := NewRuleAction(context.Background(), logger.NOP(), actionOptions)
	if err != nil {
		t.Fatal(err)
	}
	sniffAction := action.(*RuleActionSniff)
	if !sniffAction.OverrideDestination {
		t.Fatal("override_destination was not propagated")
	}
}
