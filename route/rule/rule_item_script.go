package rule

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/script"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

var _ RuleItem = (*ScriptItem)(nil)

// ScriptItem is the `script` condition: the rule matches when any listed rule script
// returns true. The scripts are looked up by tag when the condition is evaluated, so a script
// reload takes effect without rebuilding the rule; a missing script, a failed run and a
// timeout all make the condition false.
type ScriptItem struct {
	ctx     context.Context
	logger  log.ContextLogger
	tags    []string
	manager atomic.Pointer[script.Manager]
}

func NewScriptItem(ctx context.Context, logger log.ContextLogger, tags []string) *ScriptItem {
	return &ScriptItem{ctx: ctx, logger: logger, tags: tags}
}

// ScriptManager returns the script manager of the MITM engine in ctx, nil when there is none.
func ScriptManager(ctx context.Context) *script.Manager {
	engine := service.FromContext[adapter.MITMEngine](ctx)
	if engine == nil {
		return nil
	}
	provider, ok := engine.(adapter.MITMScriptProvider)
	if !ok {
		return nil
	}
	return provider.Scripts()
}

func (r *ScriptItem) scripts() *script.Manager {
	if m := r.manager.Load(); m != nil {
		return m
	}
	m := ScriptManager(r.ctx)
	if m != nil {
		r.manager.Store(m)
	}
	return m
}

func (r *ScriptItem) Match(metadata *adapter.InboundContext) bool {
	if dry := metadata.ScriptDryRun; dry != nil {
		for _, tag := range r.tags {
			dry.Add(tag)
		}
		return false
	}
	if metadata.PreMatch {
		// The metadata is partial (no domain yet), so the script would see a request that never
		// happens and its cached result would be keyed under the empty domain.
		return false
	}
	manager := r.scripts()
	if manager == nil {
		return false
	}
	in := ScriptInput(metadata)
	for _, tag := range r.tags {
		outcome := manager.RunRule(tag, in)
		if outcome.Err != "" {
			if r.logger != nil && !outcome.Cached {
				r.logger.Warn("script ", tag, ": ", outcome.Err)
			}
			continue
		}
		if outcome.Matched {
			return true
		}
	}
	return false
}

func (r *ScriptItem) String() string {
	if len(r.tags) == 1 {
		return F.ToString("script=", r.tags[0])
	}
	return F.ToString("script=[", strings.Join(r.tags, " "), "]")
}

// ScriptInput is the $request of a rule or dns script for a connection or a DNS question.
func ScriptInput(metadata *adapter.InboundContext) *script.RuleInput {
	in := &script.RuleInput{
		Network:     metadata.Network,
		Protocol:    metadata.Protocol,
		Inbound:     metadata.Inbound,
		InboundType: metadata.InboundType,
		User:        metadata.User,
		Port:        metadata.Destination.Port,
	}
	domain := metadata.Domain
	if domain == "" {
		domain = metadata.Destination.Fqdn
	}
	in.Domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if metadata.Destination.Addr.IsValid() {
		in.IP = metadata.Destination.Addr.String()
	}
	if metadata.Source.Addr.IsValid() {
		in.SourceIP = metadata.Source.Addr.String()
	}
	if owner := metadata.ProcessInfo; owner != nil {
		in.ProcessPath = owner.ProcessPath
		if i := strings.LastIndexAny(owner.ProcessPath, `/\`); i >= 0 {
			in.ProcessName = owner.ProcessPath[i+1:]
		} else {
			in.ProcessName = owner.ProcessPath
		}
		if in.User == "" {
			in.User = owner.UserName
		}
	}
	if qType := metadata.ScriptQuestionType(); qType != 0 {
		in.QueryType = dns.TypeToString[qType]
	}
	return in
}
