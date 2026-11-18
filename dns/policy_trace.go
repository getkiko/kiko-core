package dns

import (
	"context"
	"sync"
)

type policyTraceKey struct{}

type PolicyTrace struct {
	mu        sync.Mutex
	Rule      string
	RuleIndex int
	Server    string
	Detour    string
}

func WithPolicyTrace(ctx context.Context, trace *PolicyTrace) context.Context {
	trace.RuleIndex = -1
	return context.WithValue(ctx, policyTraceKey{}, trace)
}

func policyTraceFrom(ctx context.Context) *PolicyTrace {
	trace, _ := ctx.Value(policyTraceKey{}).(*PolicyTrace)
	return trace
}

func (t *PolicyTrace) setRule(index int, rule string) {
	t.mu.Lock()
	t.RuleIndex, t.Rule = index, rule
	t.mu.Unlock()
}

func (t *PolicyTrace) setServer(server, detour string) {
	t.mu.Lock()
	t.Server, t.Detour = server, detour
	t.mu.Unlock()
}

func (t *PolicyTrace) Snapshot() (rule string, index int, server, detour string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Rule, t.RuleIndex, t.Server, t.Detour
}
