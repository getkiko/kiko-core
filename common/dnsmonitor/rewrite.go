package dnsmonitor

import "context"

// Rewritten marks the query's answer as modified by the named feature.
func Rewritten(ctx context.Context, note string) {
	Current(ctx).update(func(q *Query) { q.Rewritten = note })
}

// Script records the result of a dns script action on the query.
func Script(ctx context.Context, run ScriptRun) {
	Current(ctx).update(func(q *Query) {
		if len(q.Scripts) < 8 {
			run.Detail = clip(run.Detail, 512)
			q.Scripts = append(q.Scripts, run)
		}
	})
}
