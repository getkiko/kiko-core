package dnsmonitor

import "context"

// Rewritten marks the query's answer as modified by the named feature.
func Rewritten(ctx context.Context, note string) {
	Current(ctx).update(func(q *Query) { q.Rewritten = note })
}
