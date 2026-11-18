package dnsmonitor

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
)

type traceKey struct{}
type attemptKey struct{}
type operationKey struct{}
type ingressKey struct{}
type resolverKey struct{}

type Trace struct {
	mu            sync.Mutex
	m             *Manager
	q             Query
	dirty         bool
	ended         bool
	capturedBytes int
}

func Current(ctx context.Context) *Trace { t, _ := ctx.Value(traceKey{}).(*Trace); return t }
func WithParent(ctx context.Context, t *Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

func Inbound(ctx context.Context, message *dns.Msg) context.Context {
	ctx, _ = Begin(ctx, message, "query")
	return context.WithValue(ctx, ingressKey{}, message)
}

func BeginRouter(ctx context.Context, message *dns.Msg) (context.Context, *Trace) {
	if ctx.Value(ingressKey{}) == message && Current(ctx) != nil {
		return ctx, Current(ctx)
	}
	return Begin(ctx, message, "query")
}

func ParseError(ctx context.Context, err error) {
	_, t := Begin(ctx, nil, "malformed_request")
	t.End(nil, err)
	t.update(func(q *Query) {
		if q.Error != nil {
			q.Error.Stage = "decode_request"
		}
	})
}

func WithOperation(ctx context.Context) context.Context {
	if m := FromContext(ctx); m != nil {
		return context.WithValue(ctx, operationKey{}, m.nextID())
	}
	return ctx
}

func unobserved(ctx context.Context) context.Context {
	if Current(ctx) != nil {
		return context.WithValue(ctx, traceKey{}, (*Trace)(nil))
	}
	return ctx
}

func Begin(ctx context.Context, message *dns.Msg, role string) (context.Context, *Trace) {
	m := FromContext(ctx)
	if m == nil {
		return unobserved(ctx), nil
	}
	select {
	case <-m.done:
		return unobserved(ctx), nil
	default:
	}
	t := &Trace{m: m, dirty: true, q: Query{ID: m.nextID(), StartedAt: time.Now(), Role: role, Status: "pending", Request: snapshot(message, m.options.CaptureWire)}}
	t.q.Questions = make([]Question, 0)
	if t.q.Request != nil {
		t.q.Questions = append(t.q.Questions, t.q.Request.Questions...)
	}
	if parent := Current(ctx); parent != nil {
		t.q.ParentID = parent.ID()
		parent.mu.Lock()
		t.q.Resolver = parent.q.Resolver
		t.q.Transport = parent.q.Transport
		parent.mu.Unlock()
		if role == "query" {
			t.q.Role = "bootstrap"
		}
	}
	t.q.OperationID, _ = ctx.Value(operationKey{}).(string)
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		t.q.Source = Source{Inbound: metadata.Inbound, Address: metadata.Source.String(), Destination: metadata.Destination.String(), Network: metadata.Network, User: metadata.User}
		if !metadata.Source.IsValid() {
			t.q.Source.Address = ""
		}
		if !metadata.Destination.IsValid() {
			t.q.Source.Destination = ""
		}
		if p := metadata.ProcessInfo; p != nil {
			if p.ProcessPath != "" {
				t.q.Source.Process = filepath.Base(p.ProcessPath)
			}
			t.q.Source.ProcessPath = p.ProcessPath
			t.q.Source.PID = uint32(p.ProcessID)
		}
	}
	m.mu.Lock()
	activeLimit := min(1024, max(1, m.options.Bytes/(128<<10)))
	if m.stats.Pending >= activeLimit {
		m.stats.Dropped++
		m.mu.Unlock()
		return unobserved(ctx), nil
	}
	// Keep admission bounded even when a burst finishes between consumer ticks.
	if len(m.queries) >= m.options.Entries+activeLimit {
		var oldest *Trace
		for _, candidate := range m.queries {
			candidate.mu.Lock()
			finished := candidate.ended
			candidate.mu.Unlock()
			if finished && (oldest == nil || candidate.q.StartedAt.Before(oldest.q.StartedAt)) {
				oldest = candidate
			}
		}
		if oldest == nil {
			m.stats.Dropped++
			m.mu.Unlock()
			return unobserved(ctx), nil
		}
		m.evictLocked(oldest.q.ID)
	}
	m.stats.Total++
	m.stats.Pending++
	m.queries[t.q.ID] = t
	m.mu.Unlock()
	m.notify()
	ctx = context.WithValue(ctx, outboundKey{}, []string(nil))
	return context.WithValue(context.WithValue(ctx, traceKey{}, t), attemptKey{}, (*AttemptTrace)(nil)), t
}

func Ensure(ctx context.Context, message *dns.Msg) (context.Context, *Trace, bool) {
	if t := Current(ctx); t != nil {
		return ctx, t, false
	}
	ctx, t := Begin(ctx, message, "query")
	return ctx, t, t != nil
}

func (t *Trace) ID() string {
	if t == nil {
		return ""
	}
	return t.q.ID
}
func (t *Trace) update(fn func(*Query)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	fn(&t.q)
	t.q.Revision++
	t.dirty = true
	t.mu.Unlock()
	t.m.notify()
}
func (t *Trace) copy(brief bool) Query {
	t.mu.Lock()
	q := t.q
	q.Questions = append(make([]Question, 0, len(q.Questions)), q.Questions...)
	q.Policy = append([]string(nil), q.Policy...)
	q.ResolvedAddresses = append([]string(nil), q.ResolvedAddresses...)
	q.Attempts = append([]Attempt(nil), q.Attempts...)
	for i := range q.Attempts {
		q.Attempts[i].Diagnostics = append([]string(nil), q.Attempts[i].Diagnostics...)
	}
	t.mu.Unlock()
	if brief {
		q = summary(q)
		return q
	}
	q.Request = cloneMessage(q.Request)
	q.Response = cloneMessage(q.Response)
	for i := range q.Attempts {
		q.Attempts[i].Response = cloneMessage(q.Attempts[i].Response)
	}
	return q
}

func (t *Trace) capture(message *dns.Msg) *Message {
	if message == nil {
		return nil
	}
	m := snapshot(message, t.m.options.CaptureWire)
	size := messageBytes(m)
	if t.capturedBytes+size > 64<<10 {
		t.q.Incomplete = true
		m.Answer = nil
		m.Authority = nil
		m.Additional = nil
		m.Wire = nil
		m.TruncatedCapture = true
		size = messageBytes(m)
	}
	t.capturedBytes += size
	return m
}

func (t *Trace) End(response *dns.Msg, err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.ended {
		t.mu.Unlock()
		return
	}
	t.ended = true
	now := time.Now()
	t.q.FinishedAt = &now
	t.q.DurationMS = float64(now.Sub(t.q.StartedAt)) / float64(time.Millisecond)
	if response != nil {
		t.q.Response = t.capture(response)
		t.q.ResolvedAddresses = responseAddresses(response)
	}
	t.q.Error = failure(err, "query")
	t.q.Status = "success"
	if err != nil {
		t.q.Status = t.q.Error.Kind
		if t.q.PolicyResult == "reject" {
			t.q.Status = "rejected"
			t.q.Error.Stage = "policy"
		} else if t.q.PolicyResult == "drop" {
			t.q.Status = "dropped"
			t.q.Error.Stage = "policy"
		}
	} else if response != nil && response.Rcode != dns.RcodeSuccess {
		t.q.Status = "negative"
	}
	status, cache := t.q.Status, t.q.Cache
	t.q.Revision++
	t.dirty = true
	t.mu.Unlock()
	t.m.mu.Lock()
	t.m.stats.Pending--
	if status == "timeout" {
		t.m.stats.Timeouts++
	}
	if err != nil {
		t.m.stats.Errors++
	}
	if cache == "hit" || cache == "stale" {
		t.m.stats.CacheHits++
	}
	t.m.mu.Unlock()
	t.m.notify()
}

func Cache(ctx context.Context, state string) {
	Current(ctx).update(func(q *Query) { q.Cache = state })
}
func Shared(ctx context.Context, id string) {
	Current(ctx).update(func(q *Query) { q.SharedWith = id })
}
func Flight(ctx context.Context, key any, loaded bool) {
	t := Current(ctx)
	if t == nil {
		return
	}
	if loaded {
		if owner, ok := t.m.flights.Load(key); ok {
			Shared(ctx, owner.(string))
		}
	} else {
		t.m.flights.Store(key, t.ID())
	}
}
func ForgetFlight(ctx context.Context, key any) {
	if t := Current(ctx); t != nil {
		t.m.flights.Delete(key)
	}
}

func LookupResult(ctx context.Context, domain string, addresses []netip.Addr) {
	t := Current(ctx)
	if t == nil {
		return
	}
	t.update(func(q *Query) {
		q.Questions = []Question{{Name: domain, Type: "LOOKUP", Class: "IN"}}
		for _, address := range addresses {
			q.ResolvedAddresses = append(q.ResolvedAddresses, address.String())
		}
	})
}
func Policy(ctx context.Context, rule string) {
	Current(ctx).update(func(q *Query) {
		if len(q.Policy) < 16 {
			q.Policy = append(q.Policy, clip(rule, 1024))
		}
	})
}
func Resolver(ctx context.Context, tag, transport string) {
	Current(ctx).update(func(q *Query) { q.Resolver = tag; q.Transport = transport })
}
func WithResolver(ctx context.Context, tag, transport string) context.Context {
	Resolver(ctx, tag, transport)
	if Current(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, resolverKey{}, [2]string{tag, transport})
}
func PolicyResult(ctx context.Context, action, method string) {
	Current(ctx).update(func(q *Query) {
		q.PolicyResult = action
		if method == "drop" {
			q.PolicyResult = "drop"
		}
	})
}
func Result(ctx context.Context, response *dns.Msg) {
	t := Current(ctx)
	if t != nil && response != nil {
		t.update(func(q *Query) {
			if !t.ended {
				q.Response = t.capture(response)
				q.ResolvedAddresses = responseAddresses(response)
			}
		})
	}
}
func Delivery(ctx context.Context, err error, truncated bool) {
	Current(ctx).update(func(q *Query) {
		q.Delivery = "submitted"
		if truncated {
			q.Delivery = "submitted_truncated"
		}
		q.DeliveryError = failure(err, "client_write")
		if err != nil {
			q.Delivery = "error"
		}
	})
}

type AttemptTrace struct {
	t    *Trace
	id   string
	once sync.Once
}

func StartAttempt(ctx context.Context, protocol string) (context.Context, *AttemptTrace) {
	t := Current(ctx)
	if t == nil {
		return ctx, nil
	}
	a := &AttemptTrace{t: t, id: t.m.nextID()}
	t.update(func(q *Query) {
		if len(q.Attempts) >= 16 {
			q.Incomplete = true
			return
		}
		resolver, transport := q.Resolver, q.Transport
		if selected, ok := ctx.Value(resolverKey{}).([2]string); ok {
			resolver, transport = selected[0], selected[1]
		}
		q.Attempts = append(q.Attempts, Attempt{ID: a.id, StartedAt: time.Now(), Resolver: resolver, Transport: transport, Protocol: protocol, NetworkUsed: true, Visibility: "observed"})
	})
	return context.WithValue(ctx, attemptKey{}, a), a
}
func ActiveAttempt(ctx context.Context) *AttemptTrace {
	a, _ := ctx.Value(attemptKey{}).(*AttemptTrace)
	return a
}
func (a *AttemptTrace) Update(fn func(*Attempt)) {
	if a == nil {
		return
	}
	a.t.update(func(q *Query) {
		for i := range q.Attempts {
			if q.Attempts[i].ID == a.id {
				fn(&q.Attempts[i])
				return
			}
		}
	})
}
func (a *AttemptTrace) End(response *dns.Msg, err error) {
	if a == nil {
		return
	}
	a.once.Do(func() {
		a.Update(func(v *Attempt) {
			now := time.Now()
			v.FinishedAt = &now
			v.Response = a.t.capture(response)
			stage := "exchange"
			if v.Connection == nil {
				stage = "dial_or_handshake"
			} else if v.SentAt == nil {
				stage = "send"
			} else if v.Error != nil {
				stage = v.Error.Stage
			} else {
				stage = "read_or_decode"
			}
			v.Error = failure(err, stage)
			if v.Error != nil && v.Error.Kind == "timeout" && response == nil && len(v.Diagnostics) < 16 {
				v.Diagnostics = append(v.Diagnostics, "no_matching_response_before_deadline")
			}
		})
	})
}
func (a *AttemptTrace) Sent(id uint16, err error) {
	a.Update(func(v *Attempt) {
		now := time.Now()
		v.SentAt = &now
		v.WireID = id
		if err != nil {
			v.Error = failure(err, "write")
		}
	})
}
func (a *AttemptTrace) Bind(c *Connection, reused bool) {
	a.Update(func(v *Attempt) { v.Connection = c; v.Reused = reused })
}
func (a *AttemptTrace) Diagnostic(s string) {
	a.Update(func(v *Attempt) {
		if len(v.Diagnostics) < 16 {
			v.Diagnostics = append(v.Diagnostics, clip(s, 1024))
		}
	})
}
