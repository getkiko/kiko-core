package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"hash"
	"hash/fnv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

// parallelTransport is a DNS route action with several servers: it asks
// all of them at once and answers with the first successful response.
//
// A response is successful when it carries NOERROR (with or without
// records) or NXDOMAIN: both are definite answers. Errors and the other
// rcodes (SERVFAIL, REFUSED, ...) never win while another server is still
// pending; once one server succeeds the others are canceled. A server
// that only knows some names says so for the others with an NXDOMAIN
// that is not an answer: a hosts server's, and the rcode error of a
// Tailscale, OpenConnect or OpenVPN server without default resolvers;
// that NXDOMAIN does not win either. When every server fails, the first
// DNS response received is returned (the client does not cache it), else
// the joined errors; a declining NXDOMAIN only when every server
// declined.
//
// The client sees one transport, so the cache, RDRC and the rule's
// options (strategy, client subnet, rewrite TTL, timeout) apply to the
// combined query, keyed by the combined tag. FakeIP servers cannot be
// members (rejected when rules are built).
type parallelTransport struct {
	tag     string
	members []adapter.DNSTransport
	manager adapter.DNSTransportManager
}

var _ adapter.DNSTransport = (*parallelTransport)(nil)

func (t *parallelTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *parallelTransport) Close() error                                   { return nil }
func (t *parallelTransport) Type() string                                   { return C.DNSTypeParallel }
func (t *parallelTransport) Tag() string                                    { return t.tag }
func (t *parallelTransport) Reset()                                         {}

func (t *parallelTransport) Dependencies() []string {
	return common.Map(t.members, adapter.DNSTransport.Tag)
}

type parallelResult struct {
	transport adapter.DNSTransport
	response  *mDNS.Msg
	// declined is a response saying only that the name is not the
	// server's, which is no answer.
	declined bool
	err      error
}

// parallelAccepted reports a response that ends a concurrent query.
func parallelAccepted(response *mDNS.Msg) bool {
	return response != nil && (response.Rcode == mDNS.RcodeSuccess || response.Rcode == mDNS.RcodeNameError)
}

func (t *parallelTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	dnsmonitor.Candidates(ctx, t.Dependencies())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan parallelResult, len(t.members))
	for _, member := range t.members {
		go func(member adapter.DNSTransport, message *mDNS.Msg) {
			response, declined, err := t.exchangeMember(ctx, member, message)
			results <- parallelResult{transport: member, response: response, declined: declined, err: err}
		}(member, message.Copy())
	}
	var (
		failed   *parallelResult
		declined *parallelResult
		errs     []error
	)
	for range t.members {
		var result parallelResult
		select {
		case result = <-results:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if result.err == nil && !result.declined && parallelAccepted(result.response) {
			cancel()
			recordParallelAnswer(ctx, result.transport)
			return result.response, nil
		}
		switch {
		case result.err != nil:
			errs = append(errs, E.Cause(result.err, result.transport.Tag()))
		case result.response == nil:
		case result.declined:
			if declined == nil {
				declined = &result
			}
		case failed == nil:
			failed = &result
		}
	}
	if failed == nil && len(errs) == 0 {
		// Every server declined: none has the name. With a server
		// that could not be asked, that is not known (and an NXDOMAIN
		// would be cached).
		failed = declined
	}
	if failed != nil {
		recordParallelAnswer(ctx, failed.transport)
		return failed.response, nil
	}
	if len(errs) == 0 {
		return nil, E.New("no response from ", t.tag)
	}
	return nil, E.Errors(errs...)
}

// recordParallelAnswer names the server that answered a concurrent query
// in the DNS monitor and a policy test.
func recordParallelAnswer(ctx context.Context, member adapter.DNSTransport) {
	dnsmonitor.Resolver(ctx, member.Tag(), member.Type())
	if trace := policyTraceFrom(ctx); trace != nil {
		var detour string
		if configured, ok := member.(interface{ DNSMonitorDetour() (string, bool) }); ok {
			detour, _ = configured.DNSMonitorDetour()
		}
		trace.setServer(member.Tag(), detour)
	}
}

// exchangeMember asks member; declined tells a response that only says
// the name is not member's.
func (t *parallelTransport) exchangeMember(ctx context.Context, member adapter.DNSTransport, message *mDNS.Msg) (response *mDNS.Msg, declined bool, err error) {
	release := adapter.Acquire(t.manager, member)
	defer release()
	ctx = adapter.ContextWithDNSTransportTag(ctx, member.Tag())
	ctx = dnsmonitor.WithAttemptResolver(ctx, member.Tag(), member.Type())
	ctx, attempt := monitorTransport(ctx, member)
	response, err = member.Exchange(ctx, message)
	attempt.End(response, err)
	if err != nil {
		var rcodeError RcodeError
		if errors.As(err, &rcodeError) {
			// Transports answering names of their own (Tailscale,
			// OpenConnect, OpenVPN) fail the others with an rcode.
			return FixedResponseStatus(message, int(rcodeError)), true, nil
		}
		return nil, false, err
	}
	if response == nil {
		return nil, false, E.New("empty response")
	}
	// A hosts server answers NXDOMAIN for every name it does not list.
	return response, member.Type() == C.DNSTypeHosts && response.Rcode != mDNS.RcodeSuccess, nil
}

func (t *parallelTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

// parallelEnvironmentHash is the cache environment of a concurrent query:
// the environments of its members that depend on the network (local,
// DHCP, ...), so a network change does not reuse their answers. Without
// such a member it is 0, as for a single remote server.
func (c *Client) parallelEnvironmentHash(t *parallelTransport) uint64 {
	var digest hash.Hash64
	for _, member := range t.members {
		if _, withEnvironment := member.(adapter.DNSTransportWithEnvironment); !withEnvironment {
			continue
		}
		if digest == nil {
			digest = fnv.New64a()
		}
		digest.Write([]byte(member.Tag()))
		digest.Write([]byte{0})
		var hashBytes [8]byte
		binary.BigEndian.PutUint64(hashBytes[:], c.environmentHash(member))
		digest.Write(hashBytes[:])
	}
	if digest == nil {
		return 0
	}
	return digest.Sum64()
}

// monitorResolver records the transport a query uses; a concurrent query
// also lists its servers, so a cached answer still shows them.
func monitorResolver(ctx context.Context, transport adapter.DNSTransport) context.Context {
	ctx = dnsmonitor.WithResolver(ctx, transport.Tag(), transport.Type())
	if parallel, isParallel := transport.(*parallelTransport); isParallel {
		dnsmonitor.Candidates(ctx, parallel.Dependencies())
	}
	return ctx
}

// routeTransport returns the transport of a DNS route action: its server,
// or a parallel transport of its servers that are loaded. FakeIP members
// are left out (rule building rejects them).
func (r *Router) routeTransport(action *R.RuleActionDNSRoute) (adapter.DNSTransport, bool) {
	if len(action.Servers) == 0 {
		return r.transport.Transport(action.Server)
	}
	members := make([]adapter.DNSTransport, 0, len(action.Servers))
	for _, tag := range action.Servers {
		transport, loaded := r.transport.Transport(tag)
		if !loaded {
			r.logger.Error("transport not found: ", tag)
			continue
		}
		if transport.Type() == C.DNSTypeFakeIP {
			continue
		}
		members = append(members, transport)
	}
	switch len(members) {
	case 0:
		return nil, false
	case 1:
		return members[0], true
	}
	return &parallelTransport{tag: action.Server, members: members, manager: r.transport}, true
}

// validateParallelDNSRules checks the servers of route actions with
// several servers: each must exist and none may be FakeIP, whose answers
// cannot be mixed with real ones.
func validateParallelDNSRules(rules []option.DNSRule, transportManager adapter.DNSTransportManager) error {
	if transportManager == nil {
		return nil
	}
	for i, rule := range rules {
		if dnsRuleActionType(rule) != C.RuleActionTypeRoute {
			continue
		}
		var servers []string
		switch rule.Type {
		case "", C.RuleTypeDefault:
			servers = rule.DefaultOptions.RouteOptions.Servers
		case C.RuleTypeLogical:
			servers = rule.LogicalOptions.RouteOptions.Servers
		}
		if len(common.Uniq(servers)) < 2 {
			continue
		}
		for _, server := range servers {
			transport, loaded := transportManager.Transport(server)
			if !loaded {
				return E.New("dns rule[", i, "]: server not found: ", server)
			}
			if transport.Type() == C.DNSTypeFakeIP {
				return E.New("dns rule[", i, "]: fakeip server cannot be queried with other servers: ", server)
			}
		}
	}
	return nil
}
