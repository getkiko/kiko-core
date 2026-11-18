package script

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	E "github.com/sagernet/sing/common/exceptions"
)

// Rule and dns scripts run on the connection path: the `script` condition of a route or DNS
// rule and the `script` action of a DNS rule. They are synchronous, bounded by a short
// timeout (default 100 ms), cached by script hash and input, and every failure resolves to a
// defined outcome, so a rule never waits on a broken script for long.
const (
	// RuleCacheTTL is how long the outcome of a rule or dns script is reused for the same
	// script and input; RuleErrorTTL is the same for a failed run.
	RuleCacheTTL = 60 * time.Second
	RuleErrorTTL = 10 * time.Second
	// RuleCacheEntries bounds the cache.
	RuleCacheEntries = 4096
	// RuleWaitLimit is how long a call waits for a free rule slot before it fails.
	RuleWaitLimit = 50 * time.Millisecond
	// RuleBreakerFailures consecutive failed runs of a script switch it off for
	// RuleBreakerPause: its calls fail at once, without running it.
	RuleBreakerFailures = 5
	RuleBreakerPause    = 30 * time.Second

	maxRuleOutput    = 64 << 10
	maxDNSAddresses  = 32
	maxDNSTTL        = 24 * 60 * 60
	defaultDNSTTL    = 60
	maxRuleInputText = 4 << 10
)

// RuleInput is the $request of a rule or dns script. Fields the connection lacks are empty.
type RuleInput struct {
	// Domain is the destination host name or the DNS question name, lower case without the
	// trailing dot; IP is the destination address when it is already known.
	Domain string
	IP     string
	Port   uint16
	// Network is tcp or udp.
	Network string
	// Protocol is the sniffed protocol.
	Protocol    string
	Inbound     string
	InboundType string
	SourceIP    string
	// ProcessName, ProcessPath and User are known only when process lookup is on.
	ProcessName string
	ProcessPath string
	User        string
	// QueryType is the DNS question type ("A", "AAAA", "HTTPS"...), set for DNS rules.
	QueryType string
}

func (r *RuleInput) key() string {
	return strings.Join([]string{
		r.Domain, r.IP, strconv.Itoa(int(r.Port)), r.Network, r.Protocol, r.Inbound, r.InboundType,
		r.SourceIP, r.ProcessName, r.ProcessPath, r.User, r.QueryType,
	}, "\x00")
}

// clip returns a copy of r with every text field cut to a sane length.
func (r *RuleInput) clip() *RuleInput {
	c := *r
	for _, f := range []*string{&c.Domain, &c.IP, &c.Network, &c.Protocol, &c.Inbound, &c.InboundType, &c.SourceIP, &c.ProcessName, &c.ProcessPath, &c.User, &c.QueryType} {
		if len(*f) > maxRuleInputText {
			*f = (*f)[:maxRuleInputText]
		}
	}
	return &c
}

func (r *RuleInput) object(rt *goja.Runtime) *goja.Object {
	obj := rt.NewObject()
	_ = obj.Set("domain", r.Domain)
	_ = obj.Set("hostname", r.Domain)
	_ = obj.Set("ip", r.IP)
	_ = obj.Set("port", int(r.Port))
	_ = obj.Set("network", r.Network)
	_ = obj.Set("protocol", r.Protocol)
	_ = obj.Set("inbound", r.Inbound)
	_ = obj.Set("inboundType", r.InboundType)
	_ = obj.Set("sourceIp", r.SourceIP)
	_ = obj.Set("processName", r.ProcessName)
	_ = obj.Set("processPath", r.ProcessPath)
	_ = obj.Set("user", r.User)
	_ = obj.Set("queryType", r.QueryType)
	return obj
}

// RuleOutcome is the result of a rule script for one input.
type RuleOutcome struct {
	// Matched is the condition's value; false whenever Err is set.
	Matched bool
	// Err is why the script produced no value: an error, a timeout, a pause, a missing script.
	Err string
	// Cached reports that the outcome came from the cache (or from an identical call in
	// flight) instead of a run.
	Cached bool
	// Duration is the time of the run that produced the outcome.
	Duration time.Duration
}

// DNSKind is the kind of a DNS script decision.
type DNSKind string

const (
	// DNSPass continues with the next rule.
	DNSPass DNSKind = "pass"
	// DNSAnswer answers the query with Addresses (or Rcode).
	DNSAnswer DNSKind = "answer"
	// DNSServer sends the query to the DNS server named Server.
	DNSServer DNSKind = "server"
)

// DNSDecision is what a dns script decided.
type DNSDecision struct {
	Kind      DNSKind
	Rcode     int
	Addresses []netip.Addr
	TTL       uint32
	Server    string
}

// Summary is a short text of the decision for logs and the DNS monitor.
func (d DNSDecision) Summary() string {
	switch d.Kind {
	case DNSServer:
		return "server " + d.Server
	case DNSAnswer:
		if d.Rcode != 0 {
			return rcodeName(d.Rcode)
		}
		parts := make([]string, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			parts = append(parts, a.String())
		}
		if len(parts) == 0 {
			return "empty answer"
		}
		return strings.Join(parts, ", ")
	}
	return "pass"
}

// DNSOutcome is the result of a dns script for one input.
type DNSOutcome struct {
	Decision DNSDecision
	// Err is why the script produced no decision; the decision is DNSPass then.
	Err      string
	Cached   bool
	Duration time.Duration
}

var rcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func rcodeName(code int) string {
	if code >= 0 && code < len(rcodeNames) {
		return rcodeNames[code]
	}
	return strconv.Itoa(code)
}

// ParseRuleOutput interprets the JSON text a rule script passed to $done: a boolean, or an
// object whose "matched" (or "match") is a boolean. No value means false.
func ParseRuleOutput(output string) (bool, error) {
	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return false, nil
	}
	if len(output) > maxRuleOutput {
		return false, E.New("$done value is too large")
	}
	var value any
	if err := json.Unmarshal([]byte(output), &value); err != nil {
		return false, E.New("$done value is not JSON")
	}
	switch v := value.(type) {
	case bool:
		return v, nil
	case map[string]any:
		for _, key := range []string{"matched", "match"} {
			if raw, ok := v[key]; ok {
				b, isBool := raw.(bool)
				if !isBool {
					return false, E.New("$done ", key, " must be a boolean")
				}
				return b, nil
			}
		}
		return false, nil
	}
	return false, E.New("a rule script must call $done with true or false")
}

// ParseDNSOutput interprets the JSON text a dns script passed to $done. An object with
// "addresses" (an array, or "address" for one) answers the query, with "ttl" in seconds
// (default 60, at most one day); "rcode" (a name such as NXDOMAIN or a code 0-5) answers with
// that response code; "server" sends the query to the named DNS server. No value, or an
// object with none of these, passes to the next rule.
func ParseDNSOutput(output string) (DNSDecision, error) {
	pass := DNSDecision{Kind: DNSPass}
	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return pass, nil
	}
	if len(output) > maxRuleOutput {
		return pass, E.New("$done value is too large")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &fields); err != nil {
		return pass, E.New("a dns script must call $done with an object")
	}
	// A null value is an absent key.
	for key, raw := range fields {
		if strings.TrimSpace(string(raw)) == "null" {
			delete(fields, key)
		}
	}
	var addresses []string
	_, hasAddresses := fields["addresses"]
	if hasAddresses {
		if err := json.Unmarshal(fields["addresses"], &addresses); err != nil {
			return pass, E.New("addresses must be an array of strings")
		}
	}
	if raw, ok := fields["address"]; ok {
		var one string
		if err := json.Unmarshal(raw, &one); err != nil {
			return pass, E.New("address must be a string")
		}
		addresses = append(addresses, one)
		hasAddresses = true
	}
	_, hasRcode := fields["rcode"]
	var server string
	if raw, ok := fields["server"]; ok {
		if err := json.Unmarshal(raw, &server); err != nil || !validServerTag(server) {
			return pass, E.New("server must be a DNS server tag")
		}
	}
	if server != "" && (hasAddresses || hasRcode) {
		return pass, E.New("server cannot be combined with addresses or rcode")
	}
	if server != "" {
		return DNSDecision{Kind: DNSServer, Server: server}, nil
	}
	decision := DNSDecision{Kind: DNSAnswer, TTL: defaultDNSTTL}
	if raw, ok := fields["ttl"]; ok {
		var ttl float64
		if err := json.Unmarshal(raw, &ttl); err != nil || ttl < 0 || ttl > maxDNSTTL {
			return pass, E.New("ttl must be between 0 and ", maxDNSTTL, " seconds")
		}
		decision.TTL = uint32(ttl)
	}
	if hasRcode {
		code, err := parseRcode(fields["rcode"])
		if err != nil {
			return pass, err
		}
		if code != 0 && hasAddresses {
			return pass, E.New("rcode ", rcodeName(code), " cannot be combined with addresses")
		}
		decision.Rcode = code
	}
	if !hasAddresses && !hasRcode {
		return pass, nil
	}
	if len(addresses) > maxDNSAddresses {
		return pass, E.New("too many addresses (at most ", maxDNSAddresses, ")")
	}
	for _, text := range addresses {
		addr, err := netip.ParseAddr(strings.TrimSpace(text))
		if err != nil {
			return pass, E.New("invalid address: ", text)
		}
		decision.Addresses = append(decision.Addresses, addr.Unmap())
	}
	return decision, nil
}

// validServerTag accepts the characters DNS server tags may carry besides those of script
// tags (a space and the like are refused).
func validServerTag(tag string) bool {
	if tag == "" || len(tag) > 128 {
		return false
	}
	for _, r := range tag {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func parseRcode(raw json.RawMessage) (int, error) {
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		for code, candidate := range rcodeNames {
			if strings.EqualFold(name, candidate) {
				return code, nil
			}
		}
		return 0, E.New("unknown rcode: ", name)
	}
	var code float64
	if err := json.Unmarshal(raw, &code); err != nil || code != float64(int(code)) || code < 0 || int(code) >= len(rcodeNames) {
		return 0, E.New("rcode must be a name or a number from 0 to ", len(rcodeNames)-1)
	}
	return int(code), nil
}

// ruleRun is the cached part of a run.
type ruleRun struct {
	output   string
	err      string
	duration time.Duration
}

type ruleEntry struct {
	done    chan struct{}
	run     ruleRun
	expires time.Time
}

// ruleCache keeps the outcomes of rule and dns scripts by script hash and input, and joins
// identical calls that arrive while one is running.
type ruleCache struct {
	mu      sync.Mutex
	entries map[string]*ruleEntry
}

func newRuleCache() *ruleCache { return &ruleCache{entries: map[string]*ruleEntry{}} }

// enter returns the entry of key and whether the caller has to run the script for it.
func (c *ruleCache) enter(key string, now time.Time) (entry *ruleEntry, leader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil {
		select {
		case <-e.done:
			if now.Before(e.expires) {
				return e, false
			}
		default:
			return e, false
		}
	}
	if len(c.entries) >= RuleCacheEntries {
		c.evictLocked(now)
	}
	e := &ruleEntry{done: make(chan struct{})}
	c.entries[key] = e
	return e, true
}

// evictLocked drops expired entries and, when the cache is still full, a quarter of it.
func (c *ruleCache) evictLocked(now time.Time) {
	for key, e := range c.entries {
		select {
		case <-e.done:
			if !now.Before(e.expires) {
				delete(c.entries, key)
			}
		default:
		}
	}
	drop := len(c.entries) - RuleCacheEntries*3/4
	for key, e := range c.entries {
		if drop <= 0 {
			break
		}
		select {
		case <-e.done:
			delete(c.entries, key)
			drop--
		default:
		}
	}
}

// finish publishes the run to the waiters. A run that must not be reused (ttl 0) leaves the
// cache at once.
func (c *ruleCache) finish(key string, e *ruleEntry, run ruleRun, ttl time.Duration, now time.Time) {
	c.mu.Lock()
	e.run = run
	e.expires = now.Add(ttl)
	if ttl <= 0 && c.entries[key] == e {
		delete(c.entries, key)
	}
	c.mu.Unlock()
	close(e.done)
}

func (c *ruleCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ruleCache) clear() {
	c.mu.Lock()
	c.entries = map[string]*ruleEntry{}
	c.mu.Unlock()
}

// RunRule evaluates the rule script tag for in. It never fails: a missing script, a script
// of another type, a failed or timed out run, a paused script and a busy runtime all give an
// outcome with Err set and Matched false.
func (m *Manager) RunRule(tag string, in *RuleInput) *RuleOutcome {
	run, cached := m.runRuleKind(tag, PhaseRule, in)
	out := &RuleOutcome{Cached: cached, Duration: run.duration}
	if run.err != "" {
		out.Err = run.err
		return out
	}
	matched, err := ParseRuleOutput(run.output)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	out.Matched = matched
	return out
}

// RunDNS evaluates the dns script tag for in; failures give a DNSPass decision with Err set.
func (m *Manager) RunDNS(tag string, in *RuleInput) *DNSOutcome {
	run, cached := m.runRuleKind(tag, PhaseDNS, in)
	out := &DNSOutcome{Cached: cached, Duration: run.duration, Decision: DNSDecision{Kind: DNSPass}}
	if run.err != "" {
		out.Err = run.err
		return out
	}
	decision, err := ParseDNSOutput(run.output)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	out.Decision = decision
	return out
}

// RuleScriptState reports whether a script of the given type exists in the active set.
func (m *Manager) RuleScriptState(tag string, phase Phase) (found bool, typeOK bool) {
	sc := m.current.Load().Lookup(tag)
	if sc == nil {
		return false, false
	}
	return true, sc.cfg.Type == phase
}

func (m *Manager) runRuleKind(tag string, phase Phase, in *RuleInput) (ruleRun, bool) {
	sc := m.current.Load().Lookup(tag)
	if sc == nil {
		return ruleRun{err: "unknown script: " + tag}, false
	}
	if sc.cfg.Type != phase {
		return ruleRun{err: "script " + tag + " is not a " + string(phase) + " script"}, false
	}
	in = in.clip()
	key := sc.hash + "\x00" + sc.cfg.Tag + "\x00" + in.key()
	now := m.ruleNow()
	entry, leader := m.ruleCache.enter(key, now)
	if !leader {
		return m.awaitRule(sc, entry)
	}
	run := m.runRuleScript(sc, in)
	ttl := RuleCacheTTL
	if run.err != "" {
		ttl = RuleErrorTTL
		if transientRuleError(run.err) {
			ttl = 0
		}
	}
	m.ruleCache.finish(key, entry, run, ttl, now)
	return run, false
}

// awaitRule waits for the run another call of the same input is doing (or reads a cached one).
func (m *Manager) awaitRule(sc *Script, e *ruleEntry) (ruleRun, bool) {
	select {
	case <-e.done:
		return e.run, true
	default:
	}
	timer := time.NewTimer(sc.timeoutOrDefault() + RuleWaitLimit + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-e.done:
		return e.run, true
	case <-timer.C:
		return ruleRun{err: "timed out waiting for the running script"}, false
	case <-m.life.Done():
		return ruleRun{err: "script runtime closed"}, false
	}
}

func (sc *Script) timeoutOrDefault() time.Duration {
	if sc.cfg.Timeout > 0 {
		return sc.cfg.Timeout
	}
	return DefaultRuleTimeout
}

// Errors that say nothing about the input are not cached.
func transientRuleError(text string) bool {
	switch text {
	case errBusy, errCanceled, errPausedShort, errBreaker:
		return true
	}
	return false
}

const (
	errBusy        = "script runtime busy"
	errCanceled    = "canceled"
	errPausedShort = "paused after repeated failures"
	errBreaker     = "switched off after repeated failures"
)

func (m *Manager) ruleNow() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
}

// runRuleScript runs sc once for in (no cache) and reduces the result to a ruleRun.
func (m *Manager) runRuleScript(sc *Script, in *RuleInput) ruleRun {
	st := sc.state
	now := m.ruleNow()
	st.mu.Lock()
	blocked := now.Before(st.ruleBlocked)
	st.mu.Unlock()
	if blocked {
		return ruleRun{err: errBreaker}
	}
	res := m.runWith(m.life, sc, &Input{Rule: in}, runOptions{slots: m.ruleSlots, wait: RuleWaitLimit})
	run := ruleRun{duration: res.Duration}
	failed := false
	switch res.Action {
	case ActionNone:
		if len(res.Output) > maxRuleOutput {
			// Keep the cache small: the value would be rejected on parse anyway.
			run.err = "$done value is too large"
		} else {
			run.output = res.Output
		}
	case ActionError:
		run.err, failed = res.Error, true
	case ActionTimeout:
		run.err, failed = res.Error, true
	case ActionLimit:
		run.err, failed = res.Error, true
	case ActionPaused:
		run.err = errPausedShort
	case ActionSkipped:
		switch res.Reason {
		case ReasonCanceled:
			run.err = errCanceled
		default:
			run.err = errBusy
		}
	default:
		run.err = "unexpected script action: " + string(res.Action)
	}
	st.mu.Lock()
	switch {
	case failed:
		st.ruleFails++
		if st.ruleFails >= RuleBreakerFailures {
			st.ruleBlocked = now.Add(RuleBreakerPause)
			st.ruleFails = 0
		}
	case run.err == "":
		st.ruleFails = 0
	}
	st.mu.Unlock()
	return run
}

// RuleCacheLen reports the number of cached outcomes (tests and status).
func (m *Manager) RuleCacheLen() int { return m.ruleCache.size() }
