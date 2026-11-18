package group

import (
	"context"
	"io"
	"math"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	"github.com/sagernet/sing-box/common/grouphealth"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// Group is the runtime of the fallback, loadbalance and smart policy
// groups: members, health checks, what routed connections report, and
// interruption. How a member is chosen is its strategy.
type Group struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	tags                         []string
	members                      []adapter.Outbound
	strategy                     groupStrategy
	link                         string
	interval                     time.Duration
	timeout                      time.Duration
	idleTimeout                  time.Duration
	maxFailures                  int
	interruptExternalConnections bool
	interruptGroup               *interrupt.Group
	memberAccess                 sync.Mutex
	memberInterrupt              map[string]*interrupt.Group
	history                      *urltest.HistoryStorage
	health                       *grouphealth.Store
	unsubscribe                  func()
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	access                       sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      atomic.Bool
	closed                       bool
	lastActive                   common.TypedValue[time.Time]
	checking                     atomic.Bool
	batches                      atomic.Int32
	checkAccess                  sync.Mutex
	probing                      sync.Map
	recovering                   sync.Map
	selectAccess                 sync.Mutex
	current                      [2]common.TypedValue[adapter.Outbound]
	switchedAt                   [2]time.Time
	evaluatedAt                  atomic.Int64
}

var (
	_ adapter.OutboundGroup             = (*Group)(nil)
	_ adapter.ContextualOutboundGroup   = (*Group)(nil)
	_ adapter.URLTestGroup              = (*Group)(nil)
	_ adapter.GroupCloseFeedback        = (*Group)(nil)
	_ adapter.MemberConnectionAttacher  = (*Group)(nil)
	_ adapter.MemberFlowTrackerOutbound = (*Group)(nil)
	_ adapter.GroupStatusReporter       = (*Group)(nil)
	_ adapter.StatefulGroup             = (*Group)(nil)
	_ adapter.FlowTrackerOutbound       = (*Group)(nil)
	_ adapter.InterfaceUpdateListener   = (*Group)(nil)
	_ adapter.Referrer                  = (*Group)(nil)
)

// groupStrategy chooses a group's members.
type groupStrategy interface {
	mode() string
	// name is the load balance strategy, "" for others.
	name() string
	// hasCurrent tells whether the group has one current member per
	// network, chosen by choose; otherwise each connection is given one
	// by pick.
	hasCurrent() bool
	choose(g *Group, network string, current adapter.Outbound, now time.Time) adapter.Outbound
	pick(g *Group, network string, metadata *adapter.InboundContext, dryRun bool) adapter.Outbound
	// probeSet are the members a periodic check probes.
	probeSet(g *Group) []adapter.Outbound
	// learns tells whether the strategy scores members by how routed
	// connections close.
	learns() bool
	inherit(old groupStrategy)
}

const (
	// recoveryFirst is the first delay before a down member is probed
	// again; it doubles up to the interval.
	recoveryFirst = 15 * time.Second
	// evaluateEvery is how often routed connections make a group with a
	// current member reconsider it.
	evaluateEvery = 15 * time.Second
)

func newGroup(ctx context.Context, logger log.ContextLogger, groupType, tag string, tags []string, health option.GroupHealthCheckOptions, interruptExternalConnections bool, strategy groupStrategy) (*Group, error) {
	if len(tags) == 0 {
		return nil, E.New("missing tags")
	}
	for i, it := range tags {
		if slices.Contains(tags[:i], it) {
			return nil, E.New("duplicate tag: ", it)
		}
	}
	g := &Group{
		Adapter:                      outbound.NewAdapter(groupType, tag, []string{N.NetworkTCP, N.NetworkUDP}, tags),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         tags,
		strategy:                     strategy,
		link:                         health.URL,
		interval:                     time.Duration(health.Interval),
		timeout:                      time.Duration(health.Timeout),
		idleTimeout:                  time.Duration(health.IdleTimeout),
		maxFailures:                  int(health.MaxFailures),
		interruptExternalConnections: interruptExternalConnections,
		interruptGroup:               interrupt.NewGroup(),
		memberInterrupt:              map[string]*interrupt.Group{},
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		pause:                        service.FromContext[pause.Manager](ctx),
		close:                        make(chan struct{}),
	}
	if g.interval == 0 {
		g.interval = C.DefaultURLTestInterval
	}
	if g.timeout == 0 {
		g.timeout = C.DefaultGroupProbeTimeout
	}
	if g.idleTimeout == 0 {
		g.idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if g.maxFailures == 0 {
		g.maxFailures = C.DefaultGroupMaxFailures
	}
	if g.interval > g.idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	g.health = grouphealth.For(g.history)
	return g, nil
}

func networkIndex(network string) int {
	if network == N.NetworkUDP {
		return 1
	}
	return 0
}

func supports(member adapter.Outbound, network string) bool {
	return common.Contains(member.Network(), network)
}

func (g *Group) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		members := make([]adapter.Outbound, 0, len(g.tags))
		for i, tag := range g.tags {
			detour, loaded := g.outbound.Outbound(tag)
			if !loaded {
				return E.New("outbound ", i, " not found: ", tag)
			}
			members = append(members, detour)
		}
		g.members = members
	case adapter.StartStateStarted:
		g.lastActive.Store(time.Now())
		g.started.Store(true)
		g.access.Lock()
		if !g.closed {
			g.unsubscribe = g.health.Subscribe(g.memberChanged)
		}
		g.access.Unlock()
		go func() {
			g.checkAccess.Lock()
			defer g.checkAccess.Unlock()
			g.probe(g.ctx, g.members, false)
			g.PerformUpdateCheck()
		}()
		scope.Add(g.Close)
	}
	return nil
}

func (g *Group) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	if g.ticker != nil {
		g.ticker.Stop()
		g.ticker = nil
		g.pause.UnregisterCallback(g.pauseCallback)
		g.pauseCallback = nil
	}
	close(g.close)
	if g.unsubscribe != nil {
		g.unsubscribe()
		g.unsubscribe = nil
	}
	return nil
}

// memberChanged reconsiders the members whose real tag a probe found
// changed, by this group or any other group or URL test sharing it. A
// member that is a group is matched by every outbound under it, not by
// its current one only: its choice may already have moved off tag, or
// fall back on tag once it has nothing left.
func (g *Group) memberChanged(tag string, state adapter.GroupMemberState) {
	if g.isClosed() {
		return
	}
	var affected bool
	for _, member := range g.members {
		if !g.reaches(member, tag, maxNesting) {
			continue
		}
		affected = true
		if member.Tag() == tag {
			if state == adapter.GroupMemberDown {
				g.memberDown(member)
			}
			continue
		}
		if g.batches.Load() == 0 {
			// Nested groups fail over first, innermost first, so that
			// this group sees them as they are then.
			refreshNested(member, maxNesting)
		}
		// A group member is down when what it uses now is.
		if state == adapter.GroupMemberDown && g.state(member, N.NetworkTCP) == adapter.GroupMemberDown {
			g.memberDown(member)
		}
	}
	if affected && g.batches.Load() == 0 {
		// The group's own test of its members, while it runs,
		// reconsiders them once all are tested.
		g.PerformUpdateCheck()
	}
}

// maxNesting bounds how deep nested groups are followed.
const maxNesting = 8

// reaches reports whether outbound is tag or a group with tag under it.
func (g *Group) reaches(outbound adapter.Outbound, tag string, depth int) bool {
	if outbound == nil {
		return false
	}
	if outbound.Tag() == tag {
		return true
	}
	if depth == 0 {
		return false
	}
	if nested, isNested := outbound.(*Group); isNested {
		for _, member := range nested.members {
			if g.reaches(member, tag, depth-1) {
				return true
			}
		}
		return false
	}
	group, isGroup := outbound.(adapter.OutboundGroup)
	if !isGroup {
		return false
	}
	for _, memberTag := range group.All() {
		if memberTag == tag {
			return true
		}
		if g.outbound == nil {
			continue
		}
		if member, loaded := g.outbound.Outbound(memberTag); loaded && member != outbound && g.reaches(member, tag, depth-1) {
			return true
		}
	}
	return false
}

// refreshNested reconsiders the policy groups under outbound and then
// outbound itself, when it is one.
func refreshNested(outbound adapter.Outbound, depth int) {
	if depth == 0 {
		return
	}
	switch nested := outbound.(type) {
	case *Group:
		for _, member := range nested.members {
			refreshNested(member, depth-1)
		}
		nested.PerformUpdateCheck()
	case *URLTest:
		refreshFastest(nested)
	}
}

// refreshFastest has a fastest group choose again by the delay history
// as it is now. It does so by itself only on its own checks, which stop
// while it is idle, as once a group it is a member of has left it: that
// group would keep finding it on the member it left for good.
func refreshFastest(nested *URLTest) {
	// Its own check, while it runs, chooses once all are tested.
	if nested.group != nil && !nested.group.checking.Load() {
		nested.PerformUpdateCheck()
	}
}

// refreshFastestOnPath refreshes the fastest groups a connection through
// member goes through now, innermost first.
func refreshFastestOnPath(member adapter.Outbound, network string) {
	var path []*URLTest
	for detour, depth := member, 0; detour != nil && depth < maxNesting; depth++ {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		if fastest, isFastest := detour.(*URLTest); isFastest {
			path = append(path, fastest)
		}
		detour = group.Selected(network)
	}
	for i := len(path) - 1; i >= 0; i-- {
		refreshFastest(path[i])
	}
}

// ProbedTag is the real tag a test through detour measures: RealTag,
// or "" when a group on the way gives each connection a member of its
// own, so that the test may have gone through any of them.
func ProbedTag(detour adapter.Outbound, network string) string {
	for depth := 0; detour != nil && depth <= maxNesting; depth++ {
		if policy, isPolicy := detour.(*Group); isPolicy && !policy.strategy.hasCurrent() {
			return ""
		}
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return detour.Tag()
		}
		detour = group.Selected(network)
	}
	return ""
}

func (g *Group) isClosed() bool {
	g.access.Lock()
	defer g.access.Unlock()
	return g.closed
}

// touch marks the group in use, starting its periodic check.
func (g *Group) touch() {
	g.access.Lock()
	defer g.access.Unlock()
	if !g.started.Load() || g.closed {
		return
	}
	g.lastActive.Store(time.Now())
	if g.ticker != nil {
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *Group) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.checkOutbounds(g.ctx, g.strategy.probeSet(g), false)
	}
}

func (g *Group) checkOutbounds(ctx context.Context, members []adapter.Outbound, force bool) map[string]uint16 {
	if g.checking.Swap(true) {
		return map[string]uint16{}
	}
	defer g.checking.Store(false)
	result := g.probe(ctx, members, force)
	g.PerformUpdateCheck()
	return result
}

// probe tests members, those tested within the interval only when
// forced, and returns their delays by tag.
func (g *Group) probe(ctx context.Context, members []adapter.Outbound, force bool) map[string]uint16 {
	g.batches.Add(1)
	defer g.batches.Add(-1)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	result := map[string]uint16{}
	var access sync.Mutex
	for _, member := range members {
		realTag := RealTag(member, N.NetworkTCP)
		if realTag == "" {
			continue
		}
		if !force {
			if history := g.history.LoadURLTestHistory(realTag); history != nil && time.Since(history.Time) < g.interval {
				result[member.Tag()] = history.Delay
				continue
			}
		}
		b.Go(member.Tag(), func() (any, error) {
			delay, err := g.probeMember(ctx, member)
			if err == nil {
				access.Lock()
				result[member.Tag()] = delay
				access.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	return result
}

// probeMember tests member once, at most one test of a real tag at a
// time, and records the result. A member that is a group is tested by
// its current outbound, so that a test neither passes through the
// group's own choice (a load balance group's rotation) nor counts as
// one of its routed connections.
func (g *Group) probeMember(ctx context.Context, member adapter.Outbound) (uint16, error) {
	target := leafOutbound(member, N.NetworkTCP)
	if target == nil {
		return 0, E.New("missing selected outbound of ", member.Tag())
	}
	realTag := target.Tag()
	if _, loaded := g.probing.LoadOrStore(realTag, struct{}{}); loaded {
		if history := g.history.LoadURLTestHistory(realTag); history != nil {
			return history.Delay, nil
		}
		return 0, E.New("probe in progress")
	}
	defer g.probing.Delete(realTag)
	testCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	done := make(chan urlTestResult, 1)
	go func() {
		delay, err := urltest.URLTest(testCtx, g.link, target)
		done <- urlTestResult{delay, err}
	}()
	var result urlTestResult
	select {
	case result = <-done:
	case <-testCtx.Done():
		result.err = testCtx.Err()
	}
	if g.ctx.Err() != nil {
		return 0, g.ctx.Err()
	}
	if ctx.Err() != nil {
		// The caller gave up, as a client's delay test with a shorter
		// timeout: that says nothing of the member.
		return 0, ctx.Err()
	}
	if result.err != nil {
		g.logger.Debug("outbound ", realTag, " unavailable: ", result.err)
		if g.history != nil {
			g.history.DeleteURLTestHistory(realTag)
		}
	} else {
		g.logger.Debug("outbound ", realTag, " available: ", result.delay, "ms")
		if g.history != nil {
			g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{Time: time.Now(), Delay: result.delay})
		}
	}
	if g.health.ObserveProbe(realTag, result.err) && result.err != nil {
		g.memberDown(member)
	}
	if target != member {
		refreshFastestOnPath(member, N.NetworkTCP)
	}
	return result.delay, result.err
}

// memberDown interrupts the connections of a member that went down in a
// load balance group, and probes it again later.
func (g *Group) memberDown(member adapter.Outbound) {
	if !g.strategy.hasCurrent() {
		g.memberAccess.Lock()
		interruptGroup := g.memberInterrupt[member.Tag()]
		g.memberAccess.Unlock()
		if interruptGroup != nil {
			interruptGroup.Interrupt(g.interruptExternalConnections)
		}
	}
	g.scheduleRecovery(member, recoveryFirst)
}

func (g *Group) scheduleRecovery(member adapter.Outbound, delay time.Duration) {
	if delay > g.interval {
		g.recovering.Delete(member.Tag())
		return
	}
	if _, loaded := g.recovering.LoadOrStore(member.Tag(), struct{}{}); loaded && delay == recoveryFirst {
		return
	}
	time.AfterFunc(delay, func() {
		if g.isClosed() || time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.recovering.Delete(member.Tag())
			return
		}
		if g.health.State(RealTag(member, N.NetworkTCP)) != adapter.GroupMemberDown {
			g.recovering.Delete(member.Tag())
			return
		}
		if _, err := g.probeMember(g.ctx, member); err == nil {
			g.recovering.Delete(member.Tag())
			g.PerformUpdateCheck()
			return
		}
		g.scheduleRecovery(member, delay*2)
	})
}

// confirm probes a suspect member, then reconsiders the selection.
func (g *Group) confirm(member adapter.Outbound) {
	_, _ = g.probeMember(g.ctx, member)
	g.PerformUpdateCheck()
}

func (g *Group) state(member adapter.Outbound, network string) adapter.GroupMemberState {
	realTag := RealTag(member, network)
	if realTag == "" {
		return adapter.GroupMemberDown
	}
	return g.health.State(realTag)
}

// available are the members supporting network that are not down.
func (g *Group) available(network string) []adapter.Outbound {
	var members []adapter.Outbound
	for _, member := range g.members {
		if supports(member, network) && g.state(member, network) != adapter.GroupMemberDown {
			members = append(members, member)
		}
	}
	return members
}

func (g *Group) firstSupporting(network string) adapter.Outbound {
	for _, member := range g.members {
		if supports(member, network) {
			return member
		}
	}
	return nil
}

func (g *Group) isMember(outbound adapter.Outbound) bool {
	return outbound != nil && slices.Contains(g.members, outbound)
}

func (g *Group) All() []string {
	return g.tags
}

func (g *Group) Selected(network string) adapter.Outbound {
	if len(g.members) == 0 {
		return nil
	}
	if g.strategy.hasCurrent() {
		if current := g.current[networkIndex(network)].Load(); current != nil {
			return current
		}
		return g.reselect(network)
	}
	if members := g.available(network); len(members) > 0 {
		return members[0]
	}
	return g.firstSupporting(network)
}

func (g *Group) SelectFor(network string, metadata *adapter.InboundContext, dryRun bool) adapter.Outbound {
	if len(g.members) == 0 {
		return nil
	}
	if g.strategy.hasCurrent() {
		return g.Selected(network)
	}
	return g.strategy.pick(g, network, metadata, dryRun)
}

func (g *Group) Eligible(network string, member adapter.Outbound) bool {
	if !g.isMember(member) || !supports(member, network) {
		return false
	}
	if g.strategy.hasCurrent() {
		return member == g.Selected(network)
	}
	return g.state(member, network) != adapter.GroupMemberDown || len(g.available(network)) == 0
}

// reselect asks the strategy for the current member of network and
// switches to it.
func (g *Group) reselect(network string) adapter.Outbound {
	index := networkIndex(network)
	g.selectAccess.Lock()
	current := g.current[index].Load()
	now := time.Now()
	next := g.strategy.choose(g, network, current, now)
	switched := next != nil && next != current
	if switched {
		g.current[index].Store(next)
		if current != nil {
			g.switchedAt[index] = now
		}
	}
	g.selectAccess.Unlock()
	if !switched {
		return current
	}
	if current != nil {
		g.logger.Info("switch ", network, " to ", next.Tag(), " from ", current.Tag())
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if g.health.State(RealTag(next, network)) == adapter.GroupMemberUnknown && g.started.Load() {
		go g.confirm(next)
	}
	if g.history != nil {
		g.history.NotifyUpdated()
	}
	return next
}

func (g *Group) PerformUpdateCheck() {
	g.evaluatedAt.Store(time.Now().UnixNano())
	if !g.strategy.hasCurrent() {
		if g.history != nil {
			g.history.NotifyUpdated()
		}
		return
	}
	g.reselect(N.NetworkTCP)
	g.reselect(N.NetworkUDP)
}

// URLTest tests every member and returns their delays by tag.
func (g *Group) URLTest(ctx context.Context) (map[string]uint16, error) {
	g.checkAccess.Lock()
	defer g.checkAccess.Unlock()
	result := g.probe(ctx, g.members, true)
	g.PerformUpdateCheck()
	return result, nil
}

func (g *Group) CheckOutbounds() {
	g.checkAccess.Lock()
	defer g.checkAccess.Unlock()
	g.checkOutbounds(g.ctx, g.members, true)
}

func (g *Group) InterfaceUpdated(ctx context.Context) {
	if !g.started.Load() || g.pause.IsDevicePaused() || g.pause.IsNetworkPaused() {
		return
	}
	go func() {
		g.checkAccess.Lock()
		defer g.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		g.checkOutbounds(ctx, g.members, true)
	}()
}

func (g *Group) References() []string {
	if !g.strategy.hasCurrent() {
		return g.tags
	}
	var references []string
	for i := range g.current {
		if current := g.current[i].Load(); current != nil && !slices.Contains(references, current.Tag()) {
			references = append(references, current.Tag())
		}
	}
	return references
}

func (g *Group) AttachConnection(closer io.Closer) func() {
	g.touch()
	return g.interruptGroup.Add(closer, true)
}

func (g *Group) memberInterruptGroup(tag string) *interrupt.Group {
	g.memberAccess.Lock()
	defer g.memberAccess.Unlock()
	interruptGroup := g.memberInterrupt[tag]
	if interruptGroup == nil {
		interruptGroup = interrupt.NewGroup()
		g.memberInterrupt[tag] = interruptGroup
	}
	return interruptGroup
}

func (g *Group) AttachMemberConnection(member adapter.Outbound, closer io.Closer) func() {
	removeGroup := g.AttachConnection(closer)
	if g.strategy.hasCurrent() || member == nil {
		return removeGroup
	}
	removeMember := g.memberInterruptGroup(member.Tag()).Add(closer, true)
	return func() {
		removeGroup()
		removeMember()
	}
}

// MemberFlowTrackerFactory tracks a forwarded flow through member of a
// load balance group, which interrupts it when member goes down.
func (g *Group) MemberFlowTrackerFactory(member adapter.Outbound) func() tun.FlowTracker {
	if g.strategy.hasCurrent() || member == nil {
		return nil
	}
	token := g.memberInterruptGroup(member.Tag()).Begin()
	return func() tun.FlowTracker { return token.NewFlowTracker(true) }
}

func (g *Group) FlowTrackerFactory() func() tun.FlowTracker {
	g.touch()
	token := g.interruptGroup.Begin()
	return func() tun.FlowTracker { return token.NewFlowTracker(true) }
}

func (g *Group) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	token := g.interruptGroup.Begin()
	g.touch()
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	member := g.SelectFor(N.NetworkName(network), dialMetadata(ctx, network, destination), false)
	if member == nil {
		return nil, E.New("missing supported outbound")
	}
	ctx = dnsmonitor.WithOutbound(dnsmonitor.WithOutbound(ctx, g.Tag()), member.Tag())
	start := time.Now()
	conn, err := member.DialContext(ctx, network, destination)
	g.ReportDial(member, adapter.ContextFrom(ctx), adapter.GroupDialReport{Network: N.NetworkName(network), Latency: time.Since(start), Err: err})
	if err != nil {
		g.logger.ErrorContext(ctx, err)
		return nil, err
	}
	dnsmonitor.Remember(ctx, conn)
	wrapped, err := token.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx))
	if err != nil {
		return nil, err
	}
	dnsmonitor.Alias(ctx, conn, wrapped)
	return wrapped, nil
}

func (g *Group) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	token := g.interruptGroup.Begin()
	g.touch()
	member := g.SelectFor(N.NetworkUDP, dialMetadata(ctx, N.NetworkUDP, destination), false)
	if member == nil {
		return nil, E.New("missing supported outbound")
	}
	ctx = dnsmonitor.WithOutbound(dnsmonitor.WithOutbound(ctx, g.Tag()), member.Tag())
	conn, err := member.ListenPacket(ctx, destination)
	g.ReportDial(member, adapter.ContextFrom(ctx), adapter.GroupDialReport{Network: N.NetworkUDP, Err: err})
	if err != nil {
		g.logger.ErrorContext(ctx, err)
		return nil, err
	}
	dnsmonitor.Remember(ctx, conn)
	wrapped, err := token.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx))
	if err != nil {
		return nil, err
	}
	dnsmonitor.Alias(ctx, conn, wrapped)
	return wrapped, nil
}

// dialMetadata describes a connection the group dials itself, as a
// detour: the context's metadata with the destination dialed.
func dialMetadata(ctx context.Context, network string, destination M.Socksaddr) *adapter.InboundContext {
	var metadata adapter.InboundContext
	if inbound := adapter.ContextFrom(ctx); inbound != nil {
		metadata = *inbound
	}
	metadata.Network = N.NetworkName(network)
	metadata.Destination = destination
	return &metadata
}

func (g *Group) ReportDial(member adapter.Outbound, metadata *adapter.InboundContext, report adapter.GroupDialReport) {
	network := report.Network
	if network == "" {
		network = N.NetworkTCP
	}
	leaf := reportedLeaf(member, metadata, network)
	if leaf == nil {
		return
	}
	realTag := leaf.Tag()
	g.touch()
	if g.health.ObserveDial(realTag, destinationKey(metadata), g.maxFailures, report.Err) {
		if report.Err != nil {
			g.logger.Info("outbound ", realTag, " suspect after failed connections")
		}
		go g.confirm(leaf)
	}
	if report.Err != nil && g.strategy.learns() {
		g.health.ObserveOutcome(realTag, false, 0, 0)
		g.evaluate()
	}
}

// Outcome thresholds: a connection with this much download over this
// long is a bulk transfer, whose rate is recorded.
const (
	bulkBytes    = 512 << 10
	bulkDuration = time.Second
)

func (g *Group) ReportClose(member adapter.Outbound, metadata *adapter.InboundContext, report adapter.GroupCloseReport) {
	if !g.strategy.learns() {
		return
	}
	leaf := reportedLeaf(member, metadata, N.NetworkTCP)
	if leaf == nil {
		return
	}
	realTag := leaf.Tag()
	switch {
	case report.FirstByte > 0:
		var rate float64
		if transfer := report.Duration - report.FirstByte; report.Download >= bulkBytes && transfer >= bulkDuration {
			rate = float64(report.Download) / transfer.Seconds()
		}
		g.health.ObserveOutcome(realTag, true, report.FirstByte, rate)
	case report.Upload > 0 && report.Download == 0 && report.Err != nil:
		g.health.ObserveOutcome(realTag, false, 0, 0)
	default:
		return
	}
	g.evaluate()
}

// evaluate reconsiders the current member at most every evaluateEvery.
func (g *Group) evaluate() {
	now := time.Now().UnixNano()
	last := g.evaluatedAt.Load()
	if now-last < int64(evaluateEvery) || !g.evaluatedAt.CompareAndSwap(last, now) {
		return
	}
	go g.PerformUpdateCheck()
}

func (g *Group) InheritGroupState(old adapter.Outbound) {
	previous, isGroup := old.(*Group)
	if !isGroup || previous.Type() != g.Type() {
		return
	}
	previous.selectAccess.Lock()
	var inherited [2]adapter.Outbound
	var switchedAt [2]time.Time
	for i := range previous.current {
		inherited[i] = previous.current[i].Load()
		switchedAt[i] = previous.switchedAt[i]
	}
	previous.selectAccess.Unlock()
	g.selectAccess.Lock()
	for i, current := range inherited {
		if current == nil {
			continue
		}
		for _, member := range g.members {
			if member.Tag() == current.Tag() {
				g.current[i].Store(member)
				g.switchedAt[i] = switchedAt[i]
			}
		}
	}
	g.selectAccess.Unlock()
	g.strategy.inherit(previous.strategy)
}

func (g *Group) GroupStatus() adapter.GroupStatus {
	status := adapter.GroupStatus{Mode: g.strategy.mode(), Strategy: g.strategy.name()}
	selected := g.Selected(N.NetworkTCP)
	scorer, scores := g.strategy.(interface {
		cost(g *Group, member adapter.Outbound, network string) (float64, bool)
	})
	for _, member := range g.members {
		realTag := RealTag(member, N.NetworkTCP)
		stats := g.health.Stats(realTag)
		item := adapter.GroupMemberStatus{Tag: member.Tag(), State: stats.State, SuccessRate: -1}
		if realTag == "" {
			item.State = adapter.GroupMemberDown
		}
		if stats.SuccessWeight > 0 {
			item.SuccessRate = float32(stats.Success)
		}
		if stats.LatencyWeight > 0 {
			item.Latency = uint16(math.Min(stats.Latency, math.MaxUint16))
		}
		if g.strategy.hasCurrent() {
			item.Active = member == selected
		} else {
			item.Active = supports(member, N.NetworkTCP) && item.State != adapter.GroupMemberDown
		}
		if scores {
			if cost, ok := scorer.cost(g, member, N.NetworkTCP); ok {
				item.Score = float32(cost)
			}
		}
		status.Members = append(status.Members, item)
	}
	return status
}
