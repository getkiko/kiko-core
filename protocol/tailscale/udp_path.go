//go:build with_gvisor

package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/tailscale/disco"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/net/netns"
	"github.com/sagernet/tailscale/net/sockopts"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/types/nettype"
)

// udp_path splits magicsock's own UDP (WireGuard data, disco and STUN)
// between a system socket and the endpoint's detour outbound.
//
// Destination classification, in order:
//   - private, link-local and loopback addresses always use the system socket;
//   - otherwise the destination is attributed to a peer by, in order, an
//     exact netmap endpoint (IP and port) of exactly one peer, a source
//     address learned from a disco packet whose sender key belongs to a peer,
//     or an IP that is a netmap endpoint IP of exactly one peer; the first
//     peers rule matching that peer applies;
//   - everything else (STUN servers, unmatched peers, IPs shared by several
//     peers, reflexive addresses that were never seen carrying a peer's disco
//     packet) uses default.
//
// Reflexive addresses: magicsock adds the source of a received disco ping as a
// candidate (handlePingLocked) although it is not in the netmap. Readers learn
// "source → peer" from the disco sender key so such addresses follow the
// peer's rule; until a disco packet from the address is seen it stays
// unmapped and uses default. The same holds for CallMeMaybe endpoints that
// are not in the netmap. Addresses magicsock sends STUN binding requests to
// and DERP node IPs are never learned, and a fresh mapping is not replaced by
// a different peer's disco packet until it has been idle for udpPathLearnTTL.

const (
	udpPathBufferSize       = 65535
	udpPathPacketQueue      = 64
	udpPathRefreshInterval  = 10 * time.Second
	udpPathSummaryInterval  = 60 * time.Second
	udpPathLogSuppress      = 10 * time.Minute
	udpPathBackoffMin       = time.Second
	udpPathBackoffMax       = 30 * time.Second
	udpPathCacheLimit       = 4096
	udpPathLearnLimit       = 1024
	udpPathLearnTTL         = 2 * time.Minute
	udpPathSTUNLimit        = 256
	udpPathSocketBufferSize = 7 << 20 // magicsock socketBufferSize
	// Per-destination proxy sockets, used when the detour outbound binds a
	// UDP session to its first destination.
	udpPathPoolLimit = 64
	udpPathPoolIdle  = 2 * time.Minute
	// Consecutive proxy failures after which the detour path is reported as
	// unusable (status shows relay) and an error is logged once.
	udpPathFailureLimit = 5
	udpPathGroupDepth   = 8
)

type udpPathMode uint8

const (
	udpPathDirect udpPathMode = iota
	udpPathDetour
	udpPathRelay
)

func parseUDPPathMode(value string) (udpPathMode, error) {
	switch value {
	case "direct":
		return udpPathDirect, nil
	case "detour":
		return udpPathDetour, nil
	case "relay":
		return udpPathRelay, nil
	default:
		return 0, E.New("unknown udp path: ", value)
	}
}

func (m udpPathMode) String() string {
	switch m {
	case udpPathDetour:
		return "detour"
	case udpPathRelay:
		return "relay"
	default:
		return "direct"
	}
}

func (m udpPathMode) label() string {
	switch m {
	case udpPathDetour:
		return "proxied"
	case udpPathRelay:
		return "relay"
	default:
		return "direct"
	}
}

const (
	udpPathRuleDefault = -1
	udpPathRulePrivate = -2
)

func udpPathRuleLabel(rule int) string {
	switch rule {
	case udpPathRuleDefault:
		return "default"
	case udpPathRulePrivate:
		return "private"
	default:
		return "peers[" + strconv.Itoa(rule) + "]"
	}
}

type udpPathRule struct {
	patterns []string
	path     udpPathMode
}

type udpPathConfig struct {
	defaultPath udpPathMode
	rules       []udpPathRule
}

func normalizeUDPPathName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func newUDPPathConfig(options *option.TailscaleUDPPathOptions, detour string) (*udpPathConfig, error) {
	if options == nil {
		return nil, nil
	}
	config := &udpPathConfig{}
	if options.Default != "" {
		defaultPath, err := parseUDPPathMode(options.Default)
		if err != nil {
			return nil, E.Cause(err, "udp_path.default")
		}
		config.defaultPath = defaultPath
	}
	for index, peer := range options.Peers {
		if len(peer.Match) == 0 {
			return nil, E.New("udp_path.peers[", index, "]: missing match")
		}
		if peer.Path == "" {
			return nil, E.New("udp_path.peers[", index, "]: missing path")
		}
		rulePath, err := parseUDPPathMode(peer.Path)
		if err != nil {
			return nil, E.Cause(err, "udp_path.peers[", index, "]")
		}
		rule := udpPathRule{path: rulePath}
		for _, pattern := range peer.Match {
			pattern = normalizeUDPPathName(pattern)
			if pattern == "" {
				return nil, E.New("udp_path.peers[", index, "]: empty match")
			}
			_, err = path.Match(pattern, "")
			if err != nil {
				return nil, E.Cause(err, "udp_path.peers[", index, "]: bad match pattern ", pattern)
			}
			rule.patterns = append(rule.patterns, pattern)
		}
		config.rules = append(config.rules, rule)
	}
	if config.usesDetour() && detour == "" {
		return nil, E.New("udp_path: the `detour` path requires `detour` to be set")
	}
	return config, nil
}

func (c *udpPathConfig) usesDetour() bool {
	if c.defaultPath == udpPathDetour {
		return true
	}
	for _, rule := range c.rules {
		if rule.path == udpPathDetour {
			return true
		}
	}
	return false
}

// udpPeer is the matching view of a netmap peer. name, short and hostname are
// lower-cased; display keeps the original case for logs.
type udpPeer struct {
	name        string
	short       string
	hostname    string
	display     string
	tailscaleIP netip.Addr
}

func newUDPPeer(dnsName string, hostname string, tailscaleIP netip.Addr) udpPeer {
	trimmedName := strings.TrimSuffix(strings.TrimSpace(dnsName), ".")
	peer := udpPeer{
		name:        strings.ToLower(trimmedName),
		hostname:    normalizeUDPPathName(hostname),
		tailscaleIP: tailscaleIP,
	}
	shortName, _, _ := strings.Cut(trimmedName, ".")
	peer.short = strings.ToLower(shortName)
	switch {
	case shortName != "":
		peer.display = shortName
	case hostname != "":
		peer.display = hostname
	case tailscaleIP.IsValid():
		peer.display = tailscaleIP.String()
	default:
		peer.display = "unnamed peer"
	}
	return peer
}

func (p *udpPeer) matches(pattern string) bool {
	for _, candidate := range [...]string{p.name, p.short, p.hostname} {
		if candidate == "" {
			continue
		}
		if candidate == pattern {
			return true
		}
		matched, _ := path.Match(pattern, candidate)
		if matched {
			return true
		}
	}
	return false
}

func (r *udpPathRule) match(peer *udpPeer) bool {
	for _, pattern := range r.patterns {
		if peer.matches(pattern) {
			return true
		}
	}
	return false
}

func isUDPPathLocal(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

type udpPathDecision struct {
	path udpPathMode
	peer *udpPeer
	rule int
}

func (c *udpPathConfig) classify(destination netip.AddrPort, state *udpPathState) udpPathDecision {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	peer := state.lookup(destination)
	if isUDPPathLocal(destination.Addr()) {
		return udpPathDecision{path: udpPathDirect, peer: peer, rule: udpPathRulePrivate}
	}
	if peer != nil {
		for index := range c.rules {
			if c.rules[index].match(peer) {
				return udpPathDecision{path: c.rules[index].path, peer: peer, rule: index}
			}
		}
	}
	return udpPathDecision{path: c.defaultPath, peer: peer, rule: udpPathRuleDefault}
}

type udpPathPeerRecord struct {
	peer      udpPeer
	endpoints []netip.AddrPort
	discoKey  [32]byte
}

func udpPathPeersFromNetMap(networkMap *netmap.NetworkMap) []udpPathPeerRecord {
	if networkMap == nil {
		return nil
	}
	records := make([]udpPathPeerRecord, 0, len(networkMap.Peers))
	for _, node := range networkMap.Peers {
		if !node.Valid() {
			continue
		}
		var hostname string
		hostinfo := node.Hostinfo()
		if hostinfo.Valid() {
			hostname = hostinfo.Hostname()
		}
		var tailscaleIP netip.Addr
		addresses := node.Addresses()
		if addresses.Len() > 0 {
			tailscaleIP = addresses.At(0).Addr()
		}
		record := udpPathPeerRecord{
			peer:     newUDPPeer(node.Name(), hostname, tailscaleIP),
			discoKey: node.DiscoKey().Raw32(),
		}
		endpoints := node.Endpoints()
		for index := 0; index < endpoints.Len(); index++ {
			record.endpoints = append(record.endpoints, endpoints.At(index))
		}
		records = append(records, record)
	}
	return records
}

// udpPathDERPAddrs lists the DERP node IPs pinned in the netmap's DERP map.
// Nodes resolved through DNS have no pinned IP; their STUN probes still mark
// them as non-learnable (markSTUN).
func udpPathDERPAddrs(networkMap *netmap.NetworkMap) []netip.Addr {
	if networkMap == nil || networkMap.DERPMap == nil {
		return nil
	}
	var addrs []netip.Addr
	for _, region := range networkMap.DERPMap.Regions {
		if region == nil {
			continue
		}
		for _, node := range region.Nodes {
			if node == nil {
				continue
			}
			for _, value := range [...]string{node.IPv4, node.IPv6} {
				addr, err := netip.ParseAddr(value)
				if err == nil {
					addrs = append(addrs, addr.Unmap())
				}
			}
		}
	}
	return addrs
}

// udpPathLearned is a "source → disco key" mapping; seen is refreshed in
// place (unix nanoseconds) by every disco packet that confirms it.
type udpPathLearned struct {
	discoKey [32]byte
	seen     atomic.Int64
}

func newUDPPathLearned(discoKey [32]byte, now time.Time) *udpPathLearned {
	learned := &udpPathLearned{discoKey: discoKey}
	learned.seen.Store(now.UnixNano())
	return learned
}

func (l *udpPathLearned) fresh(now time.Time) bool {
	return now.Sub(time.Unix(0, l.seen.Load())) < udpPathLearnTTL
}

// udpPathState is an immutable snapshot of the peer table; its decision cache
// is dropped together with the snapshot whenever the table changes.
//
// exact and hosts map to nil when several peers share the key: such a
// destination cannot be attributed to a peer by address.
type udpPathState struct {
	exact   map[netip.AddrPort]*udpPeer
	hosts   map[netip.Addr]*udpPeer
	disco   map[[32]byte]*udpPeer
	derp    map[netip.Addr]struct{}
	learned map[netip.AddrPort]*udpPathLearned

	cacheAccess sync.RWMutex
	cache       map[netip.AddrPort]udpPathMode
}

func newUDPPathState(records []udpPathPeerRecord, derp []netip.Addr, learned map[netip.AddrPort]*udpPathLearned) *udpPathState {
	state := &udpPathState{
		exact:   make(map[netip.AddrPort]*udpPeer),
		hosts:   make(map[netip.Addr]*udpPeer),
		disco:   make(map[[32]byte]*udpPeer),
		derp:    make(map[netip.Addr]struct{}, len(derp)),
		learned: learned,
		cache:   make(map[netip.AddrPort]udpPathMode),
	}
	for index := range records {
		peer := &records[index].peer
		for _, endpoint := range records[index].endpoints {
			addr := endpoint.Addr().Unmap()
			if !addr.IsValid() {
				continue
			}
			addUDPPathPeer(state.exact, netip.AddrPortFrom(addr, endpoint.Port()), peer)
			addUDPPathPeer(state.hosts, addr, peer)
		}
		if records[index].discoKey != ([32]byte{}) {
			state.disco[records[index].discoKey] = peer
		}
	}
	for _, addr := range derp {
		state.derp[addr.Unmap()] = struct{}{}
	}
	return state
}

// addUDPPathPeer records peer under key, or nil once a second peer claims it.
func addUDPPathPeer[K comparable](table map[K]*udpPeer, key K, peer *udpPeer) {
	existing, exists := table[key]
	if !exists {
		table[key] = peer
	} else if existing != peer {
		table[key] = nil
	}
}

func (s *udpPathState) withLearned(learned map[netip.AddrPort]*udpPathLearned) *udpPathState {
	return &udpPathState{
		exact:   s.exact,
		hosts:   s.hosts,
		disco:   s.disco,
		derp:    s.derp,
		learned: learned,
		cache:   make(map[netip.AddrPort]udpPathMode),
	}
}

func (s *udpPathState) lookup(destination netip.AddrPort) *udpPeer {
	if peer := s.exact[destination]; peer != nil {
		return peer
	}
	if learned := s.learned[destination]; learned != nil {
		if peer := s.disco[learned.discoKey]; peer != nil {
			return peer
		}
	}
	return s.hosts[destination.Addr()]
}

func (s *udpPathState) samePeers(other *udpPathState) bool {
	if !sameUDPPathTable(s.exact, other.exact) || !sameUDPPathTable(s.hosts, other.hosts) || !sameUDPPathTable(s.disco, other.disco) {
		return false
	}
	if len(s.derp) != len(other.derp) {
		return false
	}
	for addr := range s.derp {
		if _, loaded := other.derp[addr]; !loaded {
			return false
		}
	}
	return true
}

func sameUDPPathTable[K comparable](table map[K]*udpPeer, other map[K]*udpPeer) bool {
	if len(table) != len(other) {
		return false
	}
	for key, peer := range table {
		otherPeer, loaded := other[key]
		if !loaded || (peer == nil) != (otherPeer == nil) || (peer != nil && *peer != *otherPeer) {
			return false
		}
	}
	return true
}

// isUDPPathSTUNRequest reports a STUN binding request: message type 0x0001
// followed by the RFC 5389 magic cookie 0x2112A442 at bytes 4..8. WireGuard
// (type byte, then three zero bytes) and disco ("TS💬") never match.
func isUDPPathSTUNRequest(packet []byte) bool {
	return len(packet) >= 20 && packet[0] == 0x00 && packet[1] == 0x01 &&
		packet[4] == 0x21 && packet[5] == 0x12 && packet[6] == 0xA4 && packet[7] == 0x42
}

type udpPathCounter struct {
	packets atomic.Uint64
	bytes   atomic.Uint64
}

func (c *udpPathCounter) add(length int) {
	c.packets.Add(1)
	c.bytes.Add(uint64(length))
}

type udpPathLogEntry struct {
	path udpPathMode
	rule int
	peer udpPeer
	at   time.Time
}

type udpPathManager struct {
	ctx          context.Context
	logger       logger.ContextLogger
	config       *udpPathConfig
	dialer       N.Dialer
	detourTag    string
	directListen func(ctx context.Context, network string, address string) (nettype.PacketConn, error)
	// resolveDetour reports the outbound the detour currently resolves to,
	// whether it binds a UDP session to its first destination, and whether
	// that could be determined. Nil in tests.
	resolveDetour func() (resolved string, bound bool, known bool)

	stateAccess   sync.Mutex
	state         atomic.Pointer[udpPathState]
	refreshSignal chan struct{}

	stunAccess  sync.Mutex
	stunTargets map[netip.AddrPort]struct{}

	logAccess    sync.Mutex
	logged       map[netip.AddrPort]udpPathLogEntry
	conflicts    map[netip.AddrPort]time.Time
	detourReport string

	// destinationBound selects per-destination proxy sockets.
	destinationBound atomic.Bool
	proxyFailures    atomic.Int32
	proxyDegraded    atomic.Bool

	detourTx      udpPathCounter
	detourRx      udpPathCounter
	detourPending udpPathCounter
	directTx      udpPathCounter
	directRx      udpPathCounter
	relayDrop     udpPathCounter
}

func newUDPPathManager(ctx context.Context, logger logger.ContextLogger, config *udpPathConfig, dialer N.Dialer, detourTag string, directListen func(ctx context.Context, network string, address string) (nettype.PacketConn, error)) *udpPathManager {
	manager := &udpPathManager{
		ctx:           ctx,
		logger:        logger,
		config:        config,
		dialer:        dialer,
		detourTag:     detourTag,
		directListen:  directListen,
		refreshSignal: make(chan struct{}, 1),
		stunTargets:   make(map[netip.AddrPort]struct{}),
		logged:        make(map[netip.AddrPort]udpPathLogEntry),
		conflicts:     make(map[netip.AddrPort]time.Time),
	}
	manager.state.Store(newUDPPathState(nil, nil, nil))
	return manager
}

func (m *udpPathManager) logStartup() {
	m.logger.Info("tailscale udp: enabled, default=", m.config.defaultPath.String(), ", ", len(m.config.rules), " rules, detour=", m.detourTag)
}

func (m *udpPathManager) scheduleRefresh() {
	select {
	case m.refreshSignal <- struct{}{}:
	default:
	}
}

// run refreshes the peer table on netmap changes (scheduleRefresh) and every
// udpPathRefreshInterval, re-checks the detour outbound, and logs the
// per-path traffic summary.
func (m *udpPathManager) run(ctx context.Context, loadNetMap func() *netmap.NetworkMap) {
	refreshTicker := time.NewTicker(udpPathRefreshInterval)
	defer refreshTicker.Stop()
	summaryTicker := time.NewTicker(udpPathSummaryInterval)
	defer summaryTicker.Stop()
	m.checkDetour()
	m.refreshNetMap(loadNetMap())
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.refreshSignal:
			m.refreshNetMap(loadNetMap())
		case <-refreshTicker.C:
			m.checkDetour()
			m.refreshNetMap(loadNetMap())
		case <-summaryTicker.C:
			m.logSummary()
			m.pruneLogged(time.Now())
		}
	}
}

func (m *udpPathManager) refreshNetMap(networkMap *netmap.NetworkMap) {
	m.refresh(udpPathPeersFromNetMap(networkMap), udpPathDERPAddrs(networkMap))
}

func (m *udpPathManager) refresh(records []udpPathPeerRecord, derp []netip.Addr) {
	m.stateAccess.Lock()
	defer m.stateAccess.Unlock()
	current := m.state.Load()
	next := newUDPPathState(records, derp, current.learned)
	if current.samePeers(next) {
		return
	}
	m.state.Store(next)
	m.logger.Debug("tailscale udp: peer table updated, ", len(records), " peers, ", len(next.exact), " endpoint addresses")
}

// checkDetour detects a detour outbound whose UDP session only reaches the
// destination it was created for (VMess/VLESS without xudp/packetaddr). A
// group resolves to its current member, so this is re-run periodically and
// before each shared proxy socket is created.
func (m *udpPathManager) checkDetour() bool {
	if m.resolveDetour == nil {
		return m.destinationBound.Load()
	}
	resolved, bound, known := m.resolveDetour()
	m.destinationBound.Store(bound)
	report := resolved + "|" + strconv.FormatBool(bound) + "|" + strconv.FormatBool(known)
	m.logAccess.Lock()
	previous := m.detourReport
	m.detourReport = report
	m.logAccess.Unlock()
	if report == previous {
		return bound
	}
	switch {
	case !known:
		m.logger.Warn("tailscale udp: cannot determine the outbound currently used by detour=", m.detourTag, " (", resolved, "), using a single proxy socket; if its UDP sessions only send to the first destination, hole punching through the detour does not work")
	case bound:
		m.logger.Warn("tailscale udp: UDP sessions of the current outbound ", resolved, " of detour=", m.detourTag, " only send to the first destination (VMess/VLESS without xudp or packetaddr), using a proxy socket per destination (at most ", udpPathPoolLimit, ", closed after ", udpPathPoolIdle, " idle); hole punching through this outbound does not work")
	case previous != "":
		m.logger.Info("tailscale udp: the current outbound ", resolved, " of detour=", m.detourTag, " supports multiple destinations, using a single proxy socket")
	}
	return bound
}

// resolveUDPPathDetour follows groups (selector, urltest) to their current
// member and reports whether that outbound binds UDP to one destination.
func resolveUDPPathDetour(outboundManager adapter.OutboundManager, tag string) (string, bool, bool) {
	if outboundManager == nil {
		return tag, false, false
	}
	for range udpPathGroupDepth {
		outbound, loaded := outboundManager.Outbound(tag)
		if !loaded {
			return tag, false, false
		}
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			bounded, isBounded := outbound.(udpDestinationBoundOutbound)
			return tag, isBounded && bounded.UDPDestinationBound(), true
		}
		next := group.Selected(N.NetworkUDP)
		if next == nil {
			return tag, false, false
		}
		tag = next.Tag()
	}
	return tag, false, false
}

// udpDestinationBoundOutbound is implemented by VMess and VLESS outbounds.
type udpDestinationBoundOutbound interface {
	UDPDestinationBound() bool
}

// proxyFailed counts a proxy socket failure; after udpPathFailureLimit in a
// row the detour path is reported as relay and an error is logged once.
func (m *udpPathManager) proxyFailed(err error) {
	if m.proxyFailures.Add(1) < udpPathFailureLimit {
		return
	}
	if m.proxyDegraded.CompareAndSwap(false, true) {
		m.logger.Error("tailscale udp: UDP through detour=", m.detourTag, " failed ", udpPathFailureLimit, " times in a row, peers on the detour path fall back to DERP (the outbound may not support UDP): ", err)
	}
}

func (m *udpPathManager) proxySucceeded() {
	m.proxyFailures.Store(0)
	if m.proxyDegraded.CompareAndSwap(true, false) {
		m.logger.Info("tailscale udp: UDP through detour=", m.detourTag, " recovered")
	}
}

func (m *udpPathManager) pathFor(destination netip.AddrPort) udpPathMode {
	state := m.state.Load()
	state.cacheAccess.RLock()
	cachedPath, loaded := state.cache[destination]
	state.cacheAccess.RUnlock()
	if loaded {
		return cachedPath
	}
	decision := m.config.classify(destination, state)
	state.cacheAccess.Lock()
	if len(state.cache) >= udpPathCacheLimit {
		clear(state.cache)
	}
	state.cache[destination] = decision.path
	state.cacheAccess.Unlock()
	m.logDecision(destination, decision)
	return decision.path
}

// statusPath reports the path magicsock's packets to curAddr (a peer's
// ipnstate CurAddr) take, for display. It classifies without caching or
// logging. A peer without a direct address is reached through DERP, and so
// is a detour peer while the detour keeps failing.
func (m *udpPathManager) statusPath(curAddr string, relay string) string {
	if curAddr == "" {
		if relay != "" {
			return udpPathRelay.String()
		}
		return ""
	}
	destination, err := netip.ParseAddrPort(curAddr)
	if err != nil {
		return ""
	}
	path := m.config.classify(destination, m.state.Load()).path
	if path == udpPathDetour && m.proxyDegraded.Load() {
		path = udpPathRelay
	}
	return path.String()
}

// markSTUN records a destination magicsock sent a STUN binding request to:
// replies from it are STUN, never a peer's disco, so it is never learned.
func (m *udpPathManager) markSTUN(destination netip.AddrPort) {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	m.stunAccess.Lock()
	_, marked := m.stunTargets[destination]
	if !marked {
		if len(m.stunTargets) >= udpPathSTUNLimit {
			clear(m.stunTargets)
		}
		m.stunTargets[destination] = struct{}{}
	}
	m.stunAccess.Unlock()
	if marked || m.state.Load().learned[destination] == nil {
		return
	}
	m.stateAccess.Lock()
	defer m.stateAccess.Unlock()
	current := m.state.Load()
	if current.learned[destination] == nil {
		return
	}
	learned := make(map[netip.AddrPort]*udpPathLearned, len(current.learned))
	for source, entry := range current.learned {
		if source != destination {
			learned[source] = entry
		}
	}
	m.state.Store(current.withLearned(learned))
}

func (m *udpPathManager) isSTUNTarget(source netip.AddrPort) bool {
	m.stunAccess.Lock()
	defer m.stunAccess.Unlock()
	_, marked := m.stunTargets[source]
	return marked
}

// observe learns "source address → peer" from the sender key of a disco
// packet, so reflexive addresses that are not in the netmap follow the peer's
// rule. Only relevant when per-peer rules exist. A source that is a netmap
// endpoint of one peer, a DERP node or a STUN target is never learned, and a
// fresh mapping to another peer is kept (the sender key alone is not
// stronger evidence than the mapping already confirmed).
func (m *udpPathManager) observe(source netip.AddrPort, payload []byte) {
	if len(m.config.rules) == 0 {
		return
	}
	rawKey, isDisco := disco.Source(payload)
	if !isDisco {
		return
	}
	addr := source.Addr().Unmap()
	if isUDPPathLocal(addr) {
		return
	}
	source = netip.AddrPortFrom(addr, source.Port())
	var discoKey [32]byte
	copy(discoKey[:], rawKey)
	now := time.Now()
	state := m.state.Load()
	if state.exact[source] != nil || state.disco[discoKey] == nil {
		return
	}
	if _, isDERP := state.derp[addr]; isDERP {
		return
	}
	if learned := state.learned[source]; learned != nil && learned.discoKey == discoKey {
		learned.seen.Store(now.UnixNano())
		return
	}
	if m.isSTUNTarget(source) {
		return
	}
	m.stateAccess.Lock()
	defer m.stateAccess.Unlock()
	current := m.state.Load()
	sender := current.disco[discoKey]
	if current.exact[source] != nil || sender == nil {
		return
	}
	if existing := current.learned[source]; existing != nil {
		if existing.discoKey == discoKey {
			existing.seen.Store(now.UnixNano())
			return
		}
		if existing.fresh(now) {
			m.logLearnConflict(source, current.disco[existing.discoKey], sender, now)
			return
		}
	}
	learned := make(map[netip.AddrPort]*udpPathLearned, len(current.learned)+1)
	for learnedSource, entry := range current.learned {
		if learnedSource != source && entry.fresh(now) {
			learned[learnedSource] = entry
		}
	}
	if len(learned) >= udpPathLearnLimit {
		clear(learned)
	}
	learned[source] = newUDPPathLearned(discoKey, now)
	m.state.Store(current.withLearned(learned))
}

func (m *udpPathManager) logLearnConflict(source netip.AddrPort, existing *udpPeer, sender *udpPeer, now time.Time) {
	m.logAccess.Lock()
	at, logged := m.conflicts[source]
	if logged && now.Sub(at) < udpPathLogSuppress {
		m.logAccess.Unlock()
		return
	}
	m.conflicts[source] = now
	m.logAccess.Unlock()
	existingName := "unknown peer"
	if existing != nil {
		existingName = existing.display
	}
	m.logger.Warn("tailscale udp: ", source, " already belongs to ", existingName, ", ignoring the disco packet from ", sender.display, " (the mapping is kept for ", udpPathLearnTTL, ")")
}

func (m *udpPathManager) logDecision(destination netip.AddrPort, decision udpPathDecision) {
	now := time.Now()
	entry := udpPathLogEntry{path: decision.path, rule: decision.rule, at: now}
	if decision.peer != nil {
		entry.peer = *decision.peer
	}
	m.logAccess.Lock()
	previous, loaded := m.logged[destination]
	if loaded && previous.path == entry.path && previous.rule == entry.rule && previous.peer == entry.peer && now.Sub(previous.at) < udpPathLogSuppress {
		m.logAccess.Unlock()
		return
	}
	m.logged[destination] = entry
	m.logAccess.Unlock()
	m.logger.Info(m.describeDecision(destination, decision))
}

func (m *udpPathManager) describeDecision(destination netip.AddrPort, decision udpPathDecision) string {
	var builder strings.Builder
	builder.WriteString("tailscale udp: ")
	if decision.peer != nil {
		builder.WriteString(decision.peer.display)
		if decision.peer.tailscaleIP.IsValid() {
			builder.WriteString(" (")
			builder.WriteString(decision.peer.tailscaleIP.String())
			builder.WriteString(")")
		}
	} else {
		builder.WriteString("unknown peer")
	}
	builder.WriteString(" → ")
	builder.WriteString(destination.String())
	builder.WriteString(" ")
	builder.WriteString(decision.path.label())
	if decision.path == udpPathDetour {
		builder.WriteString(" detour=")
		builder.WriteString(m.detourTag)
	}
	builder.WriteString(" rule=")
	builder.WriteString(udpPathRuleLabel(decision.rule))
	return builder.String()
}

func (m *udpPathManager) pruneLogged(now time.Time) {
	m.logAccess.Lock()
	defer m.logAccess.Unlock()
	for destination, entry := range m.logged {
		if now.Sub(entry.at) >= udpPathLogSuppress {
			delete(m.logged, destination)
		}
	}
	for source, at := range m.conflicts {
		if now.Sub(at) >= udpPathLogSuppress {
			delete(m.conflicts, source)
		}
	}
}

func (m *udpPathManager) logSummary() {
	detourTxPackets, detourTxBytes := m.detourTx.packets.Swap(0), m.detourTx.bytes.Swap(0)
	detourRxPackets, detourRxBytes := m.detourRx.packets.Swap(0), m.detourRx.bytes.Swap(0)
	pendingPackets := m.detourPending.packets.Swap(0)
	m.detourPending.bytes.Swap(0)
	directTxPackets, directTxBytes := m.directTx.packets.Swap(0), m.directTx.bytes.Swap(0)
	directRxPackets, directRxBytes := m.directRx.packets.Swap(0), m.directRx.bytes.Swap(0)
	relayPackets := m.relayDrop.packets.Swap(0)
	m.relayDrop.bytes.Swap(0)
	if detourTxPackets == 0 && detourRxPackets == 0 && pendingPackets == 0 && directTxPackets == 0 && directRxPackets == 0 && relayPackets == 0 {
		return
	}
	var builder strings.Builder
	builder.WriteString("tailscale udp: summary proxied tx ")
	builder.WriteString(formatUDPPathTraffic(detourTxPackets, detourTxBytes))
	builder.WriteString(" rx ")
	builder.WriteString(formatUDPPathTraffic(detourRxPackets, detourRxBytes))
	if pendingPackets > 0 {
		builder.WriteString(" dropped before proxy ready ")
		builder.WriteString(strconv.FormatUint(pendingPackets, 10))
		builder.WriteString(" packets")
	}
	builder.WriteString(", direct tx ")
	builder.WriteString(formatUDPPathTraffic(directTxPackets, directTxBytes))
	builder.WriteString(" rx ")
	builder.WriteString(formatUDPPathTraffic(directRxPackets, directRxBytes))
	builder.WriteString(", relay dropped ")
	builder.WriteString(strconv.FormatUint(relayPackets, 10))
	builder.WriteString(" packets")
	m.logger.Info(builder.String())
}

func formatUDPPathTraffic(packets uint64, bytes uint64) string {
	return strconv.FormatUint(packets, 10) + " packets/" + formatUDPPathBytes(bytes)
}

func formatUDPPathBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return strconv.FormatUint(bytes, 10) + " B"
	}
	value := float64(bytes)
	units := [...]string{"KB", "MB", "GB", "TB"}
	index := -1
	for value >= unit && index < len(units)-1 {
		value /= unit
		index++
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + " " + units[index]
}

func (m *udpPathManager) listen(ctx context.Context, network string, address string) (nettype.PacketConn, error) {
	direct, err := m.directListen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	// magicsock applies these only to a bare *net.UDPConn, which the split
	// conn is not.
	if udpConn, isUDPConn := direct.(*net.UDPConn); isUDPConn {
		setUDPPathSocketOptions(udpConn, m.logger)
	}
	return newUDPPathConn(m, network, direct), nil
}

func setUDPPathSocketOptions(conn *net.UDPConn, logger logger.ContextLogger) {
	for _, direction := range [...]sockopts.BufferDirection{sockopts.ReadDirection, sockopts.WriteDirection} {
		forceErr, portableErr := sockopts.SetBufferSize(conn, direction, udpPathSocketBufferSize)
		if forceErr != nil {
			logger.Debug("tailscale udp: force-set ", direction, " buffer: ", forceErr)
		}
		if portableErr != nil {
			logger.Debug("tailscale udp: set ", direction, " buffer: ", portableErr)
		}
	}
	err := sockopts.SetICMPErrImmunity(conn)
	if err != nil {
		logger.Debug("tailscale udp: ", err)
	}
}

type udpPathPacket struct {
	buffer *buf.Buffer
	source netip.AddrPort
	err    error
}

type udpPathProxy struct {
	conn     net.PacketConn
	received atomic.Bool
}

// udpPathProxySlot holds one proxy PacketConn and its reconnect state: the
// shared slot carries every detour destination, a pool slot (destination
// set) only its own. connecting, failures and retryAt are guarded by
// udpPathConn.proxyAccess.
type udpPathProxySlot struct {
	destination netip.AddrPort
	proxy       atomic.Pointer[udpPathProxy]
	lastUsed    atomic.Int64
	connecting  bool
	failures    int
	retryAt     time.Time
}

func (s *udpPathProxySlot) backoffLocked() time.Duration {
	s.failures++
	delay := udpPathBackoffMin << min(s.failures-1, 5)
	if delay > udpPathBackoffMax {
		delay = udpPathBackoffMax
	}
	s.retryAt = time.Now().Add(delay)
	return delay
}

var _ nettype.PacketConn = (*udpPathConn)(nil)

// udpPathConn implements nettype.PacketConn over a direct system socket (the
// anchor: its LocalAddr is the *net.UDPAddr magicsock asserts and advertises)
// and lazily created PacketConns through the detour outbound: one shared
// socket, or one per destination when the detour binds UDP to its first
// destination.
//
// Close waits only for the direct reader. Proxy readers are not waited for:
// magicsock calls Close while holding its own lock, and a proxy PacketConn
// may not unblock on Close; they exit on their own once their read returns
// (done is closed and the slot no longer holds their proxy).
type udpPathConn struct {
	manager *udpPathManager
	network string
	direct  nettype.PacketConn
	ctx     context.Context
	cancel  context.CancelFunc

	packets      chan udpPathPacket
	done         chan struct{}
	closeOnce    sync.Once
	closed       atomic.Bool
	directWait   sync.WaitGroup
	readDeadline udpPathDeadline

	shared        udpPathProxySlot
	proxyAccess   sync.Mutex
	pool          map[netip.AddrPort]*udpPathProxySlot
	writeDeadline time.Time
}

func newUDPPathConn(manager *udpPathManager, network string, direct nettype.PacketConn) *udpPathConn {
	ctx, cancel := context.WithCancel(manager.ctx)
	conn := &udpPathConn{
		manager: manager,
		network: network,
		direct:  direct,
		ctx:     ctx,
		cancel:  cancel,
		packets: make(chan udpPathPacket, udpPathPacketQueue),
		done:    make(chan struct{}),
	}
	conn.readDeadline.cancel = make(chan struct{})
	conn.directWait.Add(1)
	go conn.readDirect()
	return conn
}

func (c *udpPathConn) readDirect() {
	defer c.directWait.Done()
	for {
		buffer := buf.NewSize(udpPathBufferSize)
		length, source, err := c.direct.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			// Only a closed socket ends the reader: E.IsClosed also matches
			// ECONNRESET, which Windows reports for ICMP port unreachable.
			if errors.Is(err, net.ErrClosed) || c.closed.Load() {
				return
			}
			select {
			case c.packets <- udpPathPacket{err: err}:
			case <-c.done:
				return
			}
			continue
		}
		buffer.Extend(length)
		c.manager.directRx.add(length)
		c.manager.observe(source, buffer.Bytes())
		select {
		case c.packets <- udpPathPacket{buffer: buffer, source: source}:
		case <-c.done:
			buffer.Release()
			return
		}
	}
}

func (c *udpPathConn) readProxy(slot *udpPathProxySlot, proxy *udpPathProxy) {
	for {
		buffer := buf.NewSize(udpPathBufferSize)
		length, addr, err := proxy.conn.ReadFrom(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			c.proxyFailed(slot, proxy, "read", err)
			return
		}
		if c.closed.Load() {
			buffer.Release()
			return
		}
		source := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
		if !source.IsValid() {
			buffer.Release()
			continue
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		buffer.Extend(length)
		if !proxy.received.Swap(true) {
			c.proxyAccess.Lock()
			slot.failures = 0
			c.proxyAccess.Unlock()
			c.manager.proxySucceeded()
		}
		c.manager.detourRx.add(length)
		c.manager.observe(source, buffer.Bytes())
		select {
		case c.packets <- udpPathPacket{buffer: buffer, source: source}:
		case <-c.done:
			buffer.Release()
			return
		}
	}
}

func (c *udpPathConn) ReadFromUDPAddrPort(buffer []byte) (int, netip.AddrPort, error) {
	if c.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	select {
	case packet := <-c.packets:
		if packet.err != nil {
			return 0, netip.AddrPort{}, packet.err
		}
		copied := copy(buffer, packet.buffer.Bytes())
		packet.buffer.Release()
		return copied, packet.source, nil
	case <-c.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	case <-c.readDeadline.wait():
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	}
}

func (c *udpPathConn) WriteToUDPAddrPort(buffer []byte, destination netip.AddrPort) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if isUDPPathSTUNRequest(buffer) {
		c.manager.markSTUN(destination)
	}
	switch c.manager.pathFor(destination) {
	case udpPathRelay:
		c.manager.relayDrop.add(len(buffer))
		return len(buffer), nil
	case udpPathDetour:
		return c.writeProxy(buffer, destination)
	default:
		n, err := c.direct.WriteToUDPAddrPort(buffer, destination)
		if err == nil {
			c.manager.directTx.add(n)
		}
		return n, err
	}
}

// writeProxy never blocks on proxy setup: while the detour PacketConn is being
// created or backing off, packets are dropped and magicsock retransmits.
func (c *udpPathConn) writeProxy(buffer []byte, destination netip.AddrPort) (int, error) {
	slot, proxy := c.loadProxy(destination)
	if proxy == nil {
		c.manager.detourPending.add(len(buffer))
		return len(buffer), nil
	}
	_, err := proxy.conn.WriteTo(buffer, M.SocksaddrFromNetIP(destination).UDPAddr())
	if err != nil {
		if isUDPPathTimeout(err) {
			return 0, err
		}
		c.proxyFailed(slot, proxy, "write", err)
		return len(buffer), nil
	}
	c.manager.detourTx.add(len(buffer))
	return len(buffer), nil
}

func isUDPPathTimeout(err error) bool {
	netErr, isNetErr := err.(net.Error)
	return isNetErr && netErr.Timeout()
}

// loadProxy returns the slot for destination and its proxy, starting a
// connect in the background when the slot has none.
func (c *udpPathConn) loadProxy(destination netip.AddrPort) (*udpPathProxySlot, *udpPathProxy) {
	if !c.manager.destinationBound.Load() {
		slot := &c.shared
		if proxy := slot.proxy.Load(); proxy != nil {
			return slot, proxy
		}
		c.proxyAccess.Lock()
		defer c.proxyAccess.Unlock()
		return slot, c.connectLocked(slot, destination)
	}
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	now := time.Now()
	c.proxyAccess.Lock()
	slot, evicted := c.poolSlotLocked(destination, now)
	var proxy *udpPathProxy
	if slot != nil {
		slot.lastUsed.Store(now.UnixNano())
		proxy = slot.proxy.Load()
		if proxy == nil {
			proxy = c.connectLocked(slot, destination)
		}
	}
	c.proxyAccess.Unlock()
	closeUDPPathProxies(evicted)
	return slot, proxy
}

func (c *udpPathConn) connectLocked(slot *udpPathProxySlot, destination netip.AddrPort) *udpPathProxy {
	if proxy := slot.proxy.Load(); proxy != nil {
		return proxy
	}
	if c.closed.Load() || slot.connecting || time.Now().Before(slot.retryAt) {
		return nil
	}
	slot.connecting = true
	go c.connectProxy(slot, destination)
	return nil
}

// poolSlotLocked returns the pool slot for destination, creating it and
// evicting the least recently used slot when the pool is full. The caller
// closes the evicted proxies after releasing proxyAccess.
func (c *udpPathConn) poolSlotLocked(destination netip.AddrPort, now time.Time) (*udpPathProxySlot, []*udpPathProxy) {
	if c.closed.Load() {
		return nil, nil
	}
	if slot := c.pool[destination]; slot != nil {
		return slot, nil
	}
	if c.pool == nil {
		c.pool = make(map[netip.AddrPort]*udpPathProxySlot)
		go c.expirePool()
	}
	var evicted []*udpPathProxy
	if len(c.pool) >= udpPathPoolLimit {
		var oldest *udpPathProxySlot
		for _, slot := range c.pool {
			if oldest == nil || slot.lastUsed.Load() < oldest.lastUsed.Load() {
				oldest = slot
			}
		}
		delete(c.pool, oldest.destination)
		if proxy := oldest.proxy.Swap(nil); proxy != nil {
			evicted = append(evicted, proxy)
		}
	}
	slot := &udpPathProxySlot{destination: destination}
	slot.lastUsed.Store(now.UnixNano())
	c.pool[destination] = slot
	return slot, evicted
}

func (c *udpPathConn) expirePool() {
	ticker := time.NewTicker(udpPathPoolIdle / 4)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-ticker.C:
			closeUDPPathProxies(c.expireIdle(now))
		}
	}
}

func (c *udpPathConn) expireIdle(now time.Time) []*udpPathProxy {
	c.proxyAccess.Lock()
	defer c.proxyAccess.Unlock()
	var expired []*udpPathProxy
	for destination, slot := range c.pool {
		if now.Sub(time.Unix(0, slot.lastUsed.Load())) < udpPathPoolIdle {
			continue
		}
		delete(c.pool, destination)
		if proxy := slot.proxy.Swap(nil); proxy != nil {
			expired = append(expired, proxy)
		}
	}
	return expired
}

// attachedLocked reports whether slot is still in use: the shared slot, or a
// pool slot that has not been evicted or expired.
func (c *udpPathConn) attachedLocked(slot *udpPathProxySlot) bool {
	if c.closed.Load() {
		return false
	}
	return slot == &c.shared || c.pool[slot.destination] == slot
}

func (c *udpPathConn) connectProxy(slot *udpPathProxySlot, destination netip.AddrPort) {
	if slot == &c.shared && c.manager.checkDetour() {
		// The detour now resolves to a destination-bound outbound: the next
		// write goes to the pool instead.
		c.proxyAccess.Lock()
		slot.connecting = false
		c.proxyAccess.Unlock()
		return
	}
	conn, err := c.manager.dialer.ListenPacket(c.ctx, M.SocksaddrFromNetIP(destination))
	c.proxyAccess.Lock()
	slot.connecting = false
	if err != nil {
		if !c.attachedLocked(slot) {
			c.proxyAccess.Unlock()
			return
		}
		delay := slot.backoffLocked()
		c.proxyAccess.Unlock()
		c.manager.logger.Warn("tailscale udp: create proxy socket detour=", c.manager.detourTag, " network=", c.network, c.slotLabel(slot), ", retry in ", delay, ": ", err)
		c.manager.proxyFailed(err)
		return
	}
	if !c.attachedLocked(slot) {
		c.proxyAccess.Unlock()
		closeUDPPathProxies([]*udpPathProxy{{conn: conn}})
		return
	}
	if !c.writeDeadline.IsZero() {
		_ = conn.SetWriteDeadline(c.writeDeadline)
	}
	proxy := &udpPathProxy{conn: conn}
	slot.proxy.Store(proxy)
	c.proxyAccess.Unlock()
	if slot == &c.shared {
		c.manager.logger.Info("tailscale udp: proxy socket created detour=", c.manager.detourTag, " network=", c.network)
	} else {
		c.manager.logger.Debug("tailscale udp: proxy socket created detour=", c.manager.detourTag, " network=", c.network, c.slotLabel(slot))
	}
	go c.readProxy(slot, proxy)
}

func (c *udpPathConn) slotLabel(slot *udpPathProxySlot) string {
	if slot == &c.shared {
		return ""
	}
	return " destination=" + slot.destination.String()
}

func (c *udpPathConn) proxyFailed(slot *udpPathProxySlot, proxy *udpPathProxy, operation string, err error) {
	c.proxyAccess.Lock()
	if slot.proxy.Load() != proxy {
		c.proxyAccess.Unlock()
		return
	}
	slot.proxy.Store(nil)
	delay := slot.backoffLocked()
	c.proxyAccess.Unlock()
	closeUDPPathProxies([]*udpPathProxy{proxy})
	c.manager.logger.Warn("tailscale udp: proxy socket ", operation, " detour=", c.manager.detourTag, " network=", c.network, c.slotLabel(slot), ", recreate in ", delay, ": ", err)
	c.manager.proxyFailed(err)
}

// closeUDPPathProxies closes proxy sockets in the background: closing an
// outbound's PacketConn may block, and callers hold magicsock's locks.
func closeUDPPathProxies(proxies []*udpPathProxy) {
	if len(proxies) == 0 {
		return
	}
	go func() {
		for _, proxy := range proxies {
			proxy.conn.Close()
		}
	}()
}

// proxiesLocked lists every live proxy socket.
func (c *udpPathConn) proxiesLocked() []*udpPathProxy {
	var proxies []*udpPathProxy
	if proxy := c.shared.proxy.Load(); proxy != nil {
		proxies = append(proxies, proxy)
	}
	for _, slot := range c.pool {
		if proxy := slot.proxy.Load(); proxy != nil {
			proxies = append(proxies, proxy)
		}
	}
	return proxies
}

func (c *udpPathConn) LocalAddr() net.Addr {
	return c.direct.LocalAddr()
}

func (c *udpPathConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline applies to the merged read only; the underlying sockets
// keep blocking reads so the reader goroutines never spin on a past deadline.
func (c *udpPathConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *udpPathConn) SetWriteDeadline(t time.Time) error {
	c.proxyAccess.Lock()
	c.writeDeadline = t
	proxies := c.proxiesLocked()
	c.proxyAccess.Unlock()
	for _, proxy := range proxies {
		_ = proxy.conn.SetWriteDeadline(t)
	}
	return c.direct.SetWriteDeadline(t)
}

func (c *udpPathConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.proxyAccess.Lock()
		c.closed.Store(true)
		proxies := c.proxiesLocked()
		c.shared.proxy.Store(nil)
		for _, slot := range c.pool {
			slot.proxy.Store(nil)
		}
		c.pool = nil
		c.proxyAccess.Unlock()
		c.cancel()
		close(c.done)
		err = c.direct.Close()
		closeUDPPathProxies(proxies)
		c.directWait.Wait()
		for {
			select {
			case packet := <-c.packets:
				if packet.buffer != nil {
					packet.buffer.Release()
				}
			default:
				return
			}
		}
	})
	return err
}

// udpPathDeadline follows net.Pipe's pipeDeadline: wait returns a channel
// that is closed once the deadline has passed.
type udpPathDeadline struct {
	access sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func (d *udpPathDeadline) set(t time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil
	closed := isUDPPathChannelClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if duration := time.Until(t); duration > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(duration, func() {
			close(cancel)
		})
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *udpPathDeadline) wait() chan struct{} {
	d.access.Lock()
	defer d.access.Unlock()
	return d.cancel
}

func isUDPPathChannelClosed(channel chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func udpPathNotificationChanged(notify *ipn.Notify) bool {
	return notify.State != nil || notify.NetMap != nil || notify.SelfChange != nil ||
		len(notify.PeersChanged) > 0 || len(notify.PeersRemoved) > 0 || len(notify.PeerChangedPatch) > 0
}

// netns's listen hook is process-global and cannot tell endpoints apart, so
// while an endpoint uses udp_path it must be the only started Tailscale
// endpoint: every other endpoint's magicsock would otherwise bind through it.
//
// An endpoint registers in Start and unregisters first thing in Close (and
// again, idempotently, at the end), so a reload in the same process (libbox)
// can start the new endpoint while the old one is still tearing down. The
// netns hooks remember which endpoint installed them, and a closing endpoint
// only clears hooks it still owns.
var udpPathEndpoints struct {
	access        sync.Mutex
	active        []*Endpoint
	owner         *Endpoint
	controlOwner  *Endpoint
	listenerOwner *Endpoint
}

func registerUDPPathEndpoint(endpoint *Endpoint, enableUDPPath bool) error {
	udpPathEndpoints.access.Lock()
	defer udpPathEndpoints.access.Unlock()
	owner := udpPathEndpoints.owner
	if owner != nil && owner != endpoint {
		return E.New("udp_path is enabled on Tailscale endpoint[", owner.Tag(), "]; its socket hook is process-global, so no other Tailscale endpoint can start")
	}
	if enableUDPPath {
		for _, active := range udpPathEndpoints.active {
			if active != endpoint {
				return E.New("udp_path requires endpoint[", endpoint.Tag(), "] to be the only Tailscale endpoint, but endpoint[", active.Tag(), "] is running")
			}
		}
		udpPathEndpoints.owner = endpoint
	}
	if !slices.Contains(udpPathEndpoints.active, endpoint) {
		udpPathEndpoints.active = append(udpPathEndpoints.active, endpoint)
	}
	return nil
}

func unregisterUDPPathEndpoint(endpoint *Endpoint) {
	udpPathEndpoints.access.Lock()
	defer udpPathEndpoints.access.Unlock()
	if udpPathEndpoints.owner == endpoint {
		udpPathEndpoints.owner = nil
	}
	udpPathEndpoints.active = slices.DeleteFunc(udpPathEndpoints.active, func(active *Endpoint) bool {
		return active == endpoint
	})
}

func setNetnsControlFunc(endpoint *Endpoint, controlFunc func(network, address string, conn syscall.RawConn) error) {
	udpPathEndpoints.access.Lock()
	defer udpPathEndpoints.access.Unlock()
	udpPathEndpoints.controlOwner = endpoint
	netns.SetControlFunc(controlFunc)
}

func clearNetnsControlFunc(endpoint *Endpoint) {
	udpPathEndpoints.access.Lock()
	defer udpPathEndpoints.access.Unlock()
	if udpPathEndpoints.controlOwner != endpoint {
		return
	}
	udpPathEndpoints.controlOwner = nil
	netns.SetControlFunc(nil)
}

func setNetnsListenPacketFunc(endpoint *Endpoint, listenFunc func(ctx context.Context, network string, address string) (nettype.PacketConn, error)) {
	udpPathEndpoints.access.Lock()
	defer udpPathEndpoints.access.Unlock()
	udpPathEndpoints.listenerOwner = endpoint
	netns.SetListenPacketFunc(listenFunc)
}

func clearNetnsListenPacketFunc(endpoint *Endpoint) {
	udpPathEndpoints.access.Lock()
	defer udpPathEndpoints.access.Unlock()
	if udpPathEndpoints.listenerOwner != endpoint {
		return
	}
	udpPathEndpoints.listenerOwner = nil
	netns.SetListenPacketFunc(nil)
}

// stunPath is the path the network check's STUN requests take.
func (m *udpPathManager) stunPath() string {
	path := m.config.defaultPath
	if path == udpPathDetour && m.proxyDegraded.Load() {
		path = udpPathRelay
	}
	return path.String()
}

// candidatePath is the path magicsock's packets to a peer's candidate
// address take, for display, as statusPath classifies.
func (m *udpPathManager) candidatePath(address netip.AddrPort) string {
	path := m.config.classify(address, m.state.Load()).path
	if path == udpPathDetour && m.proxyDegraded.Load() {
		path = udpPathRelay
	}
	return path.String()
}
