//go:build with_gvisor

package tailscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/tailscale/disco"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/types/nettype"
)

func mustUDPPathConfig(t *testing.T, options option.TailscaleUDPPathOptions, detour string) *udpPathConfig {
	t.Helper()
	config, err := newUDPPathConfig(&options, detour)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestUDPPathConfigValidation(t *testing.T) {
	config, err := newUDPPathConfig(nil, "")
	if err != nil || config != nil {
		t.Fatalf("nil options: config=%v err=%v", config, err)
	}
	config = mustUDPPathConfig(t, option.TailscaleUDPPathOptions{}, "")
	if config.defaultPath != udpPathDirect || config.usesDetour() {
		t.Fatal("empty default must mean direct")
	}
	invalid := []struct {
		name    string
		options option.TailscaleUDPPathOptions
		detour  string
	}{
		{"unknown default", option.TailscaleUDPPathOptions{Default: "proxy"}, "out"},
		{"unknown rule path", option.TailscaleUDPPathOptions{Peers: []option.TailscaleUDPPathPeer{{Match: []string{"mac"}, Path: "derp"}}}, "out"},
		{"missing rule path", option.TailscaleUDPPathOptions{Peers: []option.TailscaleUDPPathPeer{{Match: []string{"mac"}}}}, "out"},
		{"missing match", option.TailscaleUDPPathOptions{Peers: []option.TailscaleUDPPathPeer{{Path: "direct"}}}, "out"},
		{"empty match", option.TailscaleUDPPathOptions{Peers: []option.TailscaleUDPPathPeer{{Match: []string{" "}, Path: "direct"}}}, "out"},
		{"bad pattern", option.TailscaleUDPPathOptions{Peers: []option.TailscaleUDPPathPeer{{Match: []string{"mac["}, Path: "direct"}}}, "out"},
		{"default detour without detour", option.TailscaleUDPPathOptions{Default: "detour"}, ""},
		{"rule detour without detour", option.TailscaleUDPPathOptions{Peers: []option.TailscaleUDPPathPeer{{Match: []string{"mac"}, Path: "detour"}}}, ""},
	}
	for _, testCase := range invalid {
		options := testCase.options
		_, err = newUDPPathConfig(&options, testCase.detour)
		if err == nil {
			t.Errorf("%s: expected error", testCase.name)
		}
	}
	config = mustUDPPathConfig(t, option.TailscaleUDPPathOptions{
		Default: "direct",
		Peers:   []option.TailscaleUDPPathPeer{{Match: []string{"mac"}, Path: "detour"}},
	}, "out")
	if !config.usesDetour() {
		t.Fatal("a detour rule must enable udp_path")
	}
	config = mustUDPPathConfig(t, option.TailscaleUDPPathOptions{
		Default: "relay",
		Peers:   []option.TailscaleUDPPathPeer{{Match: []string{"mac"}, Path: "direct"}},
	}, "")
	if config.usesDetour() {
		t.Fatal("relay/direct only config must not use detour")
	}
}

func TestUDPPathPeerMatching(t *testing.T) {
	peer := newUDPPeer("MacBook-Home.tail1234.ts.net.", "MacBook Pro", netip.MustParseAddr("100.64.0.3"))
	if peer.display != "MacBook-Home" {
		t.Fatalf("display = %q", peer.display)
	}
	cases := []struct {
		pattern string
		matched bool
	}{
		{"macbook-home.tail1234.ts.net", true},
		{"MacBook-Home.tail1234.ts.net.", true},
		{"macbook-home", true},
		{"MACBOOK-HOME", true},
		{"macbook pro", true},
		{"*-home", true},
		{"mac*", true},
		{"*.tail1234.ts.net", true},
		{"macbook-h?me", true},
		{"macbook", false},
		{"*-office", false},
		{"nas.tail1234.ts.net", false},
		{"tail1234", false},
	}
	for _, testCase := range cases {
		if matched := peer.matches(normalizeUDPPathName(testCase.pattern)); matched != testCase.matched {
			t.Errorf("pattern %q: matched=%v, want %v", testCase.pattern, matched, testCase.matched)
		}
	}
	unnamed := newUDPPeer("", "", netip.MustParseAddr("100.64.0.9"))
	if unnamed.matches("*") {
		t.Fatal("a peer without names must not match")
	}
	if unnamed.display != "100.64.0.9" {
		t.Fatalf("display = %q", unnamed.display)
	}
}

var (
	testMacDisco = [32]byte{1}
	testNASDisco = [32]byte{2}
)

func testUDPPathRecords() []udpPathPeerRecord {
	return []udpPathPeerRecord{
		{
			peer:      newUDPPeer("macbook.tail1234.ts.net.", "MacBook", netip.MustParseAddr("100.64.0.3")),
			endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:41641"), netip.MustParseAddrPort("192.168.1.20:41641")},
			discoKey:  testMacDisco,
		},
		{
			peer:      newUDPPeer("nas.tail1234.ts.net.", "nas", netip.MustParseAddr("100.64.0.4")),
			endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:41641")},
			discoKey:  testNASDisco,
		},
	}
}

func testUDPPathConfig(t *testing.T) *udpPathConfig {
	return mustUDPPathConfig(t, option.TailscaleUDPPathOptions{
		Default: "detour",
		Peers: []option.TailscaleUDPPathPeer{
			{Match: []string{"macbook"}, Path: "direct"},
			{Match: []string{"nas.tail1234.ts.net"}, Path: "relay"},
		},
	}, "proxy-out")
}

func TestUDPPathClassify(t *testing.T) {
	config := testUDPPathConfig(t)
	state := newUDPPathState(testUDPPathRecords(), nil, nil)
	cases := []struct {
		destination string
		path        udpPathMode
		rule        int
		peer        string
	}{
		{"203.0.113.7:41641", udpPathDirect, 0, "macbook"},
		{"203.0.113.7:9999", udpPathDirect, 0, "macbook"},
		{"[::ffff:203.0.113.7]:41641", udpPathDirect, 0, "macbook"},
		{"198.51.100.9:41641", udpPathRelay, 1, "nas"},
		{"192.168.1.20:41641", udpPathDirect, udpPathRulePrivate, "macbook"},
		{"10.0.0.1:41641", udpPathDirect, udpPathRulePrivate, ""},
		{"[::ffff:10.0.0.1]:41641", udpPathDirect, udpPathRulePrivate, ""},
		{"[fe80::1]:41641", udpPathDirect, udpPathRulePrivate, ""},
		{"127.0.0.1:41641", udpPathDirect, udpPathRulePrivate, ""},
		{"[fd7a:115c:a1e0::1]:41641", udpPathDirect, udpPathRulePrivate, ""},
		{"192.0.2.50:3478", udpPathDetour, udpPathRuleDefault, ""},
		{"[2001:db8::1]:41641", udpPathDetour, udpPathRuleDefault, ""},
	}
	for _, testCase := range cases {
		decision := config.classify(netip.MustParseAddrPort(testCase.destination), state)
		if decision.path != testCase.path || decision.rule != testCase.rule {
			t.Errorf("%s: path=%v rule=%d, want path=%v rule=%d", testCase.destination, decision.path, decision.rule, testCase.path, testCase.rule)
		}
		var peerName string
		if decision.peer != nil {
			peerName = decision.peer.short
		}
		if peerName != testCase.peer {
			t.Errorf("%s: peer=%q, want %q", testCase.destination, peerName, testCase.peer)
		}
	}
	learned := map[netip.AddrPort]*udpPathLearned{netip.MustParseAddrPort("192.0.2.50:1234"): newUDPPathLearned(testNASDisco, time.Now())}
	learnedState := newUDPPathState(testUDPPathRecords(), nil, learned)
	decision := config.classify(netip.MustParseAddrPort("192.0.2.50:1234"), learnedState)
	if decision.path != udpPathRelay || decision.rule != 1 {
		t.Fatalf("learned reflexive address: path=%v rule=%d", decision.path, decision.rule)
	}
	decision = config.classify(netip.MustParseAddrPort("192.0.2.50:1235"), learnedState)
	if decision.path != udpPathDetour || decision.peer != nil {
		t.Fatalf("learned addresses match by port: path=%v", decision.path)
	}
}

func TestUDPPathPeersFromNetMap(t *testing.T) {
	discoKey := key.NewDisco().Public()
	networkMap := &netmap.NetworkMap{
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				Name:      "MacBook.tail1234.ts.net.",
				Hostinfo:  (&tailcfg.Hostinfo{Hostname: "MacBook-Pro"}).View(),
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
				Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:41641")},
				DiscoKey:  discoKey,
			}).View(),
			(&tailcfg.Node{Name: "bare.tail1234.ts.net."}).View(),
		},
	}
	records := udpPathPeersFromNetMap(networkMap)
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	record := records[0]
	if record.peer.name != "macbook.tail1234.ts.net" || record.peer.short != "macbook" || record.peer.hostname != "macbook-pro" {
		t.Fatalf("peer = %+v", record.peer)
	}
	if record.peer.tailscaleIP != netip.MustParseAddr("100.64.0.3") || len(record.endpoints) != 1 || record.discoKey != discoKey.Raw32() {
		t.Fatalf("record = %+v", record)
	}
	if records[1].peer.hostname != "" || records[1].discoKey != ([32]byte{}) {
		t.Fatalf("bare record = %+v", records[1])
	}
	if udpPathPeersFromNetMap(nil) != nil {
		t.Fatal("nil netmap must yield no records")
	}
}

type captureLogger struct {
	logger.ContextLogger
	access sync.Mutex
	infos  []string
	warns  []string
	errs   []string
}

func newCaptureLogger() *captureLogger {
	return &captureLogger{ContextLogger: logger.NOP()}
}

func (l *captureLogger) Info(args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.infos = append(l.infos, fmt.Sprint(args...))
}

func (l *captureLogger) Warn(args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.warns = append(l.warns, fmt.Sprint(args...))
}

func (l *captureLogger) Error(args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.errs = append(l.errs, fmt.Sprint(args...))
}

func (l *captureLogger) countInfo(substring string) int {
	l.access.Lock()
	defer l.access.Unlock()
	var count int
	for _, line := range l.infos {
		if strings.Contains(line, substring) {
			count++
		}
	}
	return count
}

func TestUDPPathDecisionLog(t *testing.T) {
	capture := newCaptureLogger()
	manager := newUDPPathManager(context.Background(), capture, testUDPPathConfig(t), nil, "hk-ss", nil)
	manager.refresh(testUDPPathRecords(), nil)
	destination := netip.MustParseAddrPort("192.0.2.50:3478")
	if manager.pathFor(destination) != udpPathDetour {
		t.Fatal("unknown destination must use default")
	}
	manager.pathFor(destination)
	if count := capture.countInfo("unknown peer → 192.0.2.50:3478 proxied detour=hk-ss rule=default"); count != 1 {
		t.Fatalf("decision logged %d times: %v", count, capture.infos)
	}
	// A peer-table change drops the cache; an unchanged decision stays quiet.
	records := testUDPPathRecords()
	records[1].endpoints = append(records[1].endpoints, netip.MustParseAddrPort("198.51.100.10:41641"))
	manager.refresh(records, nil)
	manager.pathFor(destination)
	if count := capture.countInfo("192.0.2.50:3478"); count != 1 {
		t.Fatalf("unchanged decision logged again: %v", capture.infos)
	}
	// A changed decision is logged at once.
	records[1].endpoints = append(records[1].endpoints, destination)
	manager.refresh(records, nil)
	if manager.pathFor(destination) != udpPathRelay {
		t.Fatal("refreshed peer table must reclassify")
	}
	if count := capture.countInfo("nas (100.64.0.4) → 192.0.2.50:3478 relay rule=peers[1]"); count != 1 {
		t.Fatalf("changed decision not logged: %v", capture.infos)
	}
	manager.pathFor(netip.MustParseAddrPort("192.168.1.20:41641"))
	if count := capture.countInfo("macbook (100.64.0.3) → 192.168.1.20:41641 direct rule=private"); count != 1 {
		t.Fatalf("private decision not logged: %v", capture.infos)
	}
	manager.pruneLogged(time.Now().Add(udpPathLogSuppress))
	manager.logAccess.Lock()
	remaining := len(manager.logged)
	manager.logAccess.Unlock()
	if remaining != 0 {
		t.Fatalf("expired log entries kept: %d", remaining)
	}
}

func TestUDPPathSummary(t *testing.T) {
	capture := newCaptureLogger()
	manager := newUDPPathManager(context.Background(), capture, testUDPPathConfig(t), nil, "out", nil)
	manager.logSummary()
	if len(capture.infos) != 0 {
		t.Fatal("an idle period must not be summarized")
	}
	manager.detourTx.add(3 << 20)
	manager.directTx.add(100)
	manager.relayDrop.add(10)
	manager.logSummary()
	if count := capture.countInfo("summary proxied tx 1 packets/3.0 MB rx 0 packets/0 B, direct tx 1 packets/100 B rx 0 packets/0 B, relay dropped 1 packets"); count != 1 {
		t.Fatalf("summary = %v", capture.infos)
	}
	manager.logSummary()
	if len(capture.infos) != 1 {
		t.Fatal("counters must reset after a summary")
	}
}

type fakeProxyPacket struct {
	payload     []byte
	destination netip.AddrPort
}

type fakeProxyConn struct {
	incoming  chan fakeProxyPacket
	writes    chan fakeProxyPacket
	done      chan struct{}
	closeOnce sync.Once
	access    sync.Mutex
	writeErr  error
}

func newFakeProxyConn() *fakeProxyConn {
	return &fakeProxyConn{
		incoming: make(chan fakeProxyPacket, 16),
		writes:   make(chan fakeProxyPacket, 16),
		done:     make(chan struct{}),
	}
}

func (c *fakeProxyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.incoming:
		return copy(p, packet.payload), M.SocksaddrFromNetIP(packet.destination).UDPAddr(), nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeProxyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	writeErr := c.writeErr
	c.access.Unlock()
	if writeErr != nil {
		return 0, writeErr
	}
	c.writes <- fakeProxyPacket{payload: bytes.Clone(p), destination: M.SocksaddrFromNet(addr).AddrPort()}
	return len(p), nil
}

func (c *fakeProxyConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *fakeProxyConn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *fakeProxyConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *fakeProxyConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeProxyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeProxyConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeProxyDialer struct {
	access       sync.Mutex
	calls        int
	failures     int
	destinations []M.Socksaddr
	conns        []*fakeProxyConn
}

func (d *fakeProxyDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unsupported")
}

func (d *fakeProxyDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	defer d.access.Unlock()
	d.calls++
	d.destinations = append(d.destinations, destination)
	if d.failures > 0 {
		d.failures--
		return nil, errors.New("detour unavailable")
	}
	conn := newFakeProxyConn()
	d.conns = append(d.conns, conn)
	return conn, nil
}

func (d *fakeProxyDialer) callCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.calls
}

func (d *fakeProxyDialer) lastConn() *fakeProxyConn {
	d.access.Lock()
	defer d.access.Unlock()
	if len(d.conns) == 0 {
		return nil
	}
	return d.conns[len(d.conns)-1]
}

func listenLoopbackUDP(ctx context.Context, network string, address string) (nettype.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func newTestUDPPathConn(t *testing.T, dialer *fakeProxyDialer) (*udpPathManager, *udpPathConn) {
	t.Helper()
	manager := newUDPPathManager(context.Background(), newCaptureLogger(), testUDPPathConfig(t), dialer, "proxy-out", listenLoopbackUDP)
	manager.refresh(testUDPPathRecords(), nil)
	packetConn, err := manager.listen(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	conn := packetConn.(*udpPathConn)
	t.Cleanup(func() { conn.Close() })
	return manager, conn
}

func waitUDPPath(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for ", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readUDPPath(t *testing.T, conn *udpPathConn) ([]byte, netip.AddrPort) {
	t.Helper()
	err := conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, source, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return buffer[:n], source
}

func TestUDPPathConnDirect(t *testing.T) {
	_, conn := newTestUDPPathConn(t, &fakeProxyDialer{})
	localAddr, isUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	if !isUDPAddr || localAddr.Port == 0 {
		t.Fatalf("LocalAddr must be the anchor's *net.UDPAddr, got %T %v", conn.LocalAddr(), conn.LocalAddr())
	}
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	remoteAddr := remote.LocalAddr().(*net.UDPAddr).AddrPort()
	n, err := conn.WriteToUDPAddrPort([]byte("to-remote"), remoteAddr)
	if err != nil || n != len("to-remote") {
		t.Fatalf("direct write: n=%d err=%v", n, err)
	}
	remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 2048)
	n, source, err := remote.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "to-remote" || source.Port() != uint16(localAddr.Port) {
		t.Fatalf("remote read: %q from %v err=%v", buffer[:n], source, err)
	}
	_, err = remote.WriteToUDPAddrPort([]byte("from-remote"), localAddr.AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	payload, source := readUDPPath(t, conn)
	if string(payload) != "from-remote" || source != remoteAddr {
		t.Fatalf("merged read: %q from %v", payload, source)
	}
}

func TestUDPPathConnDetourAndRelay(t *testing.T) {
	dialer := &fakeProxyDialer{}
	manager, conn := newTestUDPPathConn(t, dialer)
	destination := netip.MustParseAddrPort("192.0.2.50:3478")
	n, err := conn.WriteToUDPAddrPort([]byte("stun-1"), destination)
	if err != nil || n != len("stun-1") {
		t.Fatalf("pending detour write: n=%d err=%v", n, err)
	}
	waitUDPPath(t, "proxy socket", func() bool { return conn.shared.proxy.Load() != nil })
	if dialer.callCount() != 1 || dialer.destinations[0].AddrPort() != destination {
		t.Fatalf("dialer calls=%d destinations=%v", dialer.callCount(), dialer.destinations)
	}
	proxy := dialer.lastConn()
	_, err = conn.WriteToUDPAddrPort([]byte("stun-2"), destination)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-proxy.writes:
		if string(packet.payload) != "stun-2" || packet.destination != destination {
			t.Fatalf("proxy write: %q to %v", packet.payload, packet.destination)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy write not received")
	}
	if manager.detourPending.packets.Load() != 1 || manager.detourTx.packets.Load() != 1 {
		t.Fatalf("pending=%d tx=%d", manager.detourPending.packets.Load(), manager.detourTx.packets.Load())
	}

	proxy.incoming <- fakeProxyPacket{payload: []byte("stun-reply"), destination: destination}
	payload, source := readUDPPath(t, conn)
	if string(payload) != "stun-reply" || source != destination {
		t.Fatalf("proxy read: %q from %v", payload, source)
	}

	n, err = conn.WriteToUDPAddrPort([]byte("to-nas"), netip.MustParseAddrPort("198.51.100.9:41641"))
	if err != nil || n != len("to-nas") {
		t.Fatalf("relay write: n=%d err=%v", n, err)
	}
	select {
	case packet := <-proxy.writes:
		t.Fatalf("relay packet leaked to proxy: %q", packet.payload)
	case <-time.After(50 * time.Millisecond):
	}
	if manager.relayDrop.packets.Load() != 1 {
		t.Fatal("relay drop not counted")
	}
}

func TestUDPPathConnLearnsReflexiveAddress(t *testing.T) {
	dialer := &fakeProxyDialer{}
	manager, conn := newTestUDPPathConn(t, dialer)
	reflexive := netip.MustParseAddrPort("192.0.2.77:55555")
	if manager.pathFor(reflexive) != udpPathDetour {
		t.Fatal("unknown reflexive address must use default")
	}
	conn.WriteToUDPAddrPort([]byte("probe"), netip.MustParseAddrPort("192.0.2.50:3478"))
	waitUDPPath(t, "proxy socket", func() bool { return conn.shared.proxy.Load() != nil })
	discoPacket := []byte(disco.Magic)
	discoPacket = append(discoPacket, testNASDisco[:]...)
	discoPacket = append(discoPacket, make([]byte, disco.NonceLen+16)...)
	dialer.lastConn().incoming <- fakeProxyPacket{payload: discoPacket, destination: reflexive}
	payload, source := readUDPPath(t, conn)
	if !bytes.Equal(payload, discoPacket) || source != reflexive {
		t.Fatal("disco packet not delivered")
	}
	if manager.pathFor(reflexive) != udpPathRelay {
		t.Fatal("reflexive address must follow the disco sender's rule")
	}
}

func TestUDPPathConnProxyBackoff(t *testing.T) {
	dialer := &fakeProxyDialer{failures: 1}
	_, conn := newTestUDPPathConn(t, dialer)
	destination := netip.MustParseAddrPort("192.0.2.50:3478")
	conn.WriteToUDPAddrPort([]byte("a"), destination)
	waitUDPPath(t, "failed dial", func() bool {
		conn.proxyAccess.Lock()
		defer conn.proxyAccess.Unlock()
		return dialer.callCount() == 1 && !conn.shared.connecting
	})
	conn.proxyAccess.Lock()
	failures, retryAt := conn.shared.failures, conn.shared.retryAt
	conn.proxyAccess.Unlock()
	if failures != 1 || time.Until(retryAt) < 500*time.Millisecond {
		t.Fatalf("failures=%d retryIn=%v", failures, time.Until(retryAt))
	}
	n, err := conn.WriteToUDPAddrPort([]byte("b"), destination)
	if err != nil || n != 1 {
		t.Fatalf("write during backoff: n=%d err=%v", n, err)
	}
	time.Sleep(20 * time.Millisecond)
	if dialer.callCount() != 1 {
		t.Fatal("dial retried during backoff")
	}
	conn.proxyAccess.Lock()
	conn.shared.retryAt = time.Time{}
	conn.proxyAccess.Unlock()
	conn.WriteToUDPAddrPort([]byte("c"), destination)
	waitUDPPath(t, "proxy socket", func() bool { return conn.shared.proxy.Load() != nil })

	proxy := dialer.lastConn()
	proxy.access.Lock()
	proxy.writeErr = errors.New("broken pipe")
	proxy.access.Unlock()
	n, err = conn.WriteToUDPAddrPort([]byte("d"), destination)
	if err != nil || n != 1 {
		t.Fatalf("write on broken proxy: n=%d err=%v", n, err)
	}
	if conn.shared.proxy.Load() != nil {
		t.Fatal("broken proxy socket must be dropped")
	}
	waitUDPPath(t, "broken proxy socket closed", proxy.isClosed)
	conn.proxyAccess.Lock()
	failures = conn.shared.failures
	conn.proxyAccess.Unlock()
	if failures != 2 {
		t.Fatalf("failures=%d", failures)
	}

	expected := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	conn.proxyAccess.Lock()
	conn.shared.failures = 0
	for index, want := range expected {
		if delay := conn.shared.backoffLocked(); delay != want {
			t.Errorf("backoff #%d = %v, want %v", index+1, delay, want)
		}
	}
	conn.proxyAccess.Unlock()
}

func TestUDPPathConnDeadlineAndClose(t *testing.T) {
	dialer := &fakeProxyDialer{}
	_, conn := newTestUDPPathConn(t, dialer)
	err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_, _, err = conn.ReadFromUDPAddrPort(buffer)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past deadline: %v", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal("deadline error must be a timeout")
	}
	err = conn.SetReadDeadline(time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadFromUDPAddrPort(buffer)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read with past deadline: %v", err)
	}
	conn.SetReadDeadline(time.Time{})

	conn.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("192.0.2.50:3478"))
	waitUDPPath(t, "proxy socket", func() bool { return conn.shared.proxy.Load() != nil })
	proxy := dialer.lastConn()

	readResult := make(chan error, 1)
	go func() {
		_, _, readErr := conn.ReadFromUDPAddrPort(buffer)
		readResult <- readErr
	}()
	time.Sleep(20 * time.Millisecond)
	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case readErr := <-readResult:
		if !errors.Is(readErr, net.ErrClosed) {
			t.Fatalf("blocked read after close: %v", readErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock the reader")
	}
	waitUDPPath(t, "proxy socket closed", proxy.isClosed)
	_, err = conn.WriteToUDPAddrPort([]byte("y"), netip.MustParseAddrPort("192.0.2.50:3478"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	if conn.Close() != nil {
		t.Fatal("second Close must be a no-op")
	}
}

func testUDPPathDiscoPacket(discoKey [32]byte) []byte {
	packet := []byte(disco.Magic)
	packet = append(packet, discoKey[:]...)
	return append(packet, make([]byte, disco.NonceLen+16)...)
}

func testUDPPathSTUNRequest() []byte {
	packet := make([]byte, 20)
	packet[1] = 0x01
	copy(packet[4:8], []byte{0x21, 0x12, 0xA4, 0x42})
	return packet
}

func TestUDPPathAmbiguousHost(t *testing.T) {
	config := testUDPPathConfig(t)
	records := testUDPPathRecords()
	shared := netip.MustParseAddr("203.0.113.50")
	records[0].endpoints = append(records[0].endpoints, netip.AddrPortFrom(shared, 41641))
	records[1].endpoints = append(records[1].endpoints, netip.AddrPortFrom(shared, 41642))
	state := newUDPPathState(records, nil, nil)
	cases := []struct {
		destination netip.AddrPort
		path        udpPathMode
		peer        string
	}{
		{netip.AddrPortFrom(shared, 41641), udpPathDirect, "macbook"},
		{netip.AddrPortFrom(shared, 41642), udpPathRelay, "nas"},
		{netip.AddrPortFrom(shared, 5000), udpPathDetour, ""},
	}
	for _, testCase := range cases {
		decision := config.classify(testCase.destination, state)
		var peerName string
		if decision.peer != nil {
			peerName = decision.peer.short
		}
		if decision.path != testCase.path || peerName != testCase.peer {
			t.Errorf("%v: path=%v peer=%q, want path=%v peer=%q", testCase.destination, decision.path, peerName, testCase.path, testCase.peer)
		}
	}
	// A learned mapping attributes a shared IP's unknown port.
	learned := map[netip.AddrPort]*udpPathLearned{netip.AddrPortFrom(shared, 5000): newUDPPathLearned(testMacDisco, time.Now())}
	decision := config.classify(netip.AddrPortFrom(shared, 5000), state.withLearned(learned))
	if decision.path != udpPathDirect || decision.peer == nil || decision.peer.short != "macbook" {
		t.Fatalf("learned port on shared IP: path=%v peer=%v", decision.path, decision.peer)
	}
	// The same endpoint claimed by two peers is attributed to neither.
	records[1].endpoints = append(records[1].endpoints, netip.AddrPortFrom(shared, 41641))
	decision = config.classify(netip.AddrPortFrom(shared, 41641), newUDPPathState(records, nil, nil))
	if decision.path != udpPathDetour || decision.peer != nil {
		t.Fatalf("ambiguous endpoint: path=%v peer=%v", decision.path, decision.peer)
	}
}

func TestUDPPathObserveExactEndpoint(t *testing.T) {
	manager := newUDPPathManager(context.Background(), newCaptureLogger(), testUDPPathConfig(t), nil, "out", nil)
	manager.refresh(testUDPPathRecords(), nil)
	// The NAS's disco from the MacBook's exact endpoint is not learned.
	macEndpoint := netip.MustParseAddrPort("203.0.113.7:41641")
	manager.observe(macEndpoint, testUDPPathDiscoPacket(testNASDisco))
	if len(manager.state.Load().learned) != 0 || manager.pathFor(macEndpoint) != udpPathDirect {
		t.Fatal("an exact netmap endpoint must not be relearned")
	}
	// Another port on the MacBook's IP is learned: the exact address wins
	// over the IP-only match.
	otherPort := netip.MustParseAddrPort("203.0.113.7:50000")
	manager.observe(otherPort, testUDPPathDiscoPacket(testNASDisco))
	if manager.pathFor(otherPort) != udpPathRelay {
		t.Fatal("a learned address must take precedence over the IP-only match")
	}
}

func TestUDPPathSTUNAndDERPNotLearnable(t *testing.T) {
	dialer := &fakeProxyDialer{}
	manager, conn := newTestUDPPathConn(t, dialer)
	stunServer := netip.MustParseAddrPort("192.0.2.80:3478")
	if !isUDPPathSTUNRequest(testUDPPathSTUNRequest()) || isUDPPathSTUNRequest(testUDPPathDiscoPacket(testNASDisco)) {
		t.Fatal("STUN detection")
	}
	wireGuard := make([]byte, 32)
	wireGuard[0] = 1
	copy(wireGuard[4:8], []byte{0x21, 0x12, 0xA4, 0x42})
	if isUDPPathSTUNRequest(wireGuard) {
		t.Fatal("a WireGuard packet must not be taken for STUN")
	}
	_, err := conn.WriteToUDPAddrPort(testUDPPathSTUNRequest(), stunServer)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.isSTUNTarget(stunServer) {
		t.Fatal("STUN destination not marked")
	}
	manager.observe(stunServer, testUDPPathDiscoPacket(testNASDisco))
	if manager.state.Load().learned[stunServer] != nil {
		t.Fatal("a STUN target must not be learned")
	}
	// Marking drops a mapping learned before the STUN request.
	reflexive := netip.MustParseAddrPort("192.0.2.81:3478")
	manager.observe(reflexive, testUDPPathDiscoPacket(testNASDisco))
	if manager.state.Load().learned[reflexive] == nil {
		t.Fatal("reflexive address not learned")
	}
	manager.markSTUN(reflexive)
	if manager.state.Load().learned[reflexive] != nil {
		t.Fatal("marking a STUN target must drop its learned mapping")
	}
	derpNode := netip.MustParseAddr("192.0.2.90")
	manager.refresh(testUDPPathRecords(), []netip.Addr{derpNode})
	manager.observe(netip.AddrPortFrom(derpNode, 41641), testUDPPathDiscoPacket(testNASDisco))
	if manager.state.Load().learned[netip.AddrPortFrom(derpNode, 41641)] != nil {
		t.Fatal("a DERP node address must not be learned")
	}
}

func TestUDPPathDERPAddrs(t *testing.T) {
	networkMap := &netmap.NetworkMap{DERPMap: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {Nodes: []*tailcfg.DERPNode{{IPv4: "192.0.2.90", IPv6: "2001:db8::90"}, {HostName: "derp.example.com"}}},
		2: nil,
	}}}
	addrs := udpPathDERPAddrs(networkMap)
	if len(addrs) != 2 {
		t.Fatalf("derp addrs = %v", addrs)
	}
	if udpPathDERPAddrs(nil) != nil || udpPathDERPAddrs(&netmap.NetworkMap{}) != nil {
		t.Fatal("no DERP map must yield no addresses")
	}
}

func TestUDPPathLearnedConflict(t *testing.T) {
	capture := newCaptureLogger()
	manager := newUDPPathManager(context.Background(), capture, testUDPPathConfig(t), nil, "out", nil)
	manager.refresh(testUDPPathRecords(), nil)
	source := netip.MustParseAddrPort("192.0.2.77:55555")
	manager.observe(source, testUDPPathDiscoPacket(testMacDisco))
	if manager.pathFor(source) != udpPathDirect {
		t.Fatal("first disco sender must be learned")
	}
	manager.observe(source, testUDPPathDiscoPacket(testNASDisco))
	if manager.pathFor(source) != udpPathDirect {
		t.Fatal("a fresh mapping must not be replaced by another peer")
	}
	capture.access.Lock()
	warned := len(capture.warns)
	capture.access.Unlock()
	if warned != 1 {
		t.Fatalf("conflict warnings = %d", warned)
	}
	manager.state.Load().learned[source].seen.Store(time.Now().Add(-udpPathLearnTTL).UnixNano())
	manager.observe(source, testUDPPathDiscoPacket(testNASDisco))
	if manager.pathFor(source) != udpPathRelay {
		t.Fatal("an idle mapping must be replaced")
	}
}

func TestUDPPathConnDestinationPool(t *testing.T) {
	dialer := &fakeProxyDialer{}
	manager, conn := newTestUDPPathConn(t, dialer)
	manager.destinationBound.Store(true)
	first := netip.MustParseAddrPort("192.0.2.50:3478")
	second := netip.MustParseAddrPort("192.0.2.60:3478")
	conn.WriteToUDPAddrPort([]byte("a"), first)
	conn.WriteToUDPAddrPort([]byte("b"), second)
	poolProxy := func(destination netip.AddrPort) *udpPathProxy {
		conn.proxyAccess.Lock()
		defer conn.proxyAccess.Unlock()
		slot := conn.pool[destination]
		if slot == nil {
			return nil
		}
		return slot.proxy.Load()
	}
	waitUDPPath(t, "pool sockets", func() bool { return poolProxy(first) != nil && poolProxy(second) != nil })
	if conn.shared.proxy.Load() != nil || dialer.callCount() != 2 {
		t.Fatalf("shared=%v calls=%d", conn.shared.proxy.Load(), dialer.callCount())
	}
	for _, destination := range []netip.AddrPort{first, second} {
		proxy := poolProxy(destination).conn.(*fakeProxyConn)
		_, err := conn.WriteToUDPAddrPort([]byte(destination.String()), destination)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case packet := <-proxy.writes:
			if string(packet.payload) != destination.String() || packet.destination != destination {
				t.Fatalf("pool write: %q to %v", packet.payload, packet.destination)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("pool write not received")
		}
	}
	idle := poolProxy(first).conn.(*fakeProxyConn)
	conn.proxyAccess.Lock()
	conn.pool[first].lastUsed.Store(time.Now().Add(-udpPathPoolIdle).UnixNano())
	conn.proxyAccess.Unlock()
	closeUDPPathProxies(conn.expireIdle(time.Now()))
	waitUDPPath(t, "idle pool socket closed", idle.isClosed)
	if poolProxy(first) != nil || poolProxy(second) == nil {
		t.Fatal("only the idle destination must expire")
	}
	conn.proxyAccess.Lock()
	for index := 0; len(conn.pool) < udpPathPoolLimit; index++ {
		conn.poolSlotLocked(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.200"), uint16(10000+index)), time.Now())
	}
	conn.pool[second].lastUsed.Store(0)
	_, evicted := conn.poolSlotLocked(netip.MustParseAddrPort("192.0.2.201:1"), time.Now())
	_, kept := conn.pool[second]
	size := len(conn.pool)
	conn.proxyAccess.Unlock()
	if size != udpPathPoolLimit || kept || len(evicted) != 1 {
		t.Fatalf("eviction: size=%d kept=%v evicted=%d", size, kept, len(evicted))
	}
	closeUDPPathProxies(evicted)
}

type blockingProxyConn struct {
	release chan struct{}
}

func (c *blockingProxyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.release
	return 0, nil, net.ErrClosed
}

func (c *blockingProxyConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }

func (c *blockingProxyConn) Close() error {
	<-c.release
	return nil
}

func (c *blockingProxyConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *blockingProxyConn) SetDeadline(t time.Time) error      { return nil }
func (c *blockingProxyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *blockingProxyConn) SetWriteDeadline(t time.Time) error { return nil }

type blockingProxyDialer struct {
	fakeProxyDialer
	conn *blockingProxyConn
}

func (d *blockingProxyDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.conn, nil
}

func TestUDPPathConnCloseDoesNotWaitForProxy(t *testing.T) {
	dialer := &blockingProxyDialer{conn: &blockingProxyConn{release: make(chan struct{})}}
	defer close(dialer.conn.release)
	manager := newUDPPathManager(context.Background(), newCaptureLogger(), testUDPPathConfig(t), dialer, "proxy-out", listenLoopbackUDP)
	packetConn, err := manager.listen(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	conn := packetConn.(*udpPathConn)
	conn.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("192.0.2.50:3478"))
	waitUDPPath(t, "proxy socket", func() bool { return conn.shared.proxy.Load() != nil })
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on a proxy socket that does not unblock")
	}
}

func TestUDPPathProxyDegraded(t *testing.T) {
	capture := newCaptureLogger()
	manager := newUDPPathManager(context.Background(), capture, testUDPPathConfig(t), nil, "out", nil)
	manager.refresh(testUDPPathRecords(), nil)
	for index := 0; index < udpPathFailureLimit+2; index++ {
		if manager.statusPath("192.0.2.50:41641", "") != "detour" && index < udpPathFailureLimit {
			t.Fatalf("degraded after %d failures", index)
		}
		manager.proxyFailed(errors.New("udp not supported"))
	}
	if manager.statusPath("192.0.2.50:41641", "") != "relay" || manager.statusPath("203.0.113.7:41641", "") != "direct" {
		t.Fatal("a failing detour must be reported as relay, other paths unchanged")
	}
	capture.access.Lock()
	errorCount := len(capture.errs)
	capture.access.Unlock()
	if errorCount != 1 {
		t.Fatalf("error logged %d times", errorCount)
	}
	manager.proxySucceeded()
	if manager.statusPath("192.0.2.50:41641", "") != "detour" {
		t.Fatal("a recovered detour must be reported again")
	}
}

type fakeUDPPathOutbound struct {
	adapter.Outbound
	bound bool
}

func (o *fakeUDPPathOutbound) UDPDestinationBound() bool { return o.bound }

type fakeUDPPathGroup struct {
	adapter.Outbound
	now string
}

func (g *fakeUDPPathGroup) All() []string { return []string{g.now} }

func (g *fakeUDPPathGroup) Selected(string) adapter.Outbound {
	if g.now == "" {
		return nil
	}
	return &fakeUDPPathTag{tag: g.now}
}

func (g *fakeUDPPathGroup) AttachConnection(io.Closer) func() { return func() {} }

// fakeUDPPathTag is a group's selection, known by its tag only.
type fakeUDPPathTag struct {
	adapter.Outbound
	tag string
}

func (t *fakeUDPPathTag) Tag() string { return t.tag }

type fakeUDPPathOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *fakeUDPPathOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func TestResolveUDPPathDetour(t *testing.T) {
	manager := &fakeUDPPathOutboundManager{outbounds: map[string]adapter.Outbound{
		"vmess":    &fakeUDPPathOutbound{bound: true},
		"ss":       &fakeUDPPathOutbound{},
		"select":   &fakeUDPPathGroup{now: "auto"},
		"auto":     &fakeUDPPathGroup{now: "vmess"},
		"empty":    &fakeUDPPathGroup{},
		"loop":     &fakeUDPPathGroup{now: "loop"},
		"no-group": &fakeUDPPathGroup{now: "missing"},
	}}
	cases := []struct {
		tag      string
		resolved string
		bound    bool
		known    bool
	}{
		{"vmess", "vmess", true, true},
		{"ss", "ss", false, true},
		{"select", "vmess", true, true},
		{"empty", "empty", false, false},
		{"loop", "loop", false, false},
		{"no-group", "missing", false, false},
		{"absent", "absent", false, false},
	}
	for _, testCase := range cases {
		resolved, bound, known := resolveUDPPathDetour(manager, testCase.tag)
		if resolved != testCase.resolved || bound != testCase.bound || known != testCase.known {
			t.Errorf("%s: resolved=%s bound=%v known=%v", testCase.tag, resolved, bound, known)
		}
	}
	resolved, _, known := resolveUDPPathDetour(nil, "x")
	if resolved != "x" || known {
		t.Fatal("no outbound manager must be unknown")
	}
}

func TestUDPPathEndpointRegistration(t *testing.T) {
	first := &Endpoint{Adapter: endpoint.NewAdapter("tailscale", "first", nil, nil)}
	second := &Endpoint{Adapter: endpoint.NewAdapter("tailscale", "second", nil, nil)}
	if registerUDPPathEndpoint(first, true) != nil || registerUDPPathEndpoint(first, true) != nil {
		t.Fatal("registering the same endpoint again must succeed")
	}
	if registerUDPPathEndpoint(second, false) == nil {
		t.Fatal("another endpoint must not start beside a udp_path endpoint")
	}
	unregisterUDPPathEndpoint(first)
	unregisterUDPPathEndpoint(first)
	if registerUDPPathEndpoint(second, true) != nil {
		t.Fatal("a reloaded endpoint must start once the previous one released the guard")
	}
	setNetnsListenPacketFunc(second, listenLoopbackUDP)
	clearNetnsListenPacketFunc(first)
	udpPathEndpoints.access.Lock()
	owner := udpPathEndpoints.listenerOwner
	udpPathEndpoints.access.Unlock()
	if owner != second {
		t.Fatal("a closing endpoint must not clear another endpoint's hook")
	}
	clearNetnsListenPacketFunc(second)
	unregisterUDPPathEndpoint(second)
	udpPathEndpoints.access.Lock()
	active, guard := len(udpPathEndpoints.active), udpPathEndpoints.owner
	udpPathEndpoints.access.Unlock()
	if active != 0 || guard != nil {
		t.Fatalf("active=%d owner=%v", active, guard)
	}
}
