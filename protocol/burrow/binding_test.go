package burrow

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/getkiko/burrow"
)

type stubNetworkManager struct {
	defaultInterface string
	autoDetect       bool
	currentInterface *adapter.NetworkInterface
	finder           control.InterfaceFinder
}

func (s *stubNetworkManager) InterfaceFinder() control.InterfaceFinder {
	if s.finder != nil {
		return s.finder
	}
	return control.NewDefaultInterfaceFinder()
}

// stubFinder mimics the interface table detected by the sing-box platform
// interface without touching netlink.
type stubFinder struct {
	control.InterfaceFinder
	byName map[string]*control.Interface
	err    error
}

func (s *stubFinder) ByName(name string) (*control.Interface, error) {
	if s.err != nil {
		return nil, s.err
	}
	if iif, ok := s.byName[name]; ok {
		return iif, nil
	}
	return nil, os.ErrNotExist
}

func (s *stubNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface {
	return s.currentInterface
}

func (s *stubNetworkManager) AutoDetectInterface() bool { return s.autoDetect }

func (s *stubNetworkManager) AutoDetectInterfaceFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error { return nil }
}

func (s *stubNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{BindInterface: s.defaultInterface}
}

func mustFailBinding(t *testing.T, name string, nm interfaceBindingManager) {
	t.Helper()
	interfaceName, ctrl, err := socketBindingForNetworkManager(nm, "", nil)
	if !errors.Is(err, errNoBindInterface) || interfaceName != nil || ctrl != nil {
		t.Fatalf("%s: expected errNoBindInterface, got %v", name, err)
	}
}

// Case 1: an explicit bind_interface has the highest priority.
func TestSocketBindingExplicitInterface(t *testing.T) {
	name, ctrl, _ := socketBindingForNetworkManager(&stubNetworkManager{}, "en0", nil)
	if name == nil || name() != "en0" {
		t.Fatal("expected en0")
	}
	if ctrl == nil {
		t.Fatal("expected a non-nil control")
	}
}

// Case 2: route.default_interface is the fallback.
func TestSocketBindingDefaultInterface(t *testing.T) {
	nm := &stubNetworkManager{defaultInterface: "eth1"}
	name, ctrl, _ := socketBindingForNetworkManager(nm, "", nil)
	if name == nil || name() != "eth1" {
		t.Fatal("expected eth1")
	}
	if ctrl == nil {
		t.Fatal("expected a non-nil control")
	}
}

// Case 3: none of the three is available, which is a configuration error.
func TestSocketBindingFailsWhenUndetermined(t *testing.T) {
	mustFailBinding(t, "auto_detect=false", &stubNetworkManager{autoDetect: false})
}

// A missing networkManager (no service in the context) fails as well.
func TestSocketBindingFailsWithoutNetworkManager(t *testing.T) {
	mustFailBinding(t, "nil networkManager", nil)
}

// Case 4: auto_detect is enabled and finds an interface.
func TestSocketBindingAutoDetect(t *testing.T) {
	nm := &stubNetworkManager{
		autoDetect:       true,
		currentInterface: &adapter.NetworkInterface{Interface: control.Interface{Name: "wlan0"}},
	}
	name, _, _ := socketBindingForNetworkManager(nm, "", nil)
	if name == nil || name() != "wlan0" {
		t.Fatal("expected wlan0")
	}
}

// Case 4, degraded: auto_detect is enabled but finds no interface at runtime;
// the attempt gets a name no interface has instead of an unbound socket.
func TestSocketBindingAutoDetectWithoutInterface(t *testing.T) {
	nm := &stubNetworkManager{autoDetect: true, currentInterface: nil}
	name, _, err := socketBindingForNetworkManager(nm, "", nil)
	if err != nil || name == nil {
		t.Fatalf("expected an interfaceName closure, got %v", err)
	}
	if got := name(); got != noDefaultInterface {
		t.Fatalf("expected %q, got %q", noDefaultInterface, got)
	}
}

// interfaceAddrFunc takes IPv4 from the interface table sing-box already
// detected without touching netlink. This is the path that avoids netlinkrib
// permission denied on Android.
func TestInterfaceAddrFuncReturnsIPv4(t *testing.T) {
	nm := &stubNetworkManager{finder: &stubFinder{byName: map[string]*control.Interface{
		"wlan0": {Name: "wlan0", Addresses: []netip.Prefix{
			netip.MustParsePrefix("fe80::1/64"),      // IPv6 is skipped
			netip.MustParsePrefix("127.0.0.1/8"),     // loopback is skipped
			netip.MustParsePrefix("192.168.1.23/24"), // match
		}},
	}}}
	addr := interfaceAddrFunc(nm, burrow.AddressFamilyIPv4, nil)
	if addr == nil {
		t.Fatal("expected non-nil")
	}
	if got := addr("wlan0"); got != "192.168.1.23" {
		t.Fatalf("expected 192.168.1.23, got %q", got)
	}
}

// A failed lookup returns an empty string so the SDK falls back to its own
// lookup; it must not panic or fail.
func TestInterfaceAddrFuncReturnsEmptyOnError(t *testing.T) {
	nm := &stubNetworkManager{finder: &stubFinder{err: errors.New("netlinkrib: permission denied")}}
	addr := interfaceAddrFunc(nm, burrow.AddressFamilyIPv4, nil)
	if addr == nil {
		t.Fatal("expected non-nil")
	}
	if got := addr("burrow-missing0"); got != "" {
		t.Fatalf("expected an empty string, got %q", got)
	}
}

// An interface with only IPv6 addresses returns an empty string.
func TestInterfaceAddrFuncReturnsEmptyWithoutIPv4(t *testing.T) {
	nm := &stubNetworkManager{finder: &stubFinder{byName: map[string]*control.Interface{
		"burrow-v6only": {Name: "burrow-v6only", Addresses: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}},
	}}}
	if got := interfaceAddrFunc(nm, burrow.AddressFamilyIPv4, nil)("burrow-v6only"); got != "" {
		t.Fatalf("expected an empty string, got %q", got)
	}
}

func TestInterfaceAddrFuncReturnsGlobalIPv6(t *testing.T) {
	nm := &stubNetworkManager{finder: &stubFinder{byName: map[string]*control.Interface{
		"warp0": {Name: "warp0", Addresses: []netip.Prefix{
			netip.MustParsePrefix("fe80::1/64"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("2606:4700:110:8765::2/128"),
			netip.MustParsePrefix("192.168.1.23/24"),
		}},
	}}}
	if got := interfaceAddrFunc(nm, burrow.AddressFamilyIPv6, nil)("warp0"); got != "2606:4700:110:8765::2" {
		t.Fatalf("expected the WARP IPv6 address, got %q", got)
	}
}

func TestInterfaceAddrFuncIPv6FiltersLocalAddresses(t *testing.T) {
	nm := &stubNetworkManager{finder: &stubFinder{byName: map[string]*control.Interface{
		"local6": {Name: "local6", Addresses: []netip.Prefix{
			netip.MustParsePrefix("::/128"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("fe80::1/64"),
		}},
	}}}
	if got := interfaceAddrFunc(nm, burrow.AddressFamilyIPv6, nil)("local6"); got != "" {
		t.Fatalf("expected an empty string, got %q", got)
	}
}

// A missing networkManager returns nil and the SDK skips this source.
func TestInterfaceAddrFuncNilManager(t *testing.T) {
	if interfaceAddrFunc(nil, burrow.AddressFamilyIPv6, nil) != nil {
		t.Fatal("expected nil")
	}
}

// countingLogger counts the errors logged.
type countingLogger struct {
	log.ContextLogger
	errors []string
}

func (l *countingLogger) Error(args ...any) { l.errors = append(l.errors, fmt.Sprint(args...)) }

// While auto_detect_interface finds no default interface, every attempt asks
// for the interface name; the missing interface is logged once per interval,
// saying that no default interface is available.
func TestSocketBindingAutoDetectLogsMissingInterfaceOncePerInterval(t *testing.T) {
	nm := &stubNetworkManager{autoDetect: true}
	logger := &countingLogger{ContextLogger: log.NewNOPFactory().NewLogger("")}
	name, _, err := socketBindingForNetworkManager(nm, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if got := name(); got != noDefaultInterface {
			t.Fatalf("name %q", got)
		}
	}
	if len(logger.errors) != 1 || !strings.Contains(logger.errors[0], "no default network interface") || strings.Contains(logger.errors[0], "bind_interface") {
		t.Fatalf("errors %q", logger.errors)
	}
}

func TestLogLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLogLimiter(time.Minute)
	l.now = func() time.Time { return now }
	if !l.allow() || l.allow() {
		t.Fatal("first message")
	}
	now = now.Add(59 * time.Second)
	if l.allow() {
		t.Fatal("within the interval")
	}
	now = now.Add(time.Second)
	if !l.allow() {
		t.Fatal("after the interval")
	}
}

// An outbound following auto_detect_interface fails at once without a
// default interface, with an error that says so, and is not retried.
func TestOutboundWithoutDefaultInterface(t *testing.T) {
	nm := &stubNetworkManager{autoDetect: true}
	out := &Outbound{logger: log.NewNOPFactory().NewLogger(""), defaultMissing: defaultInterfaceMissing(nm, "")}
	_, err := out.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	var nonRetryable *dialer.NonRetryableError
	if !errors.Is(err, errNoDefaultInterface) || !errors.As(err, &nonRetryable) {
		t.Fatalf("dial: %v", err)
	}
	if defaultInterfaceMissing(nm, "en0") != nil || defaultInterfaceMissing(&stubNetworkManager{autoDetect: true, defaultInterface: "eth0"}, "") != nil ||
		defaultInterfaceMissing(&stubNetworkManager{}, "") != nil || defaultInterfaceMissing(nil, "") != nil {
		t.Fatal("defaultMissing for a binding that does not follow auto_detect_interface")
	}
	nm.currentInterface = &adapter.NetworkInterface{Interface: control.Interface{Name: "wlan0"}}
	if out.defaultMissing() {
		t.Fatal("interface present")
	}
}
