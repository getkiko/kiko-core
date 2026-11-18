//go:build linux

package burrow

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/control"

	"github.com/getkiko/burrow"
)

func TestSystemInterfaceIndex(t *testing.T) {
	index, supported, err := systemInterfaceIndex("lo")
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("expected ioctl interface lookup support")
	}
	if index <= 0 {
		t.Fatalf("expected a positive loopback interface index, got %d", index)
	}
}

func TestSystemInterfaceIPv4(t *testing.T) {
	address, supported, err := systemInterfaceIPv4("lo")
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("expected ioctl interface lookup support")
	}
	if got := address.String(); got != "127.0.0.1" {
		t.Fatalf("expected loopback IPv4 address, got %q", got)
	}
}

func TestInterfaceAddrFuncFallsBackToIoctl(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, networkInterface := range interfaces {
		address, _, lookupErr := systemInterfaceIPv4(networkInterface.Name)
		if lookupErr != nil || address.IsLoopback() || address.IsUnspecified() {
			continue
		}
		manager := &stubNetworkManager{finder: &stubFinder{err: errors.New("netlinkrib: permission denied")}}
		if got := interfaceAddrFunc(manager, burrow.AddressFamilyIPv4, nil)(networkInterface.Name); got != address.String() {
			t.Fatalf("expected ioctl IPv4 %q for interface %q, got %q", address, networkInterface.Name, got)
		}
		return
	}
	t.Skip("no non-loopback IPv4 interface available")
}

type failingCountingFinder struct {
	control.InterfaceFinder
	calls atomic.Int32
}

func (f *failingCountingFinder) ByName(string) (*control.Interface, error) {
	f.calls.Add(1)
	return nil, errors.New("netlinkrib: permission denied")
}

func TestBindInterfaceControlUsesIoctlIndex(t *testing.T) {
	finder := &failingCountingFinder{}
	manager := &stubNetworkManager{finder: finder}
	listenConfig := net.ListenConfig{Control: bindInterfaceControl(manager, "lo", nil)}
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if calls := finder.calls.Load(); calls != 0 {
		t.Fatalf("expected ioctl index to bypass finder, got %d finder calls", calls)
	}
}
