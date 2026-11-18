//go:build with_gvisor

package tailscale

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

// fakeNetstackImpl stands in for Tailscale's netstack.Impl, which keeps its
// gVisor stack in the unexported ipstack field.
type fakeNetstackImpl struct {
	ProcessLocalIPs bool
	ipstack         *stack.Stack
}

type fakeNetstackWrongType struct {
	ipstack *int
}

type fakeNetstackMissing struct {
	stack *stack.Stack
}

func newTestTCPStack(t *testing.T) *stack.Stack {
	t.Helper()
	ipStack := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() {
		ipStack.Close()
		ipStack.Wait()
	})
	return ipStack
}

func TestNetstackIPStackSetCubic(t *testing.T) {
	ipStack := newTestTCPStack(t)
	impl := &fakeNetstackImpl{ipstack: ipStack}
	found, err := netstackIPStack(impl)
	if err != nil {
		t.Fatal(err)
	}
	if found != ipStack {
		t.Fatal("netstackIPStack returned a different stack")
	}
	current, err := setStackTCPCongestionControl(found, tcpCongestionControlCubic)
	if err != nil {
		t.Fatal(err)
	}
	if current != tcpCongestionControlCubic {
		t.Fatalf("congestion control = %q, want cubic", current)
	}
	current, err = setStackTCPCongestionControl(found, tcpCongestionControlReno)
	if err != nil {
		t.Fatal(err)
	}
	if current != tcpCongestionControlReno {
		t.Fatalf("congestion control = %q, want reno", current)
	}
	if _, err = setStackTCPCongestionControl(found, "bbr"); err == nil {
		t.Fatal("expected an error for an unavailable algorithm")
	}
}

func TestNetstackIPStackErrors(t *testing.T) {
	var intValue int
	for name, impl := range map[string]any{
		"nil":            nil,
		"non-pointer":    fakeNetstackImpl{},
		"nil pointer":    (*fakeNetstackImpl)(nil),
		"nil field":      &fakeNetstackImpl{},
		"wrong type":     &fakeNetstackWrongType{ipstack: &intValue},
		"missing":        &fakeNetstackMissing{},
		"pointer to int": &intValue,
	} {
		if _, err := netstackIPStack(impl); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestValidateTCPCongestionControl(t *testing.T) {
	for _, name := range []string{"", "reno", "cubic"} {
		if err := validateTCPCongestionControl(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"bbr", "Cubic", " reno"} {
		if err := validateTCPCongestionControl(name); err == nil {
			t.Errorf("%q: expected an error", name)
		}
	}
}
