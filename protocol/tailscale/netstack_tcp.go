//go:build with_gvisor

package tailscale

import (
	"reflect"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	E "github.com/sagernet/sing/common/exceptions"
)

// Tailscale's netstack (wgengine/netstack.Create) pins the gVisor TCP
// congestion control to reno, because gVisor's sender had an int overflow in
// congestion window arithmetic that cubic triggered more easily
// (https://github.com/google/gvisor/issues/11632). The gVisor we build with
// already carries that fix (pkg/tcpip/transport/tcp/snd.go), so the
// tcp_congestion_control option may switch the stack to cubic, which keeps a
// much larger window on long fat paths such as a WireGuard tunnel over a proxy.
//
// Tailscale exposes the *netstack.Impl but keeps its *stack.Stack in the
// unexported field "ipstack". Reaching it needs reflect + unsafe and depends on
// Tailscale's internal field name and type: when either changes, the helpers
// below return an error and the caller only logs a warning and keeps reno.

const tailscaleNetstackStackField = "ipstack"

const (
	tcpCongestionControlReno  = "reno"
	tcpCongestionControlCubic = "cubic"
)

func validateTCPCongestionControl(name string) error {
	switch name {
	case "", tcpCongestionControlReno, tcpCongestionControlCubic:
		return nil
	default:
		return E.New("unknown tcp_congestion_control: ", name, ", expected reno or cubic")
	}
}

// netstackIPStack returns the unexported ipstack *stack.Stack field of the
// struct impl points to (Tailscale's *netstack.Impl).
func netstackIPStack(impl any) (*stack.Stack, error) {
	value := reflect.ValueOf(impl)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return nil, E.New("netstack is not a non-nil struct pointer: ", reflect.TypeOf(impl))
	}
	field := value.Elem().FieldByName(tailscaleNetstackStackField)
	if !field.IsValid() {
		return nil, E.New("netstack has no field ", tailscaleNetstackStackField)
	}
	if field.Type() != reflect.TypeOf((*stack.Stack)(nil)) {
		return nil, E.New("netstack field ", tailscaleNetstackStackField, " has type ", field.Type(), ", expected *stack.Stack")
	}
	ipStack := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*stack.Stack)
	if ipStack == nil {
		return nil, E.New("netstack field ", tailscaleNetstackStackField, " is nil")
	}
	return ipStack, nil
}

// setStackTCPCongestionControl sets the default congestion control for TCP
// endpoints created afterwards and returns the value read back from the stack.
func setStackTCPCongestionControl(ipStack *stack.Stack, name string) (string, error) {
	option := tcpip.CongestionControlOption(name)
	if tcpipErr := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &option); tcpipErr != nil {
		return "", E.New("set ", name, ": ", tcpipErr)
	}
	var current tcpip.CongestionControlOption
	if tcpipErr := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &current); tcpipErr != nil {
		return "", E.New("read back: ", tcpipErr)
	}
	if string(current) != name {
		return string(current), E.New("stack reports ", string(current), " after setting ", name)
	}
	return string(current), nil
}

// applyNetstackTCPCongestionControl applies tcp_congestion_control to the
// started Tailscale server's netstack. Failures only warn.
func (t *Endpoint) applyNetstackTCPCongestionControl() {
	if t.tcpCongestionControl == "" {
		return
	}
	impl := t.server.ExportNetstack()
	if impl == nil {
		t.logger.Warn("tailscale: cannot set TCP congestion control: netstack is not available")
		return
	}
	ipStack, err := netstackIPStack(impl)
	if err != nil {
		t.logger.Warn("tailscale: cannot set TCP congestion control: ", err)
		return
	}
	current, err := setStackTCPCongestionControl(ipStack, t.tcpCongestionControl)
	if err != nil {
		t.logger.Warn("tailscale: cannot set TCP congestion control: ", err)
		return
	}
	t.logger.Info("tailscale: netstack TCP congestion control: ", current)
}
