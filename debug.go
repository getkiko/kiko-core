package box

import (
	"net"
	"net/netip"
	"runtime/debug"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func checkDebugOptions(options option.DebugOptions) error {
	if options.OOMKiller != nil {
		return E.New("legacy oom_killer in debug options is removed, use oom-killer service instead")
	}
	return nil
}

// checkMITMDebugOptions keeps the debug listener on loopback while HTTPS
// decryption holds certificate authority keys in memory.
func checkMITMDebugOptions(mitmOptions *option.MITMOptions, options option.DebugOptions) error {
	if mitmOptions == nil || !mitmOptions.Enabled || options.Listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(options.Listen)
	if err == nil {
		if host == "localhost" {
			return nil
		}
		addr, err := netip.ParseAddr(host)
		if err == nil && addr.Unmap().IsLoopback() {
			return nil
		}
	}
	return E.New("HTTPS decryption requires experimental.debug.listen on a loopback address")
}

func applyDebugOptions(options option.DebugOptions) {
	if options.GCPercent != nil {
		debug.SetGCPercent(*options.GCPercent)
	}
	if options.MaxStack != nil {
		debug.SetMaxStack(*options.MaxStack)
	}
	if options.MaxThreads != nil {
		debug.SetMaxThreads(*options.MaxThreads)
	}
	if options.PanicOnFault != nil {
		debug.SetPanicOnFault(*options.PanicOnFault)
	}
	if options.TraceBack != "" {
		debug.SetTraceback(options.TraceBack)
	}
	if options.MemoryLimit.Value() != 0 {
		debug.SetMemoryLimit(int64(float64(options.MemoryLimit.Value()) / 1.5))
	}
}
