package mitm

import (
	"context"
	"net"
	"runtime/debug"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/h1"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.MITMHostRejecter = (*Engine)(nil)

// rewriteSet is the rule set Serve hands to the HTTP engines; it is read per
// request, so a reload applies to connections in progress.
func (e *Engine) rewriteSet() *rewrite.Set {
	return e.config.Load().rewrite
}

// decidePlain reports whether a plaintext HTTP connection goes through the
// rewrite engine: some rule can match an http:// URL and the connection is in
// scope and not left to an outbound handler or an override.
func (e *Engine) decidePlain(config *compiledConfig, metadata *adapter.InboundContext) bool {
	if !config.rewrite.AppliesToPlain() || metadata.MITMOverride == C.MITMOverrideSkip {
		return false
	}
	if chain := metadata.OutboundChain; len(chain) > 0 {
		if _, isHandler := chain[len(chain)-1].(adapter.ConnectionHandler); isHandler {
			return false
		}
	}
	return config.scope.contains(metadata.Source.Addr, e.local)
}

// RejectHost reports the reject rule that covers every HTTPS request to the
// connection's domain, for a connection that is not decrypted.
func (e *Engine) RejectHost(metadata *adapter.InboundContext) (string, bool) {
	config := e.config.Load()
	if !config.enabled || metadata.Internal || metadata.Domain == "" {
		return "", false
	}
	if !config.scope.contains(metadata.Source.Addr, e.local) {
		return "", false
	}
	authority := normalizeHost(metadata.Domain)
	if port := metadata.Destination.Port; port != 0 && port != 443 {
		authority += ":" + strconv.Itoa(int(port))
	}
	return config.rewrite.HostReject(authority)
}

// servePlain relays a plaintext HTTP connection through the h1 engine so that
// rewrite rules apply. It returns with both connections closed.
func (e *Engine) servePlain(ctx context.Context, conn net.Conn, upstream net.Conn, redial adapter.MITMRedialFunc, metadata *adapter.InboundContext) (err error) {
	state := metadata.MITM
	host := metadata.Domain
	if host == "" {
		host = destinationAddr(metadata).String()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = E.New("panic: ", recovered)
			e.logger.ErrorContext(ctx, "rewrite ", host, ": ", err, "\n", string(debug.Stack()))
			common.Close(conn, upstream)
		}
	}()
	// Watching a side interrupts its reads; the read-ahead reader keeps that from cutting
	// into the protocol reader below, as on the TLS path.
	conn = withDeadlineReader(conn)
	upstream = withDeadlineReader(upstream)
	observer := e.capture.Observer()
	var connection *flow.ConnectionInfo
	if observer != nil {
		connection = connectionInfo(metadata, state, host)
		observer = &timedObserver{Observer: observer, connect: state.ConnectDuration()}
	}
	e.logger.DebugContext(ctx, "plain http ", host)
	options := h1.Options{
		OnRequest:  state.AddRequest,
		Logger:     e.logger,
		Observer:   observer,
		Connection: connection,
		Rewrite:    e.rewriteSet,
		Scheme:     "http",
		Internal:   e.internalDialer(metadata),
	}
	if redial != nil {
		options.Redial = func(ctx context.Context) (net.Conn, error) {
			fresh, err := redial(ctx)
			if err != nil {
				return nil, err
			}
			return withDeadlineReader(fresh), nil
		}
	}
	return h1.Serve(ctx, conn, upstream, options)
}
