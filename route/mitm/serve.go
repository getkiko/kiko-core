package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/common/mitm/h1"
	"github.com/sagernet/sing-box/common/mitm/h2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// HandshakeTimeout bounds both TLS handshakes of a decrypted connection.
var HandshakeTimeout = 15 * time.Second

func (e *Engine) Serve(ctx context.Context, conn net.Conn, upstream net.Conn, redial adapter.MITMRedialFunc, metadata *adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stopClose := context.AfterFunc(e.closeCtx, cancel)
	defer func() {
		stopClose()
		cancel()
	}()
	err := e.serve(ctx, conn, upstream, redial, metadata)
	var clientErr *clientSideError
	if errors.As(err, &clientErr) {
		// Like a client EOF on the copy path, a client-side failure is no failure of the
		// outbound: group feedback sees a clean close. The reason stays in the state.
		err = nil
	}
	if onClose != nil {
		onClose(err)
	}
}

// clientSideError marks a session that ended because of the client.
type clientSideError struct {
	err error
}

func (e *clientSideError) Error() string {
	return e.err.Error()
}

func (e *clientSideError) Unwrap() error {
	return e.err
}

// serve returns with both connections closed.
func (e *Engine) serve(ctx context.Context, conn net.Conn, upstream net.Conn, redial adapter.MITMRedialFunc, metadata *adapter.InboundContext) (err error) {
	state := metadata.MITM
	if state.Status() == adapter.MITMStatusPlain {
		return e.servePlain(ctx, conn, upstream, redial, metadata)
	}
	serverName := metadata.Domain
	port := metadata.Destination.Port
	if serverName == "" {
		serverName = destinationAddr(metadata).String()
	}
	closeAll := true
	defer func() {
		if recovered := recover(); recovered != nil {
			err = E.New("panic: ", recovered)
			e.logger.ErrorContext(ctx, "decrypt ", serverName, ": ", err, "\n", string(debug.Stack()))
			if state.Status() != adapter.MITMStatusDecrypted {
				state.SetFailed(err.Error())
			}
			closeAll = true
		}
		if closeAll {
			common.Close(conn, upstream)
		}
	}()
	config := e.config.Load()
	signer := config.authority
	if signer == nil {
		// A reload removed the authority after Decide: no handshake has started, so the
		// connection passes through.
		state.SetSkipped(ReasonAuthorityPending)
		e.logger.InfoContext(ctx, "pass through ", serverName, ": ", ReasonAuthorityPending)
		return bufio.CopyConn(ctx, conn, upstream)
	}
	// Watching a side interrupts its reads; the pipe-based reader keeps that from cutting into
	// the reader below.
	order := &endOrder{}
	clientEnd := &endWatchConn{Conn: conn, order: order}
	upstreamEnd := &endWatchConn{Conn: upstream, order: order}
	conn = withDeadlineReader(clientEnd)
	upstream = withDeadlineReader(upstreamEnd)
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer handshakeCancel()
	var (
		upstreamConn net.Conn
		upstreamErr  error
		upstreamALPN string
		clientClosed bool
		// certificateSent is set when the handshake picked the generated
		// certificate, the last step before the server flight is written.
		certificateSent atomic.Bool
		// upstreamTLS is how long the upstream handshake took.
		upstreamTLS time.Duration
	)
	client := &handshakeConn{Conn: conn}
	clientConn := tls.Server(client, &tls.Config{
		MinVersion: tls.VersionTLS12,
		Time:       e.timeFunc,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Upstream first: the certificate copies its names, and a failure
			// there fails the client handshake.
			// The client is not read meanwhile: watch it, so that its close or an
			// interrupt cancels the upstream handshake.
			upstreamCtx, upstreamCancel := context.WithCancel(hello.Context())
			stopWatch := client.watch(upstreamCancel)
			offer := offerProtocols(hello.SupportedProtos, config.h2)
			if len(offer) == 0 {
				upstreamErr = E.New("no application protocol in common with the client: ", strings.Join(hello.SupportedProtos, ","))
				return nil, upstreamErr
			}
			var upstreamLeaf *x509.Certificate
			handshakeStart := time.Now()
			upstreamConn, upstreamLeaf, upstreamALPN, upstreamErr = e.handshakeUpstream(upstreamCtx, config, upstream, serverName, port, offer)
			upstreamTLS = time.Since(handshakeStart)
			clientErr := stopWatch()
			upstreamCancel()
			if clientErr != nil {
				clientClosed = true
				upstreamErr = E.Cause(clientErr, "client closed during upstream TLS handshake")
				return nil, upstreamErr
			}
			if upstreamErr != nil {
				upstreamErr = E.Cause(upstreamErr, "upstream TLS handshake")
				return nil, upstreamErr
			}
			if config.upstream.verifySkipped(serverName, port) {
				// Set once the handshake succeeded: a failed one verified nothing
				// either way and is not an unverified connection.
				state.SetUnverified()
			}
			clientALPN, alpnErr := clientProtocol(hello.SupportedProtos, upstreamALPN)
			if alpnErr != nil {
				upstreamErr = alpnErr
				return nil, upstreamErr
			}
			certificate, issueErr := signer.Leaf(serverName, upstreamLeaf)
			if issueErr != nil {
				upstreamErr = E.Cause(issueErr, "issue certificate")
				return nil, upstreamErr
			}
			serverConfig := &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					certificateSent.Store(true)
					return certificate, nil
				},
				MinVersion: tls.VersionTLS12,
				Time:       e.timeFunc,
			}
			if clientALPN != "" {
				serverConfig.NextProtos = []string{clientALPN}
			}
			return serverConfig, nil
		},
	})
	tracker := &pinningTracker{
		engine:   e,
		host:     normalizeHost(serverName),
		key:      pinKeyOf(metadata),
		duration: config.pinningDuration,
		shared:   e.sharedClient(metadata),
	}
	err = clientConn.HandshakeContext(handshakeCtx)
	if err != nil {
		if upstreamErr != nil {
			err = upstreamErr
			if !clientClosed {
				e.skips.observe(tracker.host, err.Error(), e.now())
			}
		} else {
			clientClosed = true
			tracker.handshakeFailed(err, certificateSent.Load() && clientConn.ConnectionState().Version == tls.VersionTLS13)
			err = E.Cause(err, "client TLS handshake")
		}
		state.SetFailed(err.Error())
		e.logger.InfoContext(ctx, "decrypt ", serverName, ": ", err)
		if clientClosed {
			return &clientSideError{err}
		}
		return err
	}
	tracker.startedAt = e.now()
	state.SetDecrypted()
	closeAll = false
	// The observer is chosen once per connection; nil costs nothing per request.
	observer := e.capture.Observer()
	var connection *flow.ConnectionInfo
	if observer != nil {
		connection = connectionInfo(metadata, state, serverName)
		observer = &timedObserver{Observer: observer, connect: state.ConnectDuration(), tls: upstreamTLS}
	}
	var requested atomic.Bool
	onRequest := func() {
		state.AddRequest()
		if requested.CompareAndSwap(false, true) {
			tracker.requested()
		}
	}
	if clientConn.ConnectionState().NegotiatedProtocol == protocolH2 {
		e.logger.DebugContext(ctx, "decrypted ", serverName, " h2")
		options := h2.Options{
			ServerName: serverName,
			OnRequest:  onRequest,
			Logger:     e.logger,
			Observer:   observer,
			Connection: connection,
			Rewrite:    e.rewriteSet,
			Internal:   e.internalDialer(metadata),
		}
		if redial != nil {
			options.Redial = func(ctx context.Context) (net.Conn, error) {
				return e.redialUpstream(ctx, redial, serverName, port, []string{protocolH2})
			}
		}
		err = h2.Serve(ctx, clientConn, upstreamConn, options)
		tracker.finished(state.Requests(), e.closeCtx.Err() != nil || ctx.Err() != nil, clientEndedFirst(clientEnd, upstreamEnd), err)
		return err
	}
	e.logger.DebugContext(ctx, "decrypted ", serverName, " h1")
	options := h1.Options{
		OnRequest:  onRequest,
		Logger:     e.logger,
		Observer:   observer,
		Connection: connection,
		Rewrite:    e.rewriteSet,
		Internal:   e.internalDialer(metadata),
	}
	if redial != nil {
		options.Redial = func(ctx context.Context) (net.Conn, error) {
			return e.redialUpstream(ctx, redial, serverName, port, []string{protocolHTTP1})
		}
	}
	err = h1.Serve(ctx, clientConn, upstreamConn, options)
	tracker.finished(state.Requests(), e.closeCtx.Err() != nil || ctx.Err() != nil, clientEndedFirst(clientEnd, upstreamEnd), err)
	return err
}

// redialUpstream returns a fresh upstream: dialed by redial and handshaken like the first
// one (server name, fingerprint, roots), offering only the protocol the session already
// speaks; an upstream that answers otherwise is an error, as the client side cannot switch.
func (e *Engine) redialUpstream(ctx context.Context, redial adapter.MITMRedialFunc, serverName string, port uint16, protocols []string) (net.Conn, error) {
	raw, err := redial(ctx)
	if err != nil {
		e.logger.DebugContext(ctx, "redial ", serverName, ": ", err)
		return nil, err
	}
	raw = withDeadlineReader(raw)
	handshakeCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	upstreamConn, _, _, err := e.handshakeUpstream(handshakeCtx, e.config.Load(), raw, serverName, port, protocols)
	if err != nil {
		raw.Close()
		err = E.Cause(err, "upstream TLS handshake")
		e.logger.DebugContext(ctx, "redial ", serverName, ": ", err)
		return nil, err
	}
	return upstreamConn, nil
}

// connectionInfo describes a decrypted connection for the capture store. It
// is read after the handshakes, so state.Unverified is final.
func connectionInfo(metadata *adapter.InboundContext, state *adapter.MITMState, serverName string) *flow.ConnectionInfo {
	linked := state.Connection()
	info := &flow.ConnectionInfo{
		ID:          linked.ID,
		Source:      metadata.Source.String(),
		Destination: metadata.Destination.String(),
		Host:        serverName,
		Inbound:     metadata.Inbound,
		InboundType: metadata.InboundType,
		Rule:        linked.Rule,
		User:        metadata.User,
		Unverified:  state.Unverified(),
	}
	if chain := metadata.OutboundChain; len(chain) > 0 {
		last := chain[len(chain)-1]
		info.Outbound, info.OutboundType = last.Tag(), last.Type()
	}
	if owner := metadata.ProcessInfo; owner != nil {
		info.ProcessPath = owner.ProcessPath
		info.ProcessName = processName(owner.ProcessPath)
		info.ProcessID = owner.ProcessID
	}
	return info
}

// processName returns the last element of a Unix or Windows path.
func processName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}
