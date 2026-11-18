package adapter

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/script"
	N "github.com/sagernet/sing/common/network"
)

// MITMEngine decides which TLS connections are decrypted and serves them.
// It is registered in the context with service.MustRegister and exists
// whenever a box runs, even with HTTPS decryption absent or disabled.
type MITMEngine interface {
	// Decide returns the decryption state of a routed TCP connection, or nil
	// when the connection is not decrypted. The connection is served by
	// Serve when the state is pending; any other state passes through.
	// A miss does not allocate.
	Decide(metadata *InboundContext) *MITMState
	// Explain reports the decryption outcome of a routed TCP connection
	// for policy tests: status "decrypted" or "skipped" with a reason, or
	// empty when the feature is off. It follows the same evaluation as
	// Decide and is not meant for the connection path.
	Explain(metadata *InboundContext) (status string, reason string)
	// MatchQUIC reports whether a QUIC connection to a decrypted host should
	// be blocked so that the client falls back to TCP.
	MatchQUIC(metadata *InboundContext) bool
	// MatchHost reports whether connections to the domain would be decrypted
	// by hostname (include, exclude, built-in exclusions and the skip
	// table), ignoring device scope and protocol. DNS uses it to remove
	// ech and h3 hints from answers for such hosts. A miss does not allocate.
	MatchHost(domain string) bool
	// Serve decrypts a connection whose state Decide returned pending.
	// conn is the client side with the sniffed ClientHello replayed and
	// upstream the dialed, unencrypted connection to the destination.
	// redial, when not nil, dials another such connection through the same
	// outbound, for an upstream that closed a reused connection; the
	// engine owns the connections it returns. Serve blocks until the
	// session ends, closes all connections and calls onClose exactly once.
	Serve(ctx context.Context, conn net.Conn, upstream net.Conn, redial MITMRedialFunc, metadata *InboundContext, onClose N.CloseHandlerFunc)
	// Reload validates and prepares options without changing the running
	// engine; the returned commit applies them atomically. A non-nil error
	// means nothing changed.
	Reload(options *option.MITMOptions) (commit func(), err error)
	// SetAuthority validates and loads a pushed intermediate CA (PEM chain
	// up to the root, PKCS#8 DER key) used by the managed certificate
	// source; an empty chain and key clear it. A non-nil error means
	// nothing changed and never contains key material.
	SetAuthority(chainPEM []byte, keyPKCS8 []byte, rootFingerprint string, notAfter time.Time) error
	Status() MITMEngineStatus
	// ClearSkip removes the pinning skip entries of a host, or all of them
	// when host is empty, together with the failure counts that led to
	// them. It reports whether anything was removed.
	ClearSkip(host string) bool
}

// MITMHostRejecter is implemented by a MITMEngine whose rewrite rules can
// refuse connections to a host. RejectHost reports the rule that refuses every
// HTTPS request to the connection's host; the router calls it only for
// connections the engine does not decrypt.
type MITMHostRejecter interface {
	RejectHost(metadata *InboundContext) (ruleID string, ok bool)
}

// MITMCaptureProvider is implemented by a MITMEngine that records decrypted
// exchanges. Capture returns the store, or nil when the engine records
// nothing (decryption off and no records kept).
type MITMCaptureProvider interface {
	Capture() *capture.Manager
}

// MITMScriptProvider is implemented by a MITMEngine that runs scripts: Scripts is the
// manager of the top-level "scripts" and ScriptHub keeps their recent console lines and
// notifications.
type MITMScriptProvider interface {
	Scripts() *script.Manager
	ScriptHub() *script.Hub
}

// MITMRedialFunc dials a fresh, unencrypted connection to the destination of
// a decrypted connection.
type MITMRedialFunc func(ctx context.Context) (net.Conn, error)

// MITMRedialToFunc dials a fresh, unencrypted connection to another host and
// port through the outbound of a decrypted connection, for an internal
// rewrite that sends a request to a different origin. tls tells that the new
// connection will carry TLS (so TLS fragment and spoof apply). The engine
// owns the connection it returns.
type MITMRedialToFunc func(ctx context.Context, host string, port uint16, tls bool) (net.Conn, error)

type MITMEngineStatus struct {
	Enabled              bool
	AuthorityFingerprint string
	AuthorityPending     bool
	LeafCacheSize        int
	RootFingerprint      string
	AuthorityNotAfter    time.Time
	CertificateSource    string
	// Skip lists the hosts that currently pass through undecrypted.
	Skip []MITMSkipEntry
	// Failures lists hosts whose decryption failed recently, newest first.
	Failures []MITMFailure
	// BuiltinExclusions is the number of built-in exclusion entries.
	BuiltinExclusions int
}

type MITMSkipEntry struct {
	Host string
	// Source is "auto" (pinning detected) or "manual".
	Source string
	Until  time.Time
	Reason string
}

type MITMFailure struct {
	Host      string
	Count     int
	LastError string
	At        time.Time
}

type MITMStatus uint32

const (
	MITMStatusNone MITMStatus = iota
	MITMStatusPending
	MITMStatusDecrypted
	MITMStatusFailed
	MITMStatusSkipped
	// MITMStatusPlain is a plaintext HTTP connection served by the engine
	// for rewriting.
	MITMStatusPlain
)

func (s MITMStatus) String() string {
	switch s {
	case MITMStatusPending:
		return "pending"
	case MITMStatusDecrypted:
		return "decrypted"
	case MITMStatusFailed:
		return "failed"
	case MITMStatusSkipped:
		return "skipped"
	case MITMStatusPlain:
		return "plain"
	default:
		return ""
	}
}

// MITMState is the decryption state of one connection. Accessors are safe
// for concurrent use and on a nil state.
type MITMState struct {
	status   atomic.Uint32
	requests atomic.Int64
	reason   atomic.Pointer[string]
	// unverified marks a decrypted connection whose upstream certificate was
	// not verified because the host is in upstream.skip_verify.
	unverified atomic.Bool
	// connection is the tracker identity of the connection, set when the
	// connection is registered: its id and the matched route rule.
	connection atomic.Pointer[MITMConnection]
	// connect is how long the router took to reach the destination.
	connect atomic.Int64
}

// MITMConnection links a state to the connection manager's record.
type MITMConnection struct {
	ID   string
	Rule string
}

func NewMITMState(status MITMStatus, reason string) *MITMState {
	state := &MITMState{}
	if reason != "" {
		stored := reason
		state.reason.Store(&stored)
	}
	state.status.Store(uint32(status))
	return state
}

func (s *MITMState) Status() MITMStatus {
	if s == nil {
		return MITMStatusNone
	}
	return MITMStatus(s.status.Load())
}

// Pending reports whether the connection is to be served by the engine.
func (s *MITMState) Pending() bool {
	return s != nil && MITMStatus(s.status.Load()) == MITMStatusPending
}

// Serves reports whether the engine serves the connection: a pending TLS
// connection or a plaintext HTTP one.
func (s *MITMState) Serves() bool {
	if s == nil {
		return false
	}
	status := MITMStatus(s.status.Load())
	return status == MITMStatusPending || status == MITMStatusPlain
}

func (s *MITMState) Requests() int64 {
	if s == nil {
		return 0
	}
	return s.requests.Load()
}

// Reason is why the connection failed or was skipped.
func (s *MITMState) Reason() string {
	if s == nil {
		return ""
	}
	reason := s.reason.Load()
	if reason == nil {
		return ""
	}
	return *reason
}

func (s *MITMState) AddRequest() {
	s.requests.Add(1)
}

func (s *MITMState) SetDecrypted() {
	s.status.Store(uint32(MITMStatusDecrypted))
}

func (s *MITMState) SetFailed(reason string) {
	s.reason.Store(&reason)
	s.status.Store(uint32(MITMStatusFailed))
}

func (s *MITMState) SetSkipped(reason string) {
	s.reason.Store(&reason)
	s.status.Store(uint32(MITMStatusSkipped))
}

// SetUnverified marks the upstream certificate as not verified.
func (s *MITMState) SetUnverified() {
	s.unverified.Store(true)
}

// Unverified reports whether the upstream certificate was not verified.
func (s *MITMState) Unverified() bool {
	return s != nil && s.unverified.Load()
}

// SetConnection records the id and the matched rule of the tracked connection.
func (s *MITMState) SetConnection(id string, rule string) {
	if s == nil {
		return
	}
	s.connection.Store(&MITMConnection{ID: id, Rule: rule})
}

// Connection returns what SetConnection recorded, or the zero value.
func (s *MITMState) Connection() MITMConnection {
	if s == nil {
		return MITMConnection{}
	}
	if connection := s.connection.Load(); connection != nil {
		return *connection
	}
	return MITMConnection{}
}

// SetConnectDuration records how long reaching the destination took,
// name resolution included.
func (s *MITMState) SetConnectDuration(d time.Duration) {
	if s == nil {
		return
	}
	s.connect.Store(int64(d))
}

// ConnectDuration returns what SetConnectDuration recorded, or zero.
func (s *MITMState) ConnectDuration() time.Duration {
	if s == nil {
		return 0
	}
	return time.Duration(s.connect.Load())
}
