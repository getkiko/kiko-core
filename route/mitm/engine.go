// Package mitm assembles HTTPS decryption: it decides which routed TLS
// connections are decrypted and serves them with a certificate issued by
// the configured authority.
package mitm

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/authority"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/hostmatch"
	"github.com/sagernet/sing-box/common/mitm/rewrite"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"
)

// ReasonAuthorityPending is the skip reason of a connection that would be
// decrypted while no certificate authority is loaded.
const ReasonAuthorityPending = "authority_pending"

// ReasonBuiltin is the skip reason of a host the include list selects but a
// built-in exclusion entry vetoes.
const ReasonBuiltin = "builtin"

// Reasons reported by Explain for connections that pass through.
const (
	ReasonScope        = "scope"
	ReasonNotIncluded  = "not_included"
	ReasonExcluded     = "excluded"
	ReasonOverrideSkip = "override_skip"
	ReasonHandler      = "outbound_handler"
	ReasonNotTLS       = "not_tls"
	ReasonInternal     = "internal"
)

var (
	_ adapter.MITMEngine          = (*Engine)(nil)
	_ adapter.MITMCaptureProvider = (*Engine)(nil)
	_ adapter.LifecycleService    = (*Engine)(nil)
)

type Engine struct {
	ctx         context.Context
	logger      logger.ContextLogger
	timeFunc    func() time.Time
	closeCtx    context.Context
	closeCancel context.CancelFunc
	config      atomic.Pointer[compiledConfig]

	// access guards the file and managed authorities across reloads and
	// serializes publishing config.
	access           sync.Mutex
	fileKey          fileAuthorityKey
	fileAuthority    *authority.Authority
	managedAuthority *authority.Authority

	// skips and local outlive reloads.
	skips *skipTable
	local *localAddresses
	// capture records decrypted exchanges. It outlives reloads: Reload only
	// changes its options, so the instance and the kept records stay.
	capture *capture.Manager
	// controlPorts are the ports of the core's own control APIs on loopback; see
	// SetControlEndpoints.
	controlPorts atomic.Pointer[[]int]
}

// compiledConfig is the immutable configuration Decide and Serve read with
// a single atomic load.
type compiledConfig struct {
	enabled   bool
	source    string
	matcher   *hostmatch.Matcher
	authority *authority.Authority
	h2        bool
	// scope limits decryption to the configured client devices.
	scope deviceScope
	// blockQUIC drops QUIC to decrypted hosts so that clients use TCP.
	blockQUIC bool
	// pinningDuration is how long a pinned pair passes through.
	pinningDuration time.Duration
	// builtinCount is the number of effective built-in exclusion entries.
	builtinCount int
	upstream     upstreamConfig
	// rewrite is the compiled mitm.http_rewrite rule set; never nil.
	rewrite *rewrite.Set
}

type fileAuthorityKey struct {
	certificatePath string
	keyPath         string
}

// NewEngine creates the engine. It always succeeds for absent or disabled
// options, so that a later live apply can enable decryption.
func NewEngine(ctx context.Context, logger logger.ContextLogger, options *option.MITMOptions) (*Engine, error) {
	closeCtx, closeCancel := context.WithCancel(context.Background())
	engine := &Engine{
		ctx:         ctx,
		logger:      logger,
		timeFunc:    ntp.TimeFuncFromContext(ctx),
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
		skips:       newSkipTable(),
		local:       newLocalAddresses(),
		capture:     capture.New(capture.Options{}),
	}
	commit, err := engine.Reload(options)
	if err != nil {
		closeCancel()
		return nil, err
	}
	commit()
	return engine, nil
}

func (e *Engine) Name() string {
	return "mitm"
}

func (e *Engine) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(e.Close)
	config := e.config.Load()
	if config.enabled && config.authority == nil {
		e.logger.Warn("HTTPS decryption is waiting for a certificate authority")
	}
	return nil
}

// Close ends every decrypted session.
func (e *Engine) Close() error {
	e.closeCancel()
	return nil
}

func (e *Engine) Reload(options *option.MITMOptions) (func(), error) {
	mitmOptions := common.PtrValueOrDefault(options)
	certificateOptions := common.PtrValueOrDefault(mitmOptions.Certificate)
	hostnameOptions := common.PtrValueOrDefault(mitmOptions.Hostnames)
	source := certificateOptions.Source
	if source == "" {
		source = C.MITMCertificateSourceManaged
	}
	key := fileAuthorityKey{certificateOptions.CertificatePath, certificateOptions.KeyPath}
	switch source {
	case C.MITMCertificateSourceManaged:
		if key != (fileAuthorityKey{}) {
			return nil, E.New("certificate_path and key_path require certificate source `file`")
		}
	case C.MITMCertificateSourceFile:
		if key.certificatePath == "" || key.keyPath == "" {
			return nil, E.New("certificate source `file` requires certificate_path and key_path")
		}
	default:
		return nil, E.New("unknown certificate source: ", source)
	}
	builtin := hostnameOptions.BuiltinExclude == nil || *hostnameOptions.BuiltinExclude
	matcher, err := hostmatch.NewWithBuiltin(hostnameOptions.Include, hostnameOptions.Exclude, builtin, hostnameOptions.DisabledBuiltin)
	if err != nil {
		return nil, E.Cause(err, "parse hostnames")
	}
	scope, err := compileScope(mitmOptions.Sources)
	if err != nil {
		return nil, err
	}
	blockQUIC, err := compileQUIC(mitmOptions.QUIC)
	if err != nil {
		return nil, err
	}
	pinningDuration := time.Duration(mitmOptions.PinningSkipDuration)
	if pinningDuration < 0 {
		return nil, E.New("pinning_skip_duration must not be negative")
	}
	if pinningDuration == 0 {
		pinningDuration = DefaultPinningSkipDuration
	}
	upstream, err := e.compileUpstream(common.PtrValueOrDefault(mitmOptions.Upstream))
	if err != nil {
		return nil, err
	}
	captureSettings, err := mitmOptions.Capture.Resolve()
	if err != nil {
		return nil, err
	}
	rewriteSet, err := rewrite.Compile(e.ctx, mitmOptions.HTTPRewrite)
	if err != nil {
		return nil, err
	}
	rewriteSet.SetInternalGuard(e.denyInternal)
	config := &compiledConfig{
		rewrite:         rewriteSet,
		enabled:         mitmOptions.Enabled,
		source:          source,
		matcher:         matcher,
		h2:              h2Supported && (mitmOptions.H2 == nil || *mitmOptions.H2),
		scope:           scope,
		blockQUIC:       blockQUIC,
		pinningDuration: pinningDuration,
		upstream:        upstream,
	}
	if builtin {
		config.builtinCount = hostmatch.EnabledBuiltinCount(hostnameOptions.DisabledBuiltin)
	}
	e.access.Lock()
	defer e.access.Unlock()
	var loaded *authority.Authority
	if source == C.MITMCertificateSourceFile {
		if e.fileAuthority != nil && e.fileKey == key {
			config.authority = e.fileAuthority
		} else if config.enabled {
			// The file is read again only when its paths change.
			loaded, err = e.loadFileAuthority(key)
			if err != nil {
				return nil, err
			}
			config.authority = loaded
		}
	}
	return func() {
		e.access.Lock()
		defer e.access.Unlock()
		if loaded != nil {
			e.fileKey = key
			e.fileAuthority = loaded
		}
		next := *config
		// The managed authority is read at commit time so that a push
		// between validation and commit is kept.
		if next.source == C.MITMCertificateSourceManaged {
			next.authority = e.managedAuthority
		}
		e.config.Store(&next)
		e.capture.SetOptions(capture.Options{
			Enabled:    captureSettings.Enabled,
			Body:       captureSettings.Body,
			MaxBody:    captureSettings.MaxBody,
			MaxMemory:  captureSettings.MaxMemory,
			MaxRecords: captureSettings.MaxRecords,
		})
		if next.enabled {
			disableCoreDumps(e.logger)
		}
	}, nil
}

// SetAuthority loads a pushed intermediate CA for the managed source, or
// clears it when chainPEM and keyPKCS8 are empty. It is kept across
// reloads; with source `file` it is stored for a later switch back. A
// rotation starts with an empty leaf cache; sessions in progress keep
// the authority they started with.
func (e *Engine) SetAuthority(chainPEM []byte, keyPKCS8 []byte, rootFingerprint string, notAfter time.Time) error {
	var loaded *authority.Authority
	if len(chainPEM) != 0 || len(keyPKCS8) != 0 {
		var err error
		now := time.Now()
		if e.timeFunc != nil {
			now = e.timeFunc()
		}
		loaded, err = authority.LoadIntermediate(chainPEM, keyPKCS8, rootFingerprint, notAfter, now)
		if err != nil {
			return err
		}
	}
	e.access.Lock()
	defer e.access.Unlock()
	e.managedAuthority = loaded
	if current := e.config.Load(); current.source == C.MITMCertificateSourceManaged {
		next := *current
		next.authority = loaded
		e.config.Store(&next)
	}
	if loaded == nil {
		e.logger.Info("certificate authority cleared")
	} else {
		disableCoreDumps(e.logger)
		e.logger.Info("certificate authority loaded: ", loaded.Fingerprint(), ", expires ", loaded.NotAfter().Format(time.RFC3339))
	}
	return nil
}

func (e *Engine) loadFileAuthority(key fileAuthorityKey) (*authority.Authority, error) {
	certificateContent, err := filemanager.ReadFile(e.ctx, key.certificatePath)
	if err != nil {
		return nil, E.Cause(err, "read certificate authority")
	}
	keyContent, err := filemanager.ReadFile(e.ctx, key.keyPath)
	if err != nil {
		return nil, E.Cause(err, "read certificate authority key")
	}
	loaded, err := authority.Load(certificateContent, keyContent)
	if err != nil {
		return nil, E.Cause(err, "load certificate authority")
	}
	return loaded, nil
}

// Capture returns the capture store. While decryption is off it returns the
// store only as long as it keeps records, so that they stay readable.
func (e *Engine) Capture() *capture.Manager {
	if !e.config.Load().enabled && e.capture.Stats().Records == 0 {
		return nil
	}
	return e.capture
}

func (e *Engine) Status() adapter.MITMEngineStatus {
	config := e.config.Load()
	status := adapter.MITMEngineStatus{
		Enabled:           config.enabled,
		AuthorityPending:  config.authority == nil,
		CertificateSource: config.source,
	}
	if config.authority != nil {
		status.AuthorityFingerprint = config.authority.Fingerprint()
		status.RootFingerprint = config.authority.RootFingerprint()
		status.AuthorityNotAfter = config.authority.NotAfter()
		status.LeafCacheSize = config.authority.CacheLen()
	}
	status.BuiltinExclusions = config.builtinCount
	status.Skip, status.Failures = e.skips.snapshot(e.now())
	return status
}

// decision is the outcome of the host policy for one connection.
type decision uint8

const (
	decisionNone decision = iota
	decisionDecrypt
	// decisionAuthorityPending: the host is decrypted but no authority is loaded.
	decisionAuthorityPending
	// decisionPinned: the host is decrypted but its pair is in the skip table.
	decisionPinned
	// decisionBuiltin: the include list matched but a built-in exclusion vetoed.
	decisionBuiltin
	// The decisions below pass the connection through; Decide returns nil
	// for them and Explain reports the reason.
	decisionHandler
	decisionScope
	decisionOverrideSkip
	decisionExcluded
	decisionNotIncluded
)

// now is the engine clock.
func (e *Engine) now() time.Time {
	if e.timeFunc != nil {
		return e.timeFunc()
	}
	return time.Now()
}

// evaluate applies the interception policy to a connection of a protocol the
// caller has checked, in order: outbound that handles connections itself,
// device scope, the route-options override (skip ends the decision; force
// bypasses the host lists, the built-in table and the skip table), exclude
// and include hostnames and the built-in exclusions (hostmatch.Matcher.Verdict),
// a loaded authority and the skip table. It does not allocate on a miss.
func (e *Engine) evaluate(config *compiledConfig, metadata *adapter.InboundContext) decision {
	if chain := metadata.OutboundChain; len(chain) > 0 {
		if _, isHandler := chain[len(chain)-1].(adapter.ConnectionHandler); isHandler {
			return decisionHandler
		}
	}
	if !config.scope.contains(metadata.Source.Addr, e.local) {
		return decisionScope
	}
	forced := false
	switch metadata.MITMOverride {
	case C.MITMOverrideSkip:
		return decisionOverrideSkip
	case C.MITMOverrideForce:
		if metadata.Domain == "" {
			return decisionNotIncluded
		}
		forced = true
	default:
		switch config.matcher.Verdict(metadata.Domain, destinationAddr(metadata), metadata.Destination.Port) {
		case hostmatch.VerdictDecrypt:
		case hostmatch.VerdictBuiltin:
			return decisionBuiltin
		case hostmatch.VerdictExcluded:
			return decisionExcluded
		default:
			return decisionNotIncluded
		}
	}
	if config.authority == nil {
		return decisionAuthorityPending
	}
	if !forced && e.skips.active.Load() != 0 && e.skips.lookup(tableHost(metadata), pinKeyOf(metadata), e.now()) {
		return decisionPinned
	}
	return decisionDecrypt
}

// Decide checks, in order: the feature switch, TLS, then evaluate. Connections
// the engine does not decrypt get nil without an allocation; one that would be
// decrypted but cannot be (no authority, skip table) or that a built-in
// exclusion vetoed gets a skipped state with the reason.
func (e *Engine) Decide(metadata *adapter.InboundContext) *adapter.MITMState {
	config := e.config.Load()
	if !config.enabled || metadata.Internal {
		return nil
	}
	if metadata.Protocol != C.ProtocolTLS {
		if metadata.Protocol == C.ProtocolHTTP && e.decidePlain(config, metadata) {
			return adapter.NewMITMState(adapter.MITMStatusPlain, "")
		}
		return nil
	}
	switch e.evaluate(config, metadata) {
	case decisionDecrypt:
		return adapter.NewMITMState(adapter.MITMStatusPending, "")
	case decisionAuthorityPending:
		return adapter.NewMITMState(adapter.MITMStatusSkipped, ReasonAuthorityPending)
	case decisionPinned:
		e.logger.Debug("mitm: skip ", tableHost(metadata), " (pinned)")
		return adapter.NewMITMState(adapter.MITMStatusSkipped, ReasonPinned)
	case decisionBuiltin:
		return adapter.NewMITMState(adapter.MITMStatusSkipped, ReasonBuiltin)
	}
	return nil
}

// Explain reports why a routed connection is or is not decrypted, for
// policy tests; it is not used on the connection path. status is
// "decrypted" when evaluation would decrypt the connection, "skipped" with a
// reason (ReasonScope, ReasonNotIncluded, ReasonExcluded, ReasonBuiltin,
// ReasonPinned, ReasonAuthorityPending, ReasonOverrideSkip, ReasonHandler or
// ReasonNotTLS) when it passes through, and empty when the feature is off.
func (e *Engine) Explain(metadata *adapter.InboundContext) (status string, reason string) {
	config := e.config.Load()
	if !config.enabled {
		return "", ""
	}
	if metadata.Internal {
		return "skipped", ReasonInternal
	}
	if metadata.Protocol != C.ProtocolTLS {
		if metadata.Protocol == C.ProtocolHTTP && e.decidePlain(config, metadata) {
			return "plain", ""
		}
		return "skipped", ReasonNotTLS
	}
	switch e.evaluate(config, metadata) {
	case decisionDecrypt:
		return "decrypted", ""
	case decisionAuthorityPending:
		return "skipped", ReasonAuthorityPending
	case decisionPinned:
		return "skipped", ReasonPinned
	case decisionBuiltin:
		return "skipped", ReasonBuiltin
	case decisionHandler:
		return "skipped", ReasonHandler
	case decisionScope:
		return "skipped", ReasonScope
	case decisionOverrideSkip:
		return "skipped", ReasonOverrideSkip
	case decisionExcluded:
		return "skipped", ReasonExcluded
	}
	return "skipped", ReasonNotIncluded
}

// tableHost is the skip table key of a connection: the lowercase server name,
// or the destination address without one.
func tableHost(metadata *adapter.InboundContext) string {
	if metadata.Domain != "" {
		return normalizeHost(metadata.Domain)
	}
	return destinationAddr(metadata).String()
}

// normalizeHost lowercases a name and drops a trailing dot; a name that is
// already in that form is returned as is.
func normalizeHost(name string) string {
	name = strings.TrimSuffix(name, ".")
	for i := 0; i < len(name); i++ {
		if c := name[i]; 'A' <= c && c <= 'Z' {
			return strings.ToLower(name)
		}
	}
	return name
}

func destinationAddr(metadata *adapter.InboundContext) netip.Addr {
	if metadata.Destination.IsIP() {
		return metadata.Destination.Addr
	}
	if len(metadata.DestinationAddresses) > 0 {
		return metadata.DestinationAddresses[0]
	}
	return netip.Addr{}
}

// MatchQUIC reports whether a QUIC connection should be dropped so that the
// client retries over TCP: decryption is enabled with an authority loaded,
// quic is `block`, and the host policy of the connection (device scope,
// overrides, hostnames, built-in exclusions, skip table) decrypts it. It does
// not allocate on a miss.
func (e *Engine) MatchQUIC(metadata *adapter.InboundContext) bool {
	config := e.config.Load()
	if !config.enabled || !config.blockQUIC || metadata.Protocol != C.ProtocolQUIC {
		return false
	}
	return e.evaluate(config, metadata) == decisionDecrypt
}

// MatchHost reports whether connections to the domain would be decrypted by
// hostname: decryption is enabled and the include, exclude and built-in lists
// select the host on any port, and no client of it is in the skip table. It
// ignores device scope, protocol and whether an authority is loaded. It does
// not allocate on a miss.
func (e *Engine) MatchHost(domain string) bool {
	config := e.config.Load()
	if !config.enabled || domain == "" {
		return false
	}
	if !config.matcher.Match(domain, netip.Addr{}, 0) {
		return false
	}
	return e.skips.active.Load() == 0 || !e.skips.hostSkipped(normalizeHost(domain), e.now())
}

// ClearSkip removes the skip entries and failure records of a host, or of
// every host when host is empty.
func (e *Engine) ClearSkip(host string) bool {
	if host != "" {
		host = normalizeHost(host)
	}
	return e.skips.clear(host)
}
