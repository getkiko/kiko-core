package dns

import (
	"context"
	"os"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	_ adapter.DNSTransportManager = (*transportStagingView)(nil)
	_ adapter.GenerationProvider  = (*transportStagingView)(nil)
	_ adapter.GenerationProvider  = (*TransportManager)(nil)
)

func (m *TransportManager) Generation() uint64 {
	return m.generation.Load()
}

// TransportStaging prepares replacement DNS servers for a running manager.
// Staged servers resolve each other through View until Commit swaps them
// into the live tables.
type TransportStaging struct {
	manager    *TransportManager
	view       *transportStagingView
	defaultTag string
	order      []string
	staged     []adapter.DNSTransport
	stagedTag  map[string]adapter.DNSTransport
	removed    map[string]bool
	done       atomic.Bool
}

func (m *TransportManager) NewStaging(defaultTag string, order []string) *TransportStaging {
	staging := &TransportStaging{
		manager:    m,
		defaultTag: defaultTag,
		order:      order,
		stagedTag:  make(map[string]adapter.DNSTransport),
		removed:    make(map[string]bool),
	}
	staging.view = &transportStagingView{manager: m, staging: staging}
	return staging
}

func (s *TransportStaging) View() adapter.DNSTransportManager {
	return s.view
}

func (s *TransportStaging) Create(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	if transportType == C.DNSTypeFakeIP {
		return E.New("fakeip server cannot be replaced at runtime")
	}
	if _, loaded := s.stagedTag[tag]; loaded {
		return E.New("duplicate DNS server tag: ", tag)
	}
	transport, err := s.manager.registry.CreateDNSTransport(ctx, logger, tag, transportType, options)
	if err != nil {
		return err
	}
	s.staged = append(s.staged, transport)
	s.stagedTag[tag] = transport
	return nil
}

func (s *TransportStaging) Remove(tag string) {
	s.removed[tag] = true
}

func (s *TransportStaging) Staged() []adapter.DNSTransport {
	return s.staged
}

func (s *TransportStaging) lookup(tag string) (adapter.DNSTransport, bool) {
	if !s.done.Load() {
		if transport, loaded := s.stagedTag[tag]; loaded {
			return transport, true
		}
		if s.removed[tag] {
			return nil, false
		}
	}
	return s.manager.Transport(tag)
}

func (s *TransportStaging) resolveDefault() (adapter.DNSTransport, error) {
	if s.defaultTag != "" {
		transport, loaded := s.lookup(s.defaultTag)
		if !loaded {
			return nil, E.New("default DNS server not found: ", s.defaultTag)
		}
		if transport.Type() == C.DNSTypeFakeIP {
			return nil, E.New("default server cannot be fakeip")
		}
		return transport, nil
	}
	for _, tag := range s.order {
		transport, loaded := s.lookup(tag)
		if loaded {
			if transport.Type() == C.DNSTypeFakeIP {
				return nil, E.New("default server cannot be fakeip")
			}
			return transport, nil
		}
	}
	current := s.manager.Default()
	if current != nil && !s.removed[current.Tag()] {
		if replaced, loaded := s.stagedTag[current.Tag()]; loaded {
			return replaced, nil
		}
		return current, nil
	}
	return nil, E.New("missing default DNS server")
}

func (s *TransportStaging) Start() error {
	scope := s.manager.scope
	if scope == nil {
		return E.New("DNS transport manager is not started")
	}
	_, err := s.resolveDefault()
	if err != nil {
		return err
	}
	for _, transport := range s.staged {
		err = scope.Start(transportName(transport), transport, adapter.StartStateInitialize)
		if err != nil {
			return err
		}
	}
	started := make(map[string]bool)
	for len(started) < len(s.staged) {
		canContinue := false
	startOne:
		for _, transport := range s.staged {
			if started[transport.Tag()] {
				continue
			}
			for _, dependency := range transport.Dependencies() {
				if _, isStaged := s.stagedTag[dependency]; isStaged && !started[dependency] {
					continue startOne
				}
				if _, loaded := s.lookup(dependency); !loaded {
					return E.New("dependency[", dependency, "] not found for server[", transport.Tag(), "]")
				}
			}
			started[transport.Tag()] = true
			canContinue = true
			err = scope.Start(transportName(transport), transport, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if !canContinue {
			pending := common.Find(s.staged, func(it adapter.DNSTransport) bool {
				return !started[it.Tag()]
			})
			return E.New("circular server dependency: ", pending.Tag())
		}
	}
	for _, stage := range []adapter.StartStage{adapter.StartStatePostStart, adapter.StartStateStarted} {
		for _, transport := range s.staged {
			err = scope.Start(transportName(transport), transport, stage)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *TransportStaging) Discard() {
	if s.done.Swap(true) {
		return
	}
	for _, transport := range s.staged {
		s.manager.CloseRetired(transport)
	}
}

// Commit swaps staged servers into the live tables and returns the replaced
// or removed servers, which the caller must close with CloseRetired.
func (s *TransportStaging) Commit() []adapter.DNSTransport {
	m := s.manager
	defaultTransport, _ := s.resolveDefault()
	m.access.Lock()
	var retired []adapter.DNSTransport
	seen := make(map[string]bool)
	transports := make([]adapter.DNSTransport, 0, len(m.transports)+len(s.staged))
	for _, tag := range s.order {
		if seen[tag] {
			continue
		}
		if transport, loaded := s.stagedTag[tag]; loaded {
			seen[tag] = true
			transports = append(transports, transport)
		} else if transport, loaded := m.transportByTag[tag]; loaded && !s.removed[tag] {
			seen[tag] = true
			transports = append(transports, transport)
		}
	}
	for _, transport := range m.transports {
		tag := transport.Tag()
		if s.removed[tag] || s.stagedTag[tag] != nil {
			retired = append(retired, transport)
			continue
		}
		if !seen[tag] {
			seen[tag] = true
			transports = append(transports, transport)
		}
	}
	for _, transport := range s.staged {
		if !seen[transport.Tag()] {
			seen[transport.Tag()] = true
			transports = append(transports, transport)
		}
	}
	transportByTag := make(map[string]adapter.DNSTransport, len(transports))
	for _, transport := range transports {
		transportByTag[transport.Tag()] = transport
	}
	m.transports = transports
	m.transportByTag = transportByTag
	m.defaultTag = s.defaultTag
	if defaultTransport != nil {
		m.defaultTransport = defaultTransport
	}
	m.generation.Add(1)
	s.done.Store(true)
	m.access.Unlock()
	return retired
}

func (m *TransportManager) CloseRetired(transport adapter.DNSTransport) error {
	if m.scope != nil {
		child := m.scope.Detach(transport)
		if child != nil {
			return child.Close()
		}
	}
	return common.Close(transport)
}

func transportName(transport adapter.DNSTransport) string {
	return "dns/" + transport.Type() + "[" + transport.Tag() + "]"
}

var (
	_ adapter.ObjectPinner = (*TransportManager)(nil)
	_ adapter.ObjectPinner = (*transportStagingView)(nil)
)

// Acquire pins a DNS transport so that a replaced transport stays open while
// an exchange uses it.
func (m *TransportManager) Acquire(object any) func() {
	return m.pins.Acquire(object)
}

func (m *TransportManager) Pinned(objects ...any) int {
	return m.pins.Pinned(objects...)
}

func (v *transportStagingView) Acquire(object any) func() {
	return v.manager.Acquire(object)
}

func (v *transportStagingView) Pinned(objects ...any) int {
	return v.manager.Pinned(objects...)
}

type transportStagingView struct {
	manager *TransportManager
	staging *TransportStaging
}

func (v *transportStagingView) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (v *transportStagingView) Transports() []adapter.DNSTransport {
	if v.staging.done.Load() {
		return v.manager.Transports()
	}
	transports := common.Filter(v.manager.Transports(), func(it adapter.DNSTransport) bool {
		return !v.staging.removed[it.Tag()] && v.staging.stagedTag[it.Tag()] == nil
	})
	return append(transports, v.staging.staged...)
}

func (v *transportStagingView) Transport(tag string) (adapter.DNSTransport, bool) {
	return v.staging.lookup(tag)
}

func (v *transportStagingView) Default() adapter.DNSTransport {
	if !v.staging.done.Load() {
		transport, err := v.staging.resolveDefault()
		if err == nil {
			return transport
		}
	}
	return v.manager.Default()
}

func (v *transportStagingView) FakeIP() adapter.FakeIPTransport {
	return v.manager.FakeIP()
}

func (v *transportStagingView) Create(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) error {
	return v.manager.Create(ctx, logger, tag, transportType, options)
}

func (v *transportStagingView) Generation() uint64 {
	return v.manager.Generation()
}
