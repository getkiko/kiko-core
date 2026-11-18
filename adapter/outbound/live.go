package outbound

import (
	"context"
	"os"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	_ adapter.OutboundManager    = (*stagingView)(nil)
	_ adapter.GenerationProvider = (*stagingView)(nil)
	_ adapter.GenerationProvider = (*Manager)(nil)
)

var (
	_ adapter.ObjectPinner = (*Manager)(nil)
	_ adapter.ObjectPinner = (*stagingView)(nil)
)

// Acquire pins an outbound, or any object dialed through one, so that a
// replaced outbound stays open while it is in use.
func (m *Manager) Acquire(object any) func() {
	return m.pins.Acquire(object)
}

func (m *Manager) Pinned(objects ...any) int {
	return m.pins.Pinned(objects...)
}

func (v *stagingView) Acquire(object any) func() {
	return v.manager.Acquire(object)
}

func (v *stagingView) Pinned(objects ...any) int {
	return v.manager.Pinned(objects...)
}

func (m *Manager) Generation() uint64 {
	return m.generation.Load()
}

// Staging prepares replacement outbounds for a running manager. Staged
// outbounds are created and started against a view that resolves staged tags
// first, so the live tables stay untouched until Commit.
type Staging struct {
	manager    *Manager
	view       *stagingView
	defaultTag string
	order      []string
	staged     []adapter.Outbound
	stagedTag  map[string]adapter.Outbound
	removed    map[string]bool
	done       atomic.Bool
}

func (m *Manager) NewStaging(defaultTag string, order []string) *Staging {
	staging := &Staging{
		manager:    m,
		defaultTag: defaultTag,
		order:      order,
		stagedTag:  make(map[string]adapter.Outbound),
		removed:    make(map[string]bool),
	}
	staging.view = &stagingView{manager: m, staging: staging}
	return staging
}

// View returns the outbound manager that staged objects must be created with.
func (s *Staging) View() adapter.OutboundManager {
	return s.view
}

func (s *Staging) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	if _, loaded := s.stagedTag[tag]; loaded {
		return E.New("duplicate outbound tag: ", tag)
	}
	outbound, err := s.manager.registry.CreateOutbound(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	s.staged = append(s.staged, outbound)
	s.stagedTag[tag] = outbound
	return nil
}

func (s *Staging) Remove(tag string) {
	s.removed[tag] = true
}

func (s *Staging) Staged() []adapter.Outbound {
	return s.staged
}

func (s *Staging) lookup(tag string) (adapter.Outbound, bool) {
	if !s.done.Load() {
		if outbound, loaded := s.stagedTag[tag]; loaded {
			return outbound, true
		}
		if s.removed[tag] {
			return nil, false
		}
	}
	return s.manager.Outbound(tag)
}

func (s *Staging) resolveDefault() (adapter.Outbound, error) {
	if s.defaultTag != "" {
		outbound, loaded := s.lookup(s.defaultTag)
		if !loaded {
			return nil, E.New("default outbound not found: ", s.defaultTag)
		}
		return outbound, nil
	}
	for _, tag := range s.order {
		outbound, loaded := s.lookup(tag)
		if loaded {
			return outbound, nil
		}
	}
	current := s.manager.Default()
	if current != nil && !s.removed[current.Tag()] {
		if replaced, loaded := s.stagedTag[current.Tag()]; loaded {
			return replaced, nil
		}
		return current, nil
	}
	return nil, E.New("missing default outbound")
}

// Start runs all start stages for staged outbounds in dependency order.
func (s *Staging) Start() error {
	scope := s.manager.scope
	if scope == nil {
		return E.New("outbound manager is not started")
	}
	_, err := s.resolveDefault()
	if err != nil {
		return err
	}
	for _, outbound := range s.staged {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		err = scope.Start(outboundName(outbound), lifecycle, adapter.StartStateInitialize)
		if err != nil {
			return err
		}
	}
	err = s.startInOrder(scope)
	if err != nil {
		return err
	}
	for _, stage := range []adapter.StartStage{adapter.StartStatePostStart, adapter.StartStateStarted} {
		for _, outbound := range s.staged {
			lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			err = scope.Start(outboundName(outbound), lifecycle, stage)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Staging) startInOrder(scope *adapter.Scope) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outbound := range s.staged {
			if started[outbound.Tag()] {
				continue
			}
			for _, dependency := range outbound.Dependencies() {
				if _, isStaged := s.stagedTag[dependency]; isStaged && !started[dependency] {
					continue startOne
				}
				if _, loaded := s.lookup(dependency); !loaded {
					return E.New("dependency[", dependency, "] not found for outbound[", outbound.Tag(), "]")
				}
			}
			started[outbound.Tag()] = true
			canContinue = true
			lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			err := scope.Start(outboundName(outbound), lifecycle, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(s.staged) {
			return nil
		}
		if !canContinue {
			pending := common.Find(s.staged, func(it adapter.Outbound) bool {
				return !started[it.Tag()]
			})
			return E.New("circular outbound dependency: ", pending.Tag())
		}
	}
}

// Discard closes all staged outbounds. The live tables are left untouched.
func (s *Staging) Discard() {
	if s.done.Swap(true) {
		return
	}
	for _, outbound := range s.staged {
		s.manager.CloseRetired(outbound)
	}
}

// Commit swaps staged outbounds into the live tables and returns the
// replaced or removed outbounds, which the caller must close with CloseRetired.
func (s *Staging) Commit() []adapter.Outbound {
	m := s.manager
	defaultOutbound, _ := s.resolveDefault()
	m.access.Lock()
	var retired []adapter.Outbound
	seen := make(map[string]bool)
	outbounds := make([]adapter.Outbound, 0, len(m.outbounds)+len(s.staged))
	for _, tag := range s.order {
		if seen[tag] {
			continue
		}
		if outbound, loaded := s.stagedTag[tag]; loaded {
			seen[tag] = true
			outbounds = append(outbounds, outbound)
		} else if outbound, loaded := m.outboundByTag[tag]; loaded && !s.removed[tag] {
			seen[tag] = true
			outbounds = append(outbounds, outbound)
		}
	}
	for _, outbound := range m.outbounds {
		tag := outbound.Tag()
		if s.removed[tag] || s.stagedTag[tag] != nil {
			retired = append(retired, outbound)
			continue
		}
		if !seen[tag] {
			seen[tag] = true
			outbounds = append(outbounds, outbound)
		}
	}
	for _, outbound := range s.staged {
		if !seen[outbound.Tag()] {
			seen[outbound.Tag()] = true
			outbounds = append(outbounds, outbound)
		}
	}
	outboundByTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, outbound := range outbounds {
		outboundByTag[outbound.Tag()] = outbound
	}
	m.outbounds = outbounds
	m.outboundByTag = outboundByTag
	m.defaultTag = s.defaultTag
	if defaultOutbound != nil {
		m.defaultOutbound = defaultOutbound
	}
	m.generation.Add(1)
	s.done.Store(true)
	m.access.Unlock()
	return retired
}

// CloseRetired closes an outbound that is no longer part of the live tables.
func (m *Manager) CloseRetired(outbound adapter.Outbound) error {
	if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle && m.scope != nil {
		child := m.scope.Detach(lifecycle)
		if child != nil {
			return child.Close()
		}
	}
	return common.Close(outbound)
}

func outboundName(outbound adapter.Outbound) string {
	return "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
}

type stagingView struct {
	manager *Manager
	staging *Staging
}

func (v *stagingView) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (v *stagingView) Outbounds() []adapter.Outbound {
	return v.manager.Outbounds()
}

func (v *stagingView) Outbound(tag string) (adapter.Outbound, bool) {
	return v.staging.lookup(tag)
}

func (v *stagingView) Default() adapter.Outbound {
	if !v.staging.done.Load() {
		defaultOutbound, err := v.staging.resolveDefault()
		if err == nil {
			return defaultOutbound
		}
	}
	return v.manager.Default()
}

func (v *stagingView) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return v.manager.Create(ctx, router, logger, tag, outboundType, options)
}

func (v *stagingView) Generation() uint64 {
	return v.manager.Generation()
}
