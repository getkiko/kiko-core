package group

import (
	"context"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func RegisterLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.LoadBalanceOutboundOptions](registry, C.TypeLoadBalance, NewLoadBalance)
}

func NewLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.LoadBalanceOutboundOptions) (adapter.Outbound, error) {
	strategy := options.Strategy
	switch strategy {
	case "":
		strategy = C.LoadBalanceRoundRobin
	case C.LoadBalanceRoundRobin, C.LoadBalanceConsistentHashing, C.LoadBalanceStickySessions:
	default:
		return nil, E.New("unknown load balance strategy: ", strategy)
	}
	return newGroup(ctx, logger, C.TypeLoadBalance, tag, options.Outbounds, options.GroupHealthCheckOptions, options.InterruptExistConnections, &loadBalanceStrategy{kind: strategy, sticky: map[string]stickyEntry{}})
}

// loadBalanceStrategy spreads connections over the members that are not
// down.
type loadBalanceStrategy struct {
	kind   string
	next   atomic.Uint64
	access sync.Mutex
	sticky map[string]stickyEntry
}

type stickyEntry struct {
	tag     string
	expires time.Time
}

const (
	stickyTTL  = 10 * time.Minute
	stickySize = 4096
)

func (s *loadBalanceStrategy) mode() string     { return C.GroupModeLoadBalance }
func (s *loadBalanceStrategy) name() string     { return s.kind }
func (s *loadBalanceStrategy) hasCurrent() bool { return false }
func (s *loadBalanceStrategy) learns() bool     { return false }

func (s *loadBalanceStrategy) choose(g *Group, network string, current adapter.Outbound, now time.Time) adapter.Outbound {
	return nil
}

func (s *loadBalanceStrategy) probeSet(g *Group) []adapter.Outbound {
	return g.members
}

func (s *loadBalanceStrategy) inherit(old groupStrategy) {
	previous, ok := old.(*loadBalanceStrategy)
	if !ok || previous.kind != s.kind {
		return
	}
	s.next.Store(previous.next.Load())
	previous.access.Lock()
	sticky := make(map[string]stickyEntry, len(previous.sticky))
	for key, entry := range previous.sticky {
		sticky[key] = entry
	}
	previous.access.Unlock()
	s.access.Lock()
	s.sticky = sticky
	s.access.Unlock()
}

func (s *loadBalanceStrategy) pick(g *Group, network string, metadata *adapter.InboundContext, dryRun bool) adapter.Outbound {
	members := g.available(network)
	if len(members) == 0 {
		return g.firstSupporting(network)
	}
	if len(members) == 1 {
		return members[0]
	}
	key := destinationKey(metadata)
	switch s.kind {
	case C.LoadBalanceConsistentHashing:
		if key != "" {
			return rendezvous(key, members)
		}
	case C.LoadBalanceStickySessions:
		if metadata != nil && key != "" {
			return s.stickyPick(metadata.Source.Addr.String()+"|"+key, members, dryRun)
		}
	}
	var index uint64
	if dryRun {
		index = s.next.Load()
	} else {
		index = s.next.Add(1) - 1
	}
	return members[index%uint64(len(members))]
}

func (s *loadBalanceStrategy) stickyPick(key string, members []adapter.Outbound, dryRun bool) adapter.Outbound {
	now := time.Now()
	s.access.Lock()
	defer s.access.Unlock()
	if entry, ok := s.sticky[key]; ok && now.Before(entry.expires) {
		for _, member := range members {
			if member.Tag() == entry.tag {
				if !dryRun {
					s.sticky[key] = stickyEntry{tag: entry.tag, expires: now.Add(stickyTTL)}
				}
				return member
			}
		}
	}
	member := rendezvous(key, members)
	if dryRun {
		return member
	}
	if len(s.sticky) >= stickySize {
		for k, entry := range s.sticky {
			if !now.Before(entry.expires) {
				delete(s.sticky, k)
			}
		}
		for k := range s.sticky {
			if len(s.sticky) < stickySize {
				break
			}
			delete(s.sticky, k)
		}
	}
	s.sticky[key] = stickyEntry{tag: member.Tag(), expires: now.Add(stickyTTL)}
	return member
}

// rendezvous is the member with the highest hash of key and its tag, so
// that removing a member moves only the keys it had.
func rendezvous(key string, members []adapter.Outbound) adapter.Outbound {
	var best adapter.Outbound
	var bestHash uint64
	for _, member := range members {
		h := fnv.New64a()
		_, _ = h.Write([]byte(key))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(member.Tag()))
		if sum := h.Sum64(); best == nil || sum > bestHash {
			best, bestHash = member, sum
		}
	}
	return best
}
