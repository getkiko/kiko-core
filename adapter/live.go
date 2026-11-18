package adapter

import (
	"context"
	"sync"
)

// LiveApplyProtocol is the revision of the live configuration apply protocol
// exposed through the daemon API.
const LiveApplyProtocol = 1

type LiveConfigResult struct {
	Applied         bool
	RestartRequired bool
	Reason          string
}

// LiveConfigApplier applies route rules, outbounds, DNS servers and DNS rules
// to a running instance without recreating it.
type LiveConfigApplier interface {
	ApplyLiveConfig(ctx context.Context, content []byte, revision int64) (LiveConfigResult, error)
}

// GenerationProvider reports a counter that changes whenever objects managed
// by the provider are replaced, so cached lookups can be refreshed.
type GenerationProvider interface {
	Generation() uint64
}

// ObjectPinner counts the users of live objects such as outbounds and DNS
// transports, so that objects replaced by a live apply close only after every
// user released them.
type ObjectPinner interface {
	// Acquire pins object until the returned release function is called.
	// Release is idempotent.
	Acquire(object any) (release func())
	// Pinned returns the total pin count of objects.
	Pinned(objects ...any) int
}

// Acquire pins object on manager when manager supports pinning.
func Acquire(manager any, object any) (release func()) {
	if pinner, isPinner := manager.(ObjectPinner); isPinner && object != nil {
		return pinner.Acquire(object)
	}
	return func() {}
}

// PinCounter implements ObjectPinner. The zero value is ready to use.
type PinCounter struct {
	access sync.Mutex
	users  map[any]int
}

func (c *PinCounter) Acquire(object any) func() {
	if object == nil {
		return func() {}
	}
	c.access.Lock()
	if c.users == nil {
		c.users = make(map[any]int)
	}
	c.users[object]++
	c.access.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.access.Lock()
			count := c.users[object] - 1
			if count <= 0 {
				delete(c.users, object)
			} else {
				c.users[object] = count
			}
			c.access.Unlock()
		})
	}
}

func (c *PinCounter) Pinned(objects ...any) int {
	c.access.Lock()
	defer c.access.Unlock()
	var count int
	for _, object := range objects {
		count += c.users[object]
	}
	return count
}

// AcquireOutbound pins outbound on manager, together with the members that
// outbound groups currently select for network, so that a connection keeps
// the whole chain it dials through open.
func AcquireOutbound(manager any, outbound any, network string) (release func()) {
	pinner, isPinner := manager.(ObjectPinner)
	if !isPinner || outbound == nil {
		return func() {}
	}
	releases := []func(){pinner.Acquire(outbound)}
	current := outbound
	for range 8 {
		group, isGroup := current.(OutboundGroup)
		if !isGroup {
			break
		}
		selected := group.Selected(network)
		if selected == nil {
			break
		}
		releases = append(releases, pinner.Acquire(selected))
		current = selected
	}
	if len(releases) == 1 {
		return releases[0]
	}
	return func() {
		for _, release := range releases {
			release()
		}
	}
}
