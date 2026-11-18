// Package lifecycle exposes completion of the CLI-owned instance lifecycle to
// attached APIs. Listening on the API socket alone does not imply readiness.
package lifecycle

import (
	"sync"
	"sync/atomic"
	"time"
)

const ReloadProtocol = 1

var sequence atomic.Int64

type Instance struct {
	ID          int64
	Revision    string
	ReloadError string
	Ready       atomic.Bool
	access      sync.RWMutex
	live        string
}

// CurrentRevision returns the revision of the configuration currently applied,
// including revisions applied without recreating the instance.
func (i *Instance) CurrentRevision() string {
	i.access.RLock()
	defer i.access.RUnlock()
	if i.live != "" {
		return i.live
	}
	return i.Revision
}

func (i *Instance) SetRevision(revision string) {
	i.access.Lock()
	i.live = revision
	i.access.Unlock()
}

func New(revision, reloadError string) *Instance {
	return &Instance{ID: sequence.Add(1), Revision: revision, ReloadError: reloadError}
}

// Seed IDs per process while preserving monotonicity within the process.
func init() { sequence.Store(time.Now().UnixNano()) }
