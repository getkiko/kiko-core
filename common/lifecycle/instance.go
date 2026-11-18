// Package lifecycle exposes completion of the CLI-owned instance lifecycle to
// attached APIs. Listening on the API socket alone does not imply readiness.
package lifecycle

import (
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
}

func New(revision, reloadError string) *Instance {
	return &Instance{ID: sequence.Add(1), Revision: revision, ReloadError: reloadError}
}

// Seed IDs per process while preserving monotonicity within the process.
func init() { sequence.Store(time.Now().UnixNano()) }
