package box

import "time"

// SetLiveRetireTiming shortens the retire grace period and poll interval for
// tests and returns a function that restores them.
func SetLiveRetireTiming(delay, poll time.Duration) func() {
	oldDelay, oldPoll := liveRetireDelay, liveRetirePoll
	liveRetireDelay, liveRetirePoll = delay, poll
	return func() {
		liveRetireDelay, liveRetirePoll = oldDelay, oldPoll
	}
}

// LiveRetiring returns the number of retirements still waiting to close.
func (s *Box) LiveRetiring() int64 {
	return s.liveRetiring.Load()
}
