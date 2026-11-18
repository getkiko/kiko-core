//go:build race

package mitm

// raceEnabled: sync.Pool drops items at random under the race detector, so allocation
// counts are not meaningful there.
const raceEnabled = true
