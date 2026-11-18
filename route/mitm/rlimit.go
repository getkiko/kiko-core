package mitm

import (
	"sync"

	"github.com/sagernet/sing/common/logger"
)

var (
	coreDumpOnce sync.Once
	setCoreLimit = setCoreLimitZero
)

// disableCoreDumps sets RLIMIT_CORE to zero once per process, so that a
// crash of a process holding decryption keys leaves no core file. It runs
// when decryption is enabled and whenever an authority key is loaded.
func disableCoreDumps(logger logger.ContextLogger) {
	coreDumpOnce.Do(func() {
		err := setCoreLimit()
		if err != nil {
			logger.Warn("disable core dumps: ", err)
		}
	})
}
