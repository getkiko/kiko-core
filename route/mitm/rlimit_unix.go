//go:build unix

package mitm

import "syscall"

func setCoreLimitZero() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}
