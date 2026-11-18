//go:build !unix

package mitm

func setCoreLimitZero() error {
	return nil
}
