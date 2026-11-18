//go:build !linux

package burrow

import "net/netip"

func systemInterfaceIndex(string) (int, bool, error) {
	return 0, false, nil
}

func systemInterfaceIPv4(string) (netip.Addr, bool, error) {
	return netip.Addr{}, false, nil
}
