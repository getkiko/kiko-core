//go:build linux

package burrow

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

func systemInterfaceIndex(name string) (int, bool, error) {
	request, err := interfaceIoctl(name, unix.SIOCGIFINDEX)
	if err != nil {
		return 0, true, err
	}
	index := int(request.Uint32())
	if index <= 0 {
		return 0, true, fmt.Errorf("invalid interface index %d", index)
	}
	return index, true, nil
}

func systemInterfaceIPv4(name string) (netip.Addr, bool, error) {
	request, err := interfaceIoctl(name, unix.SIOCGIFADDR)
	if err != nil {
		return netip.Addr{}, true, err
	}
	addressBytes, err := request.Inet4Addr()
	if err != nil {
		return netip.Addr{}, true, err
	}
	address, valid := netip.AddrFromSlice(addressBytes)
	if !valid {
		return netip.Addr{}, true, fmt.Errorf("invalid IPv4 address for interface %q", name)
	}
	return address.Unmap(), true, nil
}

func interfaceIoctl(name string, request uint) (*unix.Ifreq, error) {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(socket)
	interfaceRequest, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	err = unix.IoctlIfreq(socket, request, interfaceRequest)
	if err != nil {
		return nil, err
	}
	return interfaceRequest, nil
}
