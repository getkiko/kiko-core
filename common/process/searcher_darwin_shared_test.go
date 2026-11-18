//go:build darwin

package process

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestDarwinConnectionOwnerPreservesPID(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			source := netip.MustParseAddrPort("127.0.0.1:12345")
			destination := netip.MustParseAddrPort("127.0.0.1:443")
			pid := uint32(os.Getpid())
			finder := newDarwinConnectionFinder(time.Second)
			finder.builder = func(string) (darwinSnapshot, error) {
				return darwinSnapshot{createdAt: time.Now(), entries: []darwinConnectionEntry{{
					localAddr: source.Addr(), localPort: source.Port(),
					remoteAddr: destination.Addr(), remotePort: destination.Port(),
					pid: pid, uid: int32(os.Getuid()),
				}}}, nil
			}
			owner, err := finder.find(network, source, destination)
			if err != nil {
				t.Fatal(err)
			}
			if owner.ProcessID != pid {
				t.Fatalf("PID = %d, want %d", owner.ProcessID, pid)
			}
			if owner.ProcessPath == "" {
				t.Fatal("process executable path missing")
			}
		})
	}
}
