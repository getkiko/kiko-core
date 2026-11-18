package burrow

import (
	"context"
	"net/netip"
	"testing"

	"github.com/getkiko/burrow"
)

func TestNewSignalResolverWithHosts(t *testing.T) {
	fallbackCalled := false
	fallback := func(context.Context, string) ([]netip.Addr, error) {
		fallbackCalled = true
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}

	t.Run("hosts match returns the mapped IP", func(t *testing.T) {
		fallbackCalled = false
		resolve, err := newSignalResolverWithHosts(map[string]string{
			"www.baidu.com": "203.0.113.26",
		}, fallback)
		if err != nil {
			t.Fatal(err)
		}
		addresses, err := resolve(t.Context(), "www.baidu.com")
		if err != nil {
			t.Fatal(err)
		}
		if len(addresses) != 1 || addresses[0].String() != "203.0.113.26" {
			t.Fatalf("expected 203.0.113.26, got %v", addresses)
		}
		if fallbackCalled {
			t.Fatal("a hosts match must not call the DNS fallback")
		}
	})

	t.Run("miss falls back to DNS", func(t *testing.T) {
		fallbackCalled = false
		resolve, err := newSignalResolverWithHosts(map[string]string{
			"www.baidu.com": "203.0.113.26",
		}, fallback)
		if err != nil {
			t.Fatal(err)
		}
		addresses, err := resolve(t.Context(), "other.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !fallbackCalled {
			t.Fatal("a hosts miss must fall back to DNS")
		}
		if len(addresses) != 1 || addresses[0].String() != "8.8.8.8" {
			t.Fatalf("expected the fallback result, got %v", addresses)
		}
	})

	t.Run("empty hosts returns the fallback unchanged", func(t *testing.T) {
		resolve, err := newSignalResolverWithHosts(nil, fallback)
		if err != nil {
			t.Fatal(err)
		}
		if resolve == nil {
			t.Fatal("expected the fallback itself")
		}
		var typed burrow.ResolveIPFunc = fallback
		_ = typed
	})

	t.Run("invalid IP fails", func(t *testing.T) {
		_, err := newSignalResolverWithHosts(map[string]string{
			"www.baidu.com": "not-an-ip",
		}, fallback)
		if err == nil {
			t.Fatal("expected an error for an invalid IP")
		}
	})

	t.Run("miss without fallback fails instead of panicking", func(t *testing.T) {
		resolve, err := newSignalResolverWithHosts(map[string]string{
			"www.baidu.com": "203.0.113.26",
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = resolve(t.Context(), "other.example.com"); err == nil {
			t.Fatal("expected an error")
		}
	})
}
