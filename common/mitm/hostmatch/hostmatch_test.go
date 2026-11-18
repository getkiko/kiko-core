package hostmatch

import (
	"net/netip"
	"testing"
)

func TestNewRejectsInvalid(t *testing.T) {
	for _, entry := range []string{
		"", " ", "*", "*.", "*.com", "*.com:443", "a.*.example.com", "*example.com", "example.*",
		"example.com:0", "example.com:65536", "example.com:", "example.com:abc", "example.com:+1",
		"exa mple.com", "example..com", ".example.com", "[2001:db8::1", "[2001:db8::1]x",
		"[2001:db8::1]:0", "10.0.0.0/33", "10.0.0.0/x", "fe80::1%eth0", "exam/ple.com",
	} {
		if _, err := New([]string{entry}, nil); err == nil {
			t.Errorf("include %q: expected error", entry)
		}
		if _, err := New(nil, []string{entry}); err == nil {
			t.Errorf("exclude %q: expected error", entry)
		}
	}
}

func TestEmpty(t *testing.T) {
	m, err := New(nil, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Empty() {
		t.Fatal("matcher without include entries should be empty")
	}
	if m.Match("example.org", netip.Addr{}, 443) {
		t.Fatal("empty matcher matched")
	}
	m, _ = New([]string{"example.com"}, nil)
	if m.Empty() {
		t.Fatal("matcher with include entries is not empty")
	}
	var nilMatcher *Matcher
	if !nilMatcher.Empty() || nilMatcher.Match("example.com", netip.Addr{}, 443) {
		t.Fatal("nil matcher")
	}
}

func TestMatch(t *testing.T) {
	m, err := New([]string{
		"example.com",
		"*.wild.example.org",
		"API.Foo.com.:8443",
		"*.both.net", "both.net",
		"192.0.2.10",
		"[2001:db8::1]:8443",
		"2001:db8::2",
		"10.0.0.0/8",
		"[2001:db8:ff::/48]:8443",
		"excluded.wild.example.org",
		"*.deep.example.net",
		"multi.example.com:8443", "multi.example.com:9443",
	}, []string{
		"excluded.wild.example.org",
		"10.9.0.0/16",
		"*.private.deep.example.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	none := netip.Addr{}
	ip := netip.MustParseAddr
	for _, tc := range []struct {
		name string
		addr netip.Addr
		port uint16
		want bool
	}{
		{"example.com", none, 443, true},
		{"EXAMPLE.Com", none, 443, true},
		{"example.com.", none, 443, true},
		{"example.com", none, 8443, false},
		{"www.example.com", none, 443, false},
		{"xexample.com", none, 443, false},
		{"a.wild.example.org", none, 443, true},
		{"a.b.wild.example.org", none, 443, true},
		{"A.WILD.example.org.", none, 443, true},
		{"wild.example.org", none, 443, false},
		{"awild.example.org", none, 443, false},
		{"excluded.wild.example.org", none, 443, false},
		{"api.foo.com", none, 8443, true},
		{"api.foo.com", none, 443, false},
		{"both.net", none, 443, true},
		{"x.both.net", none, 443, true},
		{"multi.example.com", none, 8443, true},
		{"multi.example.com", none, 9443, true},
		{"multi.example.com", none, 443, false},
		{"a.deep.example.net", none, 443, true},
		{"x.private.deep.example.net", none, 443, false},
		{"private.deep.example.net", none, 443, true},
		{"", ip("192.0.2.10"), 443, true},
		{"", ip("::ffff:192.0.2.10"), 443, true},
		{"", ip("192.0.2.10"), 80, false},
		{"", ip("192.0.2.11"), 443, false},
		{"", ip("2001:db8::1"), 8443, true},
		{"", ip("2001:db8::1"), 443, false},
		{"", ip("2001:db8::2"), 443, true},
		{"", ip("10.1.2.3"), 443, true},
		{"", ip("10.9.2.3"), 443, false},
		{"", ip("11.0.0.1"), 443, false},
		{"", ip("2001:db8:ff:1::1"), 8443, true},
		{"", ip("2001:db8:ff:1::1"), 443, false},
		{"", none, 443, false},
		{"unrelated.org", ip("10.1.2.3"), 443, true},
		{"example.com", ip("10.9.2.3"), 443, false},
		{"unrelated.org", none, 443, false},
		{"com", none, 443, false},
		{".", none, 443, false},
	} {
		if got := m.Match(tc.name, tc.addr, tc.port); got != tc.want {
			t.Errorf("Match(%q, %v, %d) = %v, want %v", tc.name, tc.addr, tc.port, got, tc.want)
		}
	}
}

func TestExcludeWins(t *testing.T) {
	m, err := New([]string{"*.example.com", "example.com"}, []string{"example.com", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"example.com", "a.example.com"} {
		if m.Match(name, netip.Addr{}, 443) {
			t.Errorf("%s: exclude should win", name)
		}
	}
}

func TestLongName(t *testing.T) {
	m, _ := New([]string{"*.example.com"}, nil)
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if m.Match(string(long)+".example.com", netip.Addr{}, 443) {
		t.Fatal("over-long names never match")
	}
}

func TestMatchZeroAllocs(t *testing.T) {
	m, err := New([]string{"example.com", "*.example.org", "10.0.0.0/8", "192.0.2.1"}, []string{"x.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("198.51.100.1")
	for _, name := range []string{"miss.invalid", "Example.COM.", "a.b.c.example.org", "x.example.org", ""} {
		allocs := testing.AllocsPerRun(1000, func() {
			m.Match(name, addr, 443)
		})
		if allocs != 0 {
			t.Errorf("Match(%q) allocs = %v", name, allocs)
		}
	}
}

func BenchmarkMatchMiss(b *testing.B) {
	m, _ := New([]string{"example.com", "*.example.org", "10.0.0.0/8"}, []string{"x.example.org"})
	addr := netip.MustParseAddr("198.51.100.1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Match("www.unrelated.example.net", addr, 443)
	}
}
