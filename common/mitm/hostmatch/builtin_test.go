package hostmatch

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBuiltinTableIsValid(t *testing.T) {
	if BuiltinCount() < 30 {
		t.Fatalf("builtin table has %d entries", BuiltinCount())
	}
	ids := make(map[string]struct{})
	for _, entry := range Builtin() {
		if entry.ID == "" || entry.Category == "" || len(entry.Patterns) == 0 {
			t.Errorf("incomplete entry %+v", entry)
		}
		if _, duplicate := ids[entry.ID]; duplicate {
			t.Errorf("duplicate id %s", entry.ID)
		}
		ids[entry.ID] = struct{}{}
		for _, pattern := range entry.Patterns {
			if pattern != strings.ToLower(pattern) || strings.Contains(pattern, ":") {
				t.Errorf("%s: bad pattern %q", entry.ID, pattern)
			}
		}
	}
	if _, err := NewWithBuiltin([]string{"example.com"}, nil, true, nil); err != nil {
		t.Fatal(err)
	}
	// Builtin returns a copy.
	entries := Builtin()
	entries[0].Patterns[0] = "changed"
	if Builtin()[0].Patterns[0] == "changed" {
		t.Fatal("Builtin shares its patterns")
	}
}

func TestBuiltinPrecedence(t *testing.T) {
	addr := netip.Addr{}
	testCases := []struct {
		name     string
		include  []string
		exclude  []string
		builtin  bool
		disabled []string
		host     string
		port     uint16
		want     Verdict
	}{
		{"builtin off", []string{"*.apple.com"}, nil, false, nil, "a.push.apple.com", 443, VerdictDecrypt},
		{"wildcard include does not override", []string{"*.apple.com"}, nil, true, nil, "a.push.apple.com", 443, VerdictBuiltin},
		{"wildcard include apex of builtin", []string{"*.push.apple.com"}, nil, true, nil, "x.push.apple.com", 443, VerdictBuiltin},
		{"builtin applies on other ports", []string{"*.apple.com:5223"}, nil, true, nil, "x.push.apple.com", 5223, VerdictBuiltin},
		{"exact include overrides", []string{"x.push.apple.com"}, nil, true, nil, "x.push.apple.com", 443, VerdictDecrypt},
		{"exact include with port overrides", []string{"x.push.apple.com:8443"}, nil, true, nil, "x.push.apple.com", 8443, VerdictDecrypt},
		{"exact include of other host does not", []string{"y.push.apple.com", "*.apple.com"}, nil, true, nil, "x.push.apple.com", 443, VerdictBuiltin},
		{"disabled by id", []string{"*.apple.com"}, nil, true, []string{"apple-push"}, "x.push.apple.com", 443, VerdictDecrypt},
		{"disabled by pattern", []string{"*.apple.com"}, nil, true, []string{"*.push.apple.com"}, "x.push.apple.com", 443, VerdictDecrypt},
		{"disabled pattern keeps the apex", []string{"*.apple.com", "apple.com"}, nil, true, []string{"*.push.apple.com"}, "push.apple.com", 443, VerdictBuiltin},
		{"disabled case-insensitive", []string{"*.apple.com"}, nil, true, []string{" Apple-Push "}, "x.push.apple.com", 443, VerdictDecrypt},
		{"not builtin", []string{"*.apple.com"}, nil, true, nil, "www.apple.com", 443, VerdictDecrypt},
		{"not included", []string{"example.com"}, nil, true, nil, "x.push.apple.com", 443, VerdictNone},
		{"exclude wins over exact include", []string{"x.push.apple.com"}, []string{"x.push.apple.com"}, true, nil, "x.push.apple.com", 443, VerdictExcluded},
		{"uppercase host", []string{"*.apple.com"}, nil, true, nil, "X.PUSH.Apple.com.", 443, VerdictBuiltin},
		{"ip include is not exact", []string{"1.2.3.4"}, nil, true, nil, "x.push.apple.com", 443, VerdictNone},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			matcher, err := NewWithBuiltin(testCase.include, testCase.exclude, testCase.builtin, testCase.disabled)
			if err != nil {
				t.Fatal(err)
			}
			if got := matcher.Verdict(testCase.host, addr, testCase.port); got != testCase.want {
				t.Fatalf("verdict %d, want %d", got, testCase.want)
			}
			if got := matcher.Match(testCase.host, addr, testCase.port); got != (testCase.want == VerdictDecrypt) {
				t.Fatalf("match %v", got)
			}
		})
	}
}

func TestBuiltinAnyPort(t *testing.T) {
	matcher, err := NewWithBuiltin([]string{"*.example.com", "a.example.com:8443"}, nil, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.Match("b.example.com", netip.Addr{}, 443) || matcher.Match("b.example.com", netip.Addr{}, 8443) {
		t.Fatal("explicit port semantics changed")
	}
	// Port 0 matches an entry of any port.
	if !matcher.Match("a.example.com", netip.Addr{}, 0) || !matcher.Match("b.example.com", netip.Addr{}, 0) {
		t.Fatal("port 0 does not match any port")
	}
	if matcher.Match("other.test", netip.Addr{}, 0) {
		t.Fatal("port 0 matched an unlisted host")
	}
}

func TestBuiltinRejectsUnknownDisabled(t *testing.T) {
	for _, name := range []string{"nope", "", "push.example.com"} {
		if _, err := NewWithBuiltin([]string{"example.com"}, nil, true, []string{name}); err == nil {
			t.Errorf("disabled %q: expected error", name)
		}
	}
	// Ignored without the table.
	if _, err := NewWithBuiltin([]string{"example.com"}, nil, false, []string{"nope"}); err != nil {
		t.Fatal(err)
	}
}

func TestBuiltinEveryEntryExcludes(t *testing.T) {
	for _, entry := range Builtin() {
		for _, pattern := range entry.Patterns {
			host := strings.TrimPrefix(pattern, "*.")
			if strings.HasPrefix(pattern, "*.") {
				host = "sub." + host
			}
			single, err := NewWithBuiltin([]string{host}, nil, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			// An exact include of the very host overrides; the exclusion is
			// visible through a wildcard include of its parent instead.
			parent := host[strings.IndexByte(host, '.')+1:]
			if !strings.Contains(parent, ".") {
				continue
			}
			wild, err := NewWithBuiltin([]string{"*." + parent}, nil, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := wild.Verdict(host, netip.Addr{}, 443); got != VerdictBuiltin {
				t.Errorf("%s: %s verdict %d", entry.ID, host, got)
			}
			if got := single.Verdict(host, netip.Addr{}, 443); got != VerdictDecrypt {
				t.Errorf("%s: exact include of %s verdict %d", entry.ID, host, got)
			}
		}
	}
}

func TestBuiltinZeroAllocs(t *testing.T) {
	matcher, err := NewWithBuiltin([]string{"*.apple.com", "*.example.com"}, nil, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		matcher.Verdict("x.push.apple.com", netip.Addr{}, 443)
		matcher.Verdict("a.example.com", netip.Addr{}, 443)
		matcher.Verdict("other.test", netip.Addr{}, 443)
	})
	if allocs != 0 {
		t.Fatalf("%v allocations", allocs)
	}
}
