// Package hostmatch decides by server name, address and port whether a TLS connection is decrypted.
package hostmatch

import (
	"net/netip"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// DefaultPort is the port an entry without an explicit port matches.
const DefaultPort = 443

// maxNameLength bounds the server names Match normalizes on the stack.
const maxNameLength = 253

// Matcher is a precompiled include / exclude host list with the optional
// built-in exclusion table. It is immutable and safe for concurrent use.
type Matcher struct {
	include set
	exclude set
	builtin set
	// builtinOn is set when the built-in table has any enabled pattern.
	builtinOn bool
}

// Verdict is the decision of a Matcher for one connection.
type Verdict uint8

const (
	// VerdictNone: no include entry matches.
	VerdictNone Verdict = iota
	// VerdictDecrypt: the connection is decrypted.
	VerdictDecrypt
	// VerdictExcluded: a user exclude entry matches.
	VerdictExcluded
	// VerdictBuiltin: an include entry matches, but a built-in exclusion
	// keeps the host out.
	VerdictBuiltin
)

type set struct {
	exact    map[string][]uint16 // "example.com"
	wildcard map[string][]uint16 // "*.example.com" keyed by "example.com"
	addrs    map[netip.Addr][]uint16
	prefixes []prefixEntry
	count    int
}

type prefixEntry struct {
	prefix netip.Prefix
	port   uint16
}

// New validates and compiles host entries. Entry forms: "example.com" (exact), "*.example.com"
// (any subdomain at any depth, not the apex), an optional ":port" suffix on either
// ("api.foo.com:8443"; without a port an entry only matches port 443), IP literals ("1.2.3.4",
// "2001:db8::1", "[2001:db8::1]:8443") and CIDR prefixes ("10.0.0.0/8", "[2001:db8::/32]:8443").
// Names are case-insensitive and a trailing dot is ignored. Rejected: "", "*", single-label
// wildcards such as "*.com", "*" in any other position, ports outside 1..65535.
//
// New has no built-in exclusions; NewWithBuiltin adds them.
func New(include, exclude []string) (*Matcher, error) {
	return NewWithBuiltin(include, exclude, false, nil)
}

// NewWithBuiltin is New plus the built-in exclusion table when builtin is true.
// disabledBuiltin lists entries of the table, by id or single pattern, that
// stay decryptable; it must name existing entries and is ignored when builtin
// is false.
func NewWithBuiltin(include, exclude []string, builtin bool, disabledBuiltin []string) (*Matcher, error) {
	m := &Matcher{}
	if builtin {
		table, err := compileBuiltin(disabledBuiltin)
		if err != nil {
			return nil, E.Cause(err, "disabled_builtin")
		}
		m.builtin = table
		m.builtinOn = table.count > 0
	}
	if err := m.include.compile(include); err != nil {
		return nil, E.Cause(err, "include")
	}
	if err := m.exclude.compile(exclude); err != nil {
		return nil, E.Cause(err, "exclude")
	}
	return m, nil
}

// Empty reports whether the matcher has no include entries.
func (m *Matcher) Empty() bool {
	return m == nil || m.include.count == 0
}

// Match reports whether a connection should be decrypted by host: see Verdict.
// Name entries are tested against serverName, IP and CIDR entries against
// addr; serverName "" means no SNI, so only IP and CIDR entries can match.
// Port 0 matches entries of any port. It does not allocate.
func (m *Matcher) Match(serverName string, addr netip.Addr, port uint16) bool {
	return m.Verdict(serverName, addr, port) == VerdictDecrypt
}

// Verdict applies, in order: exclude entries (VerdictExcluded), include
// entries (VerdictNone without a match), then the built-in table
// (VerdictBuiltin). A built-in pattern keeps an included host out unless an
// include entry names the host exactly or the pattern is disabled; wildcard
// and IP includes never override it. Built-in patterns apply to every port.
func (m *Matcher) Verdict(serverName string, addr netip.Addr, port uint16) Verdict {
	if m == nil || m.include.count == 0 {
		return VerdictNone
	}
	var buffer [maxNameLength]byte
	name, nameOK := normalizeName(&buffer, serverName)
	addr = addr.Unmap()
	if m.exclude.count > 0 && m.exclude.match(name, nameOK, addr, port) {
		return VerdictExcluded
	}
	if !m.include.match(name, nameOK, addr, port) {
		return VerdictNone
	}
	if m.builtinOn && nameOK && m.builtin.match(name, true, netip.Addr{}, 0) && !m.include.matchExact(name, port) {
		return VerdictBuiltin
	}
	return VerdictDecrypt
}

// normalizeName lowercases serverName into buffer and drops one trailing dot.
func normalizeName(buffer *[maxNameLength]byte, serverName string) ([]byte, bool) {
	serverName = strings.TrimSuffix(serverName, ".")
	if serverName == "" || len(serverName) > maxNameLength {
		return nil, false
	}
	for i := 0; i < len(serverName); i++ {
		c := serverName[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		buffer[i] = c
	}
	return buffer[:len(serverName)], true
}

// hasPort reports whether ports contains port; port 0 matches any port.
func hasPort(ports []uint16, port uint16) bool {
	if port == 0 {
		return len(ports) > 0
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// matchExact reports whether an exact host entry matches name.
func (s *set) matchExact(name []byte, port uint16) bool {
	ports, loaded := s.exact[string(name)]
	return loaded && hasPort(ports, port)
}

func (s *set) match(name []byte, nameOK bool, addr netip.Addr, port uint16) bool {
	if nameOK {
		if ports, loaded := s.exact[string(name)]; loaded && hasPort(ports, port) {
			return true
		}
		if len(s.wildcard) > 0 {
			for i := 0; i < len(name); i++ {
				if name[i] != '.' {
					continue
				}
				if ports, loaded := s.wildcard[string(name[i+1:])]; loaded && hasPort(ports, port) {
					return true
				}
			}
		}
	}
	if addr.IsValid() {
		if ports, loaded := s.addrs[addr]; loaded && hasPort(ports, port) {
			return true
		}
		for i := range s.prefixes {
			entry := &s.prefixes[i]
			if entry.port == port && entry.prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func (s *set) compile(entries []string) error {
	for _, entry := range entries {
		if err := s.add(entry); err != nil {
			return E.Cause(err, "host entry ", strconv.Quote(entry))
		}
	}
	return nil
}

func (s *set) add(entry string) error {
	host, port, err := splitPort(strings.TrimSpace(entry))
	if err != nil {
		return err
	}
	if host == "" {
		return E.New("empty host")
	}
	if strings.Contains(host, "/") {
		prefix, err := netip.ParsePrefix(host)
		if err != nil {
			return E.Cause(err, "invalid CIDR")
		}
		if prefix.Addr().Zone() != "" {
			return E.New("zoned CIDR")
		}
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), max(prefix.Bits()-96, 0))
		}
		s.prefixes = append(s.prefixes, prefixEntry{prefix: prefix.Masked(), port: port})
		s.count++
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return E.New("zoned address")
		}
		if s.addrs == nil {
			s.addrs = make(map[netip.Addr][]uint16)
		}
		addr = addr.Unmap()
		s.addrs[addr] = appendPort(s.addrs[addr], port)
		s.count++
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	target := &s.exact
	if rest, isWildcard := strings.CutPrefix(name, "*."); isWildcard {
		if !strings.Contains(rest, ".") {
			return E.New("wildcard must cover at least two labels")
		}
		name = rest
		target = &s.wildcard
	}
	if err := validateName(name); err != nil {
		return err
	}
	if *target == nil {
		*target = make(map[string][]uint16)
	}
	(*target)[name] = appendPort((*target)[name], port)
	s.count++
	return nil
}

func appendPort(ports []uint16, port uint16) []uint16 {
	if hasPort(ports, port) {
		return ports
	}
	return append(ports, port)
}

// splitPort separates an optional ":port". A bare IPv6 literal or prefix (more than one colon,
// no brackets) has no port.
func splitPort(entry string) (string, uint16, error) {
	if strings.HasPrefix(entry, "[") {
		end := strings.IndexByte(entry, ']')
		if end < 0 {
			return "", 0, E.New("missing ]")
		}
		host, rest := entry[1:end], entry[end+1:]
		if rest == "" {
			return host, DefaultPort, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, E.New("unexpected characters after ]")
		}
		port, err := parsePort(rest[1:])
		return host, port, err
	}
	switch strings.Count(entry, ":") {
	case 0:
		return entry, DefaultPort, nil
	case 1:
		host, portString, _ := strings.Cut(entry, ":")
		port, err := parsePort(portString)
		return host, port, err
	default:
		return entry, DefaultPort, nil
	}
}

func parsePort(s string) (uint16, error) {
	value, err := strconv.ParseUint(s, 10, 16)
	if err != nil || value == 0 || s[0] == '+' {
		return 0, E.New("invalid port ", strconv.Quote(s))
	}
	return uint16(value), nil
}

func validateName(name string) error {
	if name == "" {
		return E.New("empty host")
	}
	if len(name) > maxNameLength {
		return E.New("host name too long")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return E.New("empty label")
		}
		if len(label) > 63 {
			return E.New("label too long")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
			case c == '*':
				return E.New("wildcard is only allowed as the leading label")
			default:
				return E.New("invalid character ", strconv.QuoteRune(rune(c)))
			}
		}
	}
	return nil
}
