package httpx

import "strings"

// FilterAltSvc removes the HTTP/3 (and legacy QUIC) alternatives from an
// Alt-Svc field value so that clients keep using TCP through the decrypting
// proxy. It returns the filtered value and whether anything changed; the
// result is empty when no alternative is left (the field should be dropped).
// "clear" and values it cannot split are returned unchanged.
func FilterAltSvc(value string) (string, bool) {
	if !strings.Contains(strings.ToLower(value), "h3") && !strings.Contains(strings.ToLower(value), "quic") {
		return value, false
	}
	var (
		kept    []string
		changed bool
		start   int
		quoted  bool
		escaped bool
	)
	flush := func(end int) {
		entry := strings.TrimSpace(value[start:end])
		start = end + 1
		if entry == "" {
			return
		}
		if altSvcQUICEntry(entry) {
			changed = true
			return
		}
		kept = append(kept, entry)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == ',' && !quoted:
			flush(i)
		}
	}
	flush(len(value))
	if !changed {
		return value, false
	}
	return strings.Join(kept, ", "), true
}

// altSvcQUICEntry reports whether an alt-value (protocol-id=alt-authority;
// parameters) advertises HTTP/3 or Google QUIC.
func altSvcQUICEntry(entry string) bool {
	name, _, found := strings.Cut(entry, "=")
	if !found {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "h3" || strings.HasPrefix(name, "h3-") || name == "quic" || strings.HasPrefix(name, "quic%")
}
