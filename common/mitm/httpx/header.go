// Package httpx is a minimal HTTP/1.1 message codec for the decrypting proxy. It keeps header
// fields in wire order and case, parses message heads with strict limits, decides body framing
// per RFC 9112 section 6, and implements the chunked transfer coding.
package httpx

import "strings"

// Field is one header field as it appeared on the wire.
type Field struct {
	Name  string
	Value string
}

// Header is an ordered list of fields. Lookups are case-insensitive; order and case are preserved.
type Header []Field

// Get returns the value of the first field named name, or "".
func (h Header) Get(name string) string {
	for i := range h {
		if strings.EqualFold(h[i].Name, name) {
			return h[i].Value
		}
	}
	return ""
}

// Has reports whether a field named name exists.
func (h Header) Has(name string) bool {
	for i := range h {
		if strings.EqualFold(h[i].Name, name) {
			return true
		}
	}
	return false
}

// Count returns the number of fields named name.
func (h Header) Count(name string) int {
	var n int
	for i := range h {
		if strings.EqualFold(h[i].Name, name) {
			n++
		}
	}
	return n
}

// Add appends a field.
func (h *Header) Add(name, value string) {
	*h = append(*h, Field{Name: name, Value: value})
}

// Set replaces the value of the first field named name and removes the others, or appends the field.
func (h *Header) Set(name, value string) {
	fields := *h
	n := 0
	found := false
	for i := range fields {
		if strings.EqualFold(fields[i].Name, name) {
			if found {
				continue
			}
			found = true
			fields[i].Value = value
		}
		fields[n] = fields[i]
		n++
	}
	clear(fields[n:])
	*h = fields[:n]
	if !found {
		h.Add(name, value)
	}
}

// Del removes every field named name.
func (h *Header) Del(name string) {
	*h = h.filter(func(field *Field) bool { return !strings.EqualFold(field.Name, name) })
}

func (h *Header) filter(keep func(field *Field) bool) Header {
	fields := *h
	n := 0
	for i := range fields {
		if keep(&fields[i]) {
			fields[n] = fields[i]
			n++
		}
	}
	clear(fields[n:])
	return fields[:n]
}

// HasToken reports whether any field named name holds token in its comma-separated list,
// compared case-insensitively.
func (h Header) HasToken(name, token string) bool {
	for i := range h {
		if strings.EqualFold(h[i].Name, name) && listHasToken(h[i].Value, token) {
			return true
		}
	}
	return false
}

func listHasToken(list, token string) bool {
	for list != "" {
		var element string
		element, list, _ = strings.Cut(list, ",")
		if strings.EqualFold(trimOWS(element), token) {
			return true
		}
	}
	return false
}

func trimOWS(s string) string {
	for s != "" && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for s != "" && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// hopByHop lists the fields that apply to a single connection (RFC 9110 section 7.6.1), plus
// the legacy Keep-Alive and Proxy-Connection. Trailer is end to end (RFC 9110 section 6.6.2).
var hopByHop = [...]string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"TE",
	"Transfer-Encoding",
	"Upgrade",
}

// IsHopByHop reports whether name is one of the fixed hop-by-hop fields.
func IsHopByHop(name string) bool {
	for _, hop := range hopByHop {
		if strings.EqualFold(name, hop) {
			return true
		}
	}
	return false
}

// connectionProtected lists the end-to-end fields that Connection cannot nominate: the message
// framing and routing were decided from them, so removing them would desynchronize the peers.
var connectionProtected = [...]string{
	"Content-Length",
	"Host",
}

func isConnectionProtected(name string) bool {
	for _, protected := range connectionProtected {
		if strings.EqualFold(name, protected) {
			return true
		}
	}
	return false
}

// RemoveHopByHop removes hop-by-hop fields in place and returns the shortened header: the fixed
// list plus every field named in Connection, except Content-Length and Host, which stay end to
// end. With keepUpgrade the Upgrade field is kept and the
// first Connection field is kept as "upgrade" (verbatim when it lists only that token), so an
// upgrade request or 101 response can be forwarded. Field order is preserved.
func RemoveHopByHop(h Header, keepUpgrade bool) Header {
	// Collect the Connection lists before compacting overwrites them.
	var connectionArray [8]string
	connection := connectionArray[:0]
	for i := range h {
		if strings.EqualFold(h[i].Name, "Connection") {
			connection = append(connection, h[i].Value)
		}
	}
	keptConnection := false
	n := 0
	for i := range h {
		field := h[i]
		name := field.Name
		if strings.EqualFold(name, "Connection") {
			if !keepUpgrade || keptConnection {
				continue
			}
			keptConnection = true
			if !strings.EqualFold(trimOWS(field.Value), "upgrade") {
				field.Value = "Upgrade"
			}
		} else if keepUpgrade && strings.EqualFold(name, "Upgrade") {
			// kept
		} else if IsHopByHop(name) || listsHaveToken(connection, name) && !isConnectionProtected(name) {
			continue
		}
		h[n] = field
		n++
	}
	clear(h[n:])
	return h[:n]
}

func listsHaveToken(lists []string, token string) bool {
	for _, list := range lists {
		if listHasToken(list, token) {
			return true
		}
	}
	return false
}
