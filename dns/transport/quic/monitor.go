package quic

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/dnsmonitor"
)

// Keep metadata for the lifetime of each QUIC connection. HTTP/3's public
// GotConn exposes addresses, so a binding is accepted only for a unique active
// connection with that exact pair. Ambiguous proxy address pairs stay unknown.
type connectionMonitor struct {
	mu          sync.Mutex
	connections map[*quic.Conn]*dnsmonitor.Connection
}

func (m *connectionMonitor) add(ctx context.Context, conn *quic.Conn, raw net.Conn, protocol, endpoint string) {
	c := dnsmonitor.Freeze(ctx, raw, protocol, endpoint)
	if c == nil {
		return
	}
	m.mu.Lock()
	if m.connections == nil {
		m.connections = make(map[*quic.Conn]*dnsmonitor.Connection)
	}
	m.connections[conn] = c
	m.mu.Unlock()
	go func() { <-conn.Context().Done(); c.Release(); m.mu.Lock(); delete(m.connections, conn); m.mu.Unlock() }()
}

func (m *connectionMonitor) get(conn *quic.Conn) *dnsmonitor.Connection {
	m.mu.Lock()
	c := m.connections[conn]
	m.mu.Unlock()
	if c == nil {
		return nil
	}
	copy := *c
	state := conn.ConnectionState().TLS
	copy.TLSVersion = tls.VersionName(state.Version)
	copy.ServerName = state.ServerName
	copy.ALPN = state.NegotiatedProtocol
	return &copy
}

func (m *connectionMonitor) match(fake net.Conn, attempt *dnsmonitor.AttemptTrace) *dnsmonitor.Connection {
	var candidates []*quic.Conn
	m.mu.Lock()
	for conn := range m.connections {
		if conn.Context().Err() == nil && conn.LocalAddr().String() == fake.LocalAddr().String() && conn.RemoteAddr().String() == fake.RemoteAddr().String() {
			candidates = append(candidates, conn)
		}
	}
	m.mu.Unlock()
	if len(candidates) == 1 {
		return m.get(candidates[0])
	}
	attempt.Diagnostic("h3_connection_binding_unknown: address pair is ambiguous or unavailable")
	return nil
}
