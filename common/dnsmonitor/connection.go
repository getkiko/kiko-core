package dnsmonitor

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"reflect"
	"time"
)

type outboundKey struct{}
type dialConfigKey struct{}

func WithDialConfig(ctx context.Context, detour string) context.Context {
	if Current(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, dialConfigKey{}, detour)
}

// The path is immutable and local to a dial candidate. Parallel dials may finish
// in any order; only the returned socket's path is used by the DNS attempt.
func WithOutbound(ctx context.Context, tag string) context.Context {
	if Current(ctx) == nil {
		return ctx
	}
	path, _ := ctx.Value(outboundKey{}).([]string)
	if len(path) > 0 && path[len(path)-1] == tag {
		return ctx
	}
	return context.WithValue(ctx, outboundKey{}, append(append([]string(nil), path...), tag))
}

func comparable(key any) bool { return key != nil && reflect.TypeOf(key).Comparable() }

func (m *Manager) lookupConn(key any) *Connection {
	if !comparable(key) {
		return nil
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return m.connections[key]
}
func (m *Manager) storeConn(key any, c *Connection) {
	if !comparable(key) || c == nil {
		return
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if len(m.connections) >= 4096 {
		for k := range m.connections {
			delete(m.connections, k)
			break
		}
	}
	m.connections[key] = c
}

// Remember records an actually executed outbound and propagates metadata across
// wrappers without changing any socket interfaces or optional type assertions.
func Remember(ctx context.Context, key any) {
	if Current(ctx) == nil || key == nil {
		return
	}
	m := FromContext(ctx)
	if m == nil {
		return
	}
	path, _ := ctx.Value(outboundKey{}).([]string)
	if old := m.lookupConn(key); old != nil && len(old.Outbound) >= len(path) {
		return
	}
	m.storeConn(key, &Connection{ID: m.nextID(), CreatedAt: time.Now(), Outbound: append([]string(nil), path...), OutboundEvidence: "observed", PeerEvidence: "logical_socket"})
}

func Alias(ctx context.Context, from, to any) {
	if Current(ctx) == nil {
		return
	}
	m := FromContext(ctx)
	if m == nil {
		return
	}
	if c := m.lookupConn(from); c != nil {
		m.storeConn(to, c)
	} else {
		Remember(ctx, to)
	}
}

func ConnectionOf(ctx context.Context, key any) *Connection {
	m := FromContext(ctx)
	if m == nil {
		return nil
	}
	return m.lookupConn(key)
}

func Freeze(ctx context.Context, key any, protocol, configured string) *Connection {
	if Current(ctx) == nil {
		return nil
	}
	m := FromContext(ctx)
	if m == nil {
		return nil
	}
	c := Connection{ID: m.nextID(), CreatedAt: time.Now(), PeerEvidence: "logical_socket", OutboundEvidence: "unknown"}
	if old := m.lookupConn(key); old != nil {
		c = *old
	}
	c.owner = m
	c.Protocol = protocol
	c.Configured = configured
	if a, ok := key.(interface {
		LocalAddr() net.Addr
		RemoteAddr() net.Addr
	}); ok {
		if a.LocalAddr() != nil {
			c.Local = a.LocalAddr().String()
		}
		if a.RemoteAddr() != nil {
			c.Peer = a.RemoteAddr().String()
		}
	}
	if stateConn, ok := key.(interface{ ConnectionState() tls.ConnectionState }); ok {
		state := stateConn.ConnectionState()
		c.TLSVersion = tls.VersionName(state.Version)
		c.ServerName = state.ServerName
		c.ALPN = state.NegotiatedProtocol
	}
	if len(c.Outbound) == 0 {
		if detour, ok := ctx.Value(dialConfigKey{}).(string); ok && detour == "" {
			c.Outbound = []string{"direct"}
			c.OutboundEvidence = "configured_direct"
			c.PeerEvidence = "observed_socket"
		}
	}
	m.storeConn(key, &c)
	return &c
}

func HTTPTrace(ctx context.Context, bind func(net.Conn) *Connection) context.Context {
	a := ActiveAttempt(ctx)
	if a == nil {
		return ctx
	}
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn:              func(info httptrace.GotConnInfo) { c := bind(info.Conn); a.Bind(c, info.Reused) },
		WroteRequest:         func(info httptrace.WroteRequestInfo) { a.Sent(0, info.Err) },
		GotFirstResponseByte: func() { a.Update(func(v *Attempt) { now := time.Now(); v.FirstByteAt = &now }) },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				a.Diagnostic("TLS handshake: " + err.Error())
			}
		},
	})
}
