package dialer

import (
	"net"
	"sync"

	N "github.com/sagernet/sing/common/network"
)

// Connections returned by a detour pin the outbound they were dialed through,
// so that an outbound replaced by a live apply stays open until they close.

type pinnedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func newPinnedConn(conn net.Conn, release func()) net.Conn {
	return &pinnedConn{Conn: conn, release: release}
}

func (c *pinnedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *pinnedConn) Upstream() any {
	return c.Conn
}

func (c *pinnedConn) UpstreamReader() any {
	return c.Conn
}

func (c *pinnedConn) ReaderReplaceable() bool {
	return true
}

func (c *pinnedConn) UpstreamWriter() any {
	return c.Conn
}

func (c *pinnedConn) WriterReplaceable() bool {
	return true
}

type pinnedPacketConn struct {
	net.PacketConn
	release func()
	once    sync.Once
}

type pinnedNetPacketConn struct {
	N.NetPacketConn
	release func()
	once    sync.Once
}

func newPinnedPacketConn(conn net.PacketConn, release func()) net.PacketConn {
	if netPacketConn, isNetPacketConn := conn.(N.NetPacketConn); isNetPacketConn {
		return &pinnedNetPacketConn{NetPacketConn: netPacketConn, release: release}
	}
	return &pinnedPacketConn{PacketConn: conn, release: release}
}

func (c *pinnedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.release)
	return err
}

func (c *pinnedPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *pinnedNetPacketConn) Close() error {
	err := c.NetPacketConn.Close()
	c.once.Do(c.release)
	return err
}

func (c *pinnedNetPacketConn) Upstream() any {
	return c.NetPacketConn
}

func (c *pinnedNetPacketConn) UpstreamReader() any {
	return c.NetPacketConn
}

func (c *pinnedNetPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *pinnedNetPacketConn) UpstreamWriter() any {
	return c.NetPacketConn
}

func (c *pinnedNetPacketConn) WriterReplaceable() bool {
	return true
}
