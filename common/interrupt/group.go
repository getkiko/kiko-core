package interrupt

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	access             sync.Mutex
	connections        list.List[*groupConnItem]
	internalGeneration uint64
	externalGeneration uint64
}

// Token binds connection registration to the selection in effect before dialing.
// A switch can interrupt the dial even when it finishes after Interrupt returns.
type Token struct {
	group              *Group
	internalGeneration uint64
	externalGeneration uint64
}

func (g *Group) Begin() Token {
	g.access.Lock()
	defer g.access.Unlock()
	return Token{g, g.internalGeneration, g.externalGeneration}
}

func (t Token) interrupted(isExternal bool) bool {
	if isExternal {
		return t.externalGeneration != t.group.externalGeneration
	}
	return t.internalGeneration != t.group.internalGeneration
}

func (t Token) add(conn io.Closer, isExternal bool) (*list.Element[*groupConnItem], error) {
	t.group.access.Lock()
	if t.interrupted(isExternal) {
		t.group.access.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	item := t.group.connections.PushBack(&groupConnItem{conn, isExternal})
	t.group.access.Unlock()
	return item, nil
}

func (t Token) NewConn(conn net.Conn, isExternal bool) (net.Conn, error) {
	item, err := t.add(conn, isExternal)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: conn, group: t.group, element: item}, nil
}

func (t Token) NewPacketConn(conn net.PacketConn, isExternal bool) (net.PacketConn, error) {
	item, err := t.add(conn, isExternal)
	if err != nil {
		return nil, err
	}
	return newPacketConn(t.group, conn, item), nil
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
}

func NewGroup() *Group {
	return &Group{}
}

func (g *Group) Add(closer io.Closer, isExternal bool) (remove func()) {
	g.access.Lock()
	defer g.access.Unlock()
	element := g.connections.PushBack(&groupConnItem{closer, isExternal})
	return func() {
		g.access.Lock()
		defer g.access.Unlock()
		g.connections.Remove(element)
	}
}

func (g *Group) NewConn(conn net.Conn, isExternal bool) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return &Conn{Conn: conn, group: g, element: item}
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal bool) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return newPacketConn(g, conn, item)
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	g.internalGeneration++
	if interruptExternalConnections {
		g.externalGeneration++
	}
	var closers []io.Closer
	for element := g.connections.Front(); element != nil; {
		nextElement := element.Next()
		if !element.Value.isExternal || interruptExternalConnections {
			closers = append(closers, element.Value.conn)
			g.connections.Remove(element)
		}
		element = nextElement
	}
	g.access.Unlock()
	for _, closer := range closers {
		closer.Close()
	}
}
