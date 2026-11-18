package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/h2"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestOfferProtocols(t *testing.T) {
	for _, test := range []struct {
		client []string
		h2     bool
		want   []string
	}{
		{[]string{"h2", "http/1.1"}, true, []string{"h2", "http/1.1"}},
		{[]string{"http/1.1", "h2"}, true, []string{"h2", "http/1.1"}},
		{[]string{"http/1.1"}, true, []string{"http/1.1"}},
		{[]string{"h2"}, true, []string{"h2"}},
		{nil, true, []string{"http/1.1"}},
		{[]string{"foo"}, true, []string{"http/1.1"}},
		{[]string{"foo", "bar"}, true, []string{"http/1.1"}},
		{[]string{"h2", "foo"}, true, []string{"h2"}},
		{[]string{"h2", "http/1.1"}, false, []string{"http/1.1"}},
		{[]string{"http/1.1"}, false, []string{"http/1.1"}},
		{[]string{"h2"}, false, nil},
		{nil, false, []string{"http/1.1"}},
		{[]string{"foo"}, false, []string{"http/1.1"}},
		{[]string{"h2", "foo"}, false, nil},
	} {
		require.Equal(t, test.want, offerProtocols(test.client, test.h2), "client %v h2 %v", test.client, test.h2)
	}
}

func TestClientProtocol(t *testing.T) {
	for _, test := range []struct {
		client   []string
		upstream string
		want     string
		fails    bool
	}{
		{[]string{"h2", "http/1.1"}, "h2", "h2", false},
		{[]string{"h2", "http/1.1"}, "http/1.1", "http/1.1", false},
		{[]string{"h2", "http/1.1"}, "", "http/1.1", false},
		{[]string{"h2"}, "http/1.1", "", true},
		{[]string{"h2"}, "", "", true},
		{[]string{"http/1.1"}, "h2", "", true},
		{nil, "", "", false},
		{nil, "http/1.1", "", false},
		{nil, "h2", "", true},
		{[]string{"foo"}, "http/1.1", "", false},
		{[]string{"foo"}, "", "", false},
		{[]string{"foo"}, "h2", "", true},
	} {
		got, err := clientProtocol(test.client, test.upstream)
		if test.fails {
			require.Error(t, err, "client %v upstream %q", test.client, test.upstream)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, test.want, got, "client %v upstream %q", test.client, test.upstream)
	}
}

func TestCheckNegotiated(t *testing.T) {
	require.NoError(t, checkNegotiated([]string{"h2", "http/1.1"}, "h2"))
	require.NoError(t, checkNegotiated([]string{"h2", "http/1.1"}, ""))
	require.NoError(t, checkNegotiated([]string{"http/1.1"}, ""))
	require.Error(t, checkNegotiated([]string{"h2"}, ""))
	require.Error(t, checkNegotiated([]string{"http/1.1"}, "h2"))
	require.Error(t, checkNegotiated([]string{"h2", "http/1.1"}, "spdy/3"))
}

// alpnOrigin is a TLS origin limited to protocols that records the ALPN lists it was offered.
type alpnOrigin struct {
	server  *httptest.Server
	access  sync.Mutex
	offered [][]string
	conns   map[net.Conn]struct{}
}

func newALPNOrigin(t *testing.T, protocols []string, handler http.Handler) *alpnOrigin {
	origin := &alpnOrigin{conns: map[net.Conn]struct{}{}}
	if handler == nil {
		handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte(request.Proto + " " + request.URL.Path))
		})
	}
	origin.server = httptest.NewUnstartedServer(handler)
	origin.server.EnableHTTP2 = slices.Contains(protocols, "h2")
	origin.server.TLS = &tls.Config{
		NextProtos: protocols,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			origin.access.Lock()
			origin.offered = append(origin.offered, slices.Clone(hello.SupportedProtos))
			origin.access.Unlock()
			return nil, nil
		},
	}
	origin.server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		origin.access.Lock()
		defer origin.access.Unlock()
		switch state {
		case http.StateNew:
			origin.conns[conn] = struct{}{}
		case http.StateClosed, http.StateHijacked:
			delete(origin.conns, conn)
		}
	}
	origin.server.StartTLS()
	t.Cleanup(origin.server.Close)
	return origin
}

func (o *alpnOrigin) address() string {
	return o.server.Listener.Addr().String()
}

// closeConnections closes every connection the origin has accepted so far.
func (o *alpnOrigin) closeConnections() {
	o.access.Lock()
	defer o.access.Unlock()
	for conn := range o.conns {
		conn.Close()
	}
}

func (o *alpnOrigin) offers() [][]string {
	o.access.Lock()
	defer o.access.Unlock()
	return slices.Clone(o.offered)
}

func h2Options(ca testCA, h2 *bool) *option.MITMOptions {
	options := fileOptions(ca, true, []string{"example.com"}, nil)
	options.H2 = h2
	return options
}

// expectedNegotiation is what the client should see for an origin and a client offer, or the
// fragment of the failure reason.
func expectedNegotiation(origin []string, client []string, h2 bool) (protocol string, failure string) {
	offer := offerProtocols(client, h2)
	if len(offer) == 0 {
		return "", "no application protocol in common"
	}
	defer func() {
		// A client with only unknown protocols gets no ALPN selected.
		if unknownOnly(client) {
			protocol = ""
		}
	}()
	upstream := ""
	for _, candidate := range origin {
		if slices.Contains(offer, candidate) {
			upstream = candidate
			break
		}
	}
	if upstream == "" && len(offer) == 1 && offer[0] == "http/1.1" {
		// Go servers let a client that offers only http/1.1 through without ALPN.
		upstream = "http/1.1"
	}
	if upstream == "" {
		return "", "upstream TLS handshake"
	}
	return upstream, ""
}

func TestALPNNegotiationMatrix(t *testing.T) {
	origins := map[string][]string{
		"h2+h1":   {"h2", "http/1.1"},
		"h1 only": {"http/1.1"},
		"h2 only": {"h2"},
	}
	clients := map[string][]string{
		"h2+h1":   {"h2", "http/1.1"},
		"h1 only": {"http/1.1"},
		"h2 only": {"h2"},
		"none":    nil,
		"foo":     {"foo"},
	}
	for originName, originProtocols := range origins {
		for clientName, clientProtocols := range clients {
			for _, h2Option := range []bool{true, false} {
				// Without the relay h2 is never offered, whatever the option says.
				h2 := h2Option && h2Supported
				name := "origin " + originName + " client " + clientName + " h2 " + map[bool]string{true: "on", false: "off"}[h2Option]
				t.Run(name, func(t *testing.T) {
					origin := newALPNOrigin(t, originProtocols, nil)
					ctx := contextWithRoots(origin.server)
					ca := writeTestCA(t)
					engine := newTestEngine(t, ctx, h2Options(ca, &h2Option))
					s := startSession(t, context.Background(), engine, origin.address())
					want, failure := expectedNegotiation(originProtocols, clientProtocols, h2)
					if want != "" && clientProtocols == nil {
						want = ""
					}
					clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: clientProtocols})
					handshakeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					err := clientConn.HandshakeContext(handshakeCtx)
					if failure != "" {
						require.Error(t, err)
						require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusFailed }, 5*time.Second, 5*time.Millisecond)
						require.Contains(t, s.state.Reason(), failure)
						return
					}
					require.NoError(t, err)
					require.Equal(t, want, clientConn.ConnectionState().NegotiatedProtocol)
					require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 5*time.Millisecond)
					offered := origin.offers()
					require.Len(t, offered, 1)
					require.Equal(t, offerProtocols(clientProtocols, h2), offered[0])
					clientConn.Close()
				})
			}
		}
	}
}

// Whatever the origin speaks, an HTTP/1.1 client gets HTTP/1.1 and a working request.
func TestHTTP1ClientOverH2Origin(t *testing.T) {
	origin := newALPNOrigin(t, []string{"h2", "http/1.1"}, nil)
	ctx := contextWithRoots(origin.server)
	ca := writeTestCA(t)
	engine := newTestEngine(t, ctx, h2Options(ca, nil))
	s := startSession(t, context.Background(), engine, origin.address())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Equal(t, "http/1.1", clientConn.ConnectionState().NegotiatedProtocol)
	require.Equal(t, [][]string{{"http/1.1"}}, origin.offers())
	client := newRedialClient(clientConn)
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(10*time.Second)))
	status, body, err := client.do(http.MethodGet, "/x", "")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "HTTP/1.1 /x", body)
}

// The h1 redial offers only http/1.1 and the h2 redial only h2, even against an origin that
// speaks both; an origin that cannot do h2 fails the h2 redial.
func TestRedialOffersOneProtocol(t *testing.T) {
	both := newALPNOrigin(t, []string{"h2", "http/1.1"}, nil)
	ctx := contextWithRoots(both.server)
	ca := writeTestCA(t)
	engine := newTestEngine(t, ctx, h2Options(ca, nil))
	redial := &countingRedial{address: both.address()}

	conn, err := engine.redialUpstream(context.Background(), redial.redial, "example.com", 443, []string{"h2"})
	require.NoError(t, err)
	require.Equal(t, "h2", negotiatedProtocol(conn))
	conn.Close()
	conn, err = engine.redialUpstream(context.Background(), redial.redial, "example.com", 443, []string{"http/1.1"})
	require.NoError(t, err)
	require.Equal(t, "http/1.1", negotiatedProtocol(conn))
	conn.Close()
	require.Equal(t, [][]string{{"h2"}, {"http/1.1"}}, both.offers())

	h1Only := newALPNOrigin(t, []string{"http/1.1"}, nil)
	engine = newTestEngine(t, contextWithRoots(h1Only.server), h2Options(ca, nil))
	redial = &countingRedial{address: h1Only.address()}
	_, err = engine.redialUpstream(context.Background(), redial.redial, "example.com", 443, []string{"h2"})
	require.Error(t, err)
	require.Equal(t, [][]string{{"h2"}}, h1Only.offers())
}

// A build without h2 support never offers h2 upstream, whatever the option says.
func TestH2UnsupportedNeverOffered(t *testing.T) {
	saved := h2Supported
	h2Supported = false
	t.Cleanup(func() { h2Supported = saved })
	origin := newALPNOrigin(t, []string{"h2", "http/1.1"}, nil)
	ctx := contextWithRoots(origin.server)
	ca := writeTestCA(t)
	yes := true
	engine := newTestEngine(t, ctx, h2Options(ca, &yes))
	s := startSession(t, context.Background(), engine, origin.address())
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"h2", "http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Equal(t, "http/1.1", clientConn.ConnectionState().NegotiatedProtocol)
	require.Equal(t, [][]string{{"http/1.1"}}, origin.offers())
	clientConn.Close()

	if !h2.Supported {
		return
	}
	// With h2 enabled the same client gets h2 again.
	h2Supported = true
	engine = newTestEngine(t, ctx, h2Options(ca, &yes))
	s = startSession(t, context.Background(), engine, origin.address())
	clientConn = tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: []string{"h2", "http/1.1"}})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Equal(t, "h2", clientConn.ConnectionState().NegotiatedProtocol)
	clientConn.Close()
}
