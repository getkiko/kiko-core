package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type monitorOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *monitorOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	v, ok := m.outbounds[tag]
	return v, ok
}

type monitorSocketOutbound struct {
	outbound.Adapter
	monitorDialer
}

func TestMonitorTLSHandshakeSocketWrappers(t *testing.T) {
	ctx, _ := monitorTest(t)
	ctx, trace := dnsmonitor.Begin(ctx, nil, "query")
	defer trace.End(nil, nil)
	address := monitorEncryptedServer(t, "tls")
	config, err := boxTLS.NewClient(ctx, log.NewNOPFactory().Logger(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	dnsmonitor.Remember(dnsmonitor.WithOutbound(ctx, "node-a"), raw)
	conn, err := boxTLS.ClientHandshake(ctx, raw, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := dnsmonitor.Freeze(ctx, conn, "tls", address.String())
	defer c.Release()
	if !slices.Equal(c.Outbound, []string{"node-a"}) || c.OutboundEvidence != "observed" {
		t.Fatalf("handshake wrapper %T route: %+v", conn, c)
	}
}

// Exercise the production DNS constructors and the actual detour/selector/TLS
// stack. A selection change must preserve the old socket's observed route.
func TestMonitorEncryptedDetourAndReusedSelection(t *testing.T) {
	for _, protocol := range []string{"tls", "https1", "https2"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, m := monitorTest(t)
			logger := log.NewNOPFactory().Logger()
			manager := &monitorOutboundManager{outbounds: make(map[string]adapter.Outbound)}
			service.MustRegister[adapter.OutboundManager](ctx, manager)
			for _, tag := range []string{"node-a", "node-b"} {
				manager.outbounds[tag] = &monitorSocketOutbound{Adapter: outbound.NewAdapter("direct", tag, nil, nil)}
			}
			selected, err := group.NewSelector(ctx, nil, logger, "proxy", option.SelectorOutboundOptions{Outbounds: []string{"node-a", "node-b"}})
			if err != nil {
				t.Fatal(err)
			}
			selector := selected.(*group.Selector)
			scope := adapter.NewScope(ctx, logger)
			defer scope.Close()
			if err := selector.Start(adapter.StartStateStart, scope); err != nil {
				t.Fatal(err)
			}
			manager.outbounds["proxy"] = selector
			address := monitorEncryptedServer(t, protocol)
			remote := option.RemoteDNSServerOptions{
				DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: address.Addr.String(), ServerPort: address.Port},
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: option.DialerOptions{Detour: "proxy"}},
			}
			tlsOptions := option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true}}
			var tt adapter.DNSTransport
			if protocol == "tls" {
				tt, err = NewTLS(ctx, logger, "dot", option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote, OutboundTLSOptionsContainer: tlsOptions})
			} else {
				tt, err = NewHTTPS(ctx, logger, "doh", option.RemoteHTTPSDNSServerOptions{RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote, OutboundTLSOptionsContainer: tlsOptions}})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.Start(adapter.StartStateStart, scope); err != nil {
				t.Fatal(err)
			}
			reset := func() {
				tt.Reset()
				if dot, ok := tt.(*TLSTransport); ok {
					dot.multiplexer.reuseState.Store(reuseStateSupported)
				}
			}
			reset()
			var firstID, firstQueryID string
			for i := range 3 {
				qctx, trace, request := monitorQuery(t, ctx, tt)
				qctx = dnsmonitor.WithDialConfig(qctx, "proxy")
				qctx, cancel := context.WithTimeout(qctx, 3*time.Second)
				response, err := tt.Exchange(qctx, request)
				cancel()
				trace.End(response, err)
				if err != nil {
					t.Fatal(err)
				}
				q, _ := m.Get(trace.ID())
				if len(q.Attempts) != 1 || q.Attempts[0].Connection == nil {
					t.Fatalf("attempts: %+v", q.Attempts)
				}
				a := q.Attempts[0]
				want := []string{"proxy", "node-a"}
				if i == 2 {
					want[1] = "node-b"
				}
				if !slices.Equal(a.Connection.Outbound, want) || a.Connection.OutboundEvidence != "observed" {
					t.Fatalf("query %d route: %+v; want %v", i, a.Connection, want)
				}
				if a.Connection.TLSVersion == "" {
					t.Fatalf("TLS metadata: %+v", a.Connection)
				}
				switch i {
				case 0:
					firstID = a.Connection.ID
					firstQueryID = trace.ID()
				case 1:
					if !a.Reused || a.Connection.ID != firstID {
						t.Fatalf("reused connection: %+v", a)
					}
					if !selector.SelectOutbound("node-b") {
						t.Fatal("switch selector")
					}
					old, _ := m.Get(firstQueryID)
					if !slices.Equal(old.Attempts[0].Connection.Outbound, []string{"proxy", "node-a"}) {
						t.Fatalf("historical route after switch: %+v", old.Attempts)
					}
					reset()
				case 2:
					if a.Reused || a.Connection.ID == firstID {
						t.Fatalf("new connection: %+v", a)
					}
				}
			}
		})
	}
}

func monitorEncryptedServer(t *testing.T, protocol string) M.Socksaddr {
	t.Helper()
	answer := func(q *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(q)
		rr, _ := dns.NewRR("monitor.example. 60 IN A 192.0.2.5")
		response.Answer = []dns.RR{rr}
		return response
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		var q dns.Msg
		if err != nil || q.Unpack(raw) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, _ = answer(&q).Pack()
		w.Header().Set("Content-Type", MimeType)
		_, _ = w.Write(raw)
	}))
	server.EnableHTTP2 = protocol == "https2"
	server.StartTLS()
	if protocol != "tls" {
		t.Cleanup(server.Close)
		return M.SocksaddrFromNet(server.Listener.Addr())
	}
	cert := server.TLS.Certificates[0]
	server.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				wire := &dns.Conn{Conn: conn}
				for {
					q, err := wire.ReadMsg()
					if err != nil || wire.WriteMsg(answer(q)) != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return M.SocksaddrFromNet(listener.Addr())
}
