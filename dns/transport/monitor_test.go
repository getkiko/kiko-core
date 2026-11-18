package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type monitorDialer struct{}

func (monitorDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}
func (monitorDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func monitorTest(t *testing.T) (context.Context, *dnsmonitor.Manager) {
	m := dnsmonitor.New(dnsmonitor.Options{})
	t.Cleanup(func() { m.Close() })
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, m)
	return ctx, m
}
func monitorQuery(t *testing.T, ctx context.Context, transport adapter.DNSTransport) (context.Context, *dnsmonitor.Trace, *dns.Msg) {
	request := new(dns.Msg)
	request.SetQuestion("monitor.example.", dns.TypeA)
	ctx, trace := dnsmonitor.Begin(ctx, request, "query")
	dnsmonitor.Resolver(ctx, transport.Tag(), transport.Type())
	ctx = dnsmonitor.WithDialConfig(ctx, "")
	return ctx, trace, request
}

func TestMonitorUDPTruncationAndConnectionReuse(t *testing.T) {
	ctx, m := monitorTest(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			buffer := make([]byte, 4096)
			n, addr, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			var q dns.Msg
			if q.Unpack(buffer[:n]) != nil {
				continue
			}
			r := new(dns.Msg)
			r.SetReply(&q)
			r.Truncated = true
			raw, _ := r.Pack()
			_, _ = udp.WriteTo(raw, addr)
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				q, err := ReadMessage(conn)
				if err != nil {
					return
				}
				r := new(dns.Msg)
				r.SetReply(q)
				_ = WriteMessage(conn, q.Id, r)
			}()
		}
	}()
	tt := NewUDPRaw(log.NewNOPFactory().Logger(), boxDNS.NewTransportAdapter("udp", "resolver", nil), monitorDialer{}, M.SocksaddrFromNet(udp.LocalAddr()))
	defer tt.multiplexer.Close()
	var firstID string
	for i := range 2 {
		qctx, trace, request := monitorQuery(t, ctx, tt)
		qctx, cancel := context.WithTimeout(qctx, time.Second)
		response, err := tt.Exchange(qctx, request)
		cancel()
		trace.End(response, err)
		if err != nil {
			t.Fatal(err)
		}
		q, _ := m.Get(trace.ID())
		if len(q.Attempts) != 2 || q.Attempts[0].Protocol != "udp" || q.Attempts[1].Protocol != "tcp" {
			t.Fatalf("attempts %+v", q.Attempts)
		}
		conn := q.Attempts[0].Connection
		if conn == nil || len(conn.Outbound) == 0 || conn.Outbound[0] != "direct" {
			t.Fatal("direct evidence lost")
		}
		if i == 0 {
			firstID = conn.ID
		} else if conn.ID != firstID || !q.Attempts[0].Reused {
			t.Fatal("reuse lost")
		}
	}
}

func TestMonitorMalformedUDPTimeout(t *testing.T) {
	ctx, m := monitorTest(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 4096)
		_, addr, err := udp.ReadFrom(buffer)
		if err == nil {
			_, _ = udp.WriteTo([]byte{0, 1, 2}, addr)
		}
	}()
	tt := NewUDPRaw(log.NewNOPFactory().Logger(), boxDNS.NewTransportAdapter("udp", "resolver", nil), monitorDialer{}, M.SocksaddrFromNet(udp.LocalAddr()))
	defer tt.multiplexer.Close()
	ctx, trace, request := monitorQuery(t, ctx, tt)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Millisecond)
	defer cancel()
	response, err := tt.Exchange(ctx, request)
	trace.End(response, err)
	q, _ := m.Get(trace.ID())
	if q.Status != "timeout" || len(q.Attempts) != 1 || !slices.Contains(q.Attempts[0].Diagnostics, "invalid_response_discarded") || !slices.Contains(q.Attempts[0].Diagnostics, "no_matching_response_before_deadline") {
		t.Fatalf("timeout %+v", q)
	}
}

func TestMonitorDoHTLSHTTPVersionAndReuse(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			ctx, m := monitorTest(t)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				var q dns.Msg
				if q.Unpack(raw) != nil {
					w.WriteHeader(400)
					return
				}
				response := new(dns.Msg)
				response.SetReply(&q)
				rr, _ := dns.NewRR("monitor.example. 60 IN A 192.0.2.5")
				response.Answer = []dns.RR{rr}
				raw, _ = response.Pack()
				w.Header().Set("Content-Type", MimeType)
				_, _ = w.Write(raw)
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			config, err := boxTLS.NewClient(ctx, log.NewNOPFactory().Logger(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true})
			if err != nil {
				t.Fatal(err)
			}
			config.SetNextProtos([]string{"h2", "http/1.1"})
			addr := M.SocksaddrFromNet(server.Listener.Addr())
			destination, _ := url.Parse(server.URL + "/dns-query")
			tt := NewHTTPSRaw(boxDNS.NewTransportAdapter("https", "doh", nil), log.NewNOPFactory().Logger(), monitorDialer{}, destination, http.Header{}, addr, config)
			defer tt.Reset()
			var firstID string
			for i := range 2 {
				qctx, trace, request := monitorQuery(t, ctx, tt)
				response, err := tt.Exchange(qctx, request)
				trace.End(response, err)
				if err != nil {
					t.Fatal(err)
				}
				q, _ := m.Get(trace.ID())
				if len(q.Attempts) != 1 {
					t.Fatalf("attempts %+v", q.Attempts)
				}
				a := q.Attempts[0]
				if a.HTTPStatus != 200 || a.Connection == nil || a.Connection.TLSVersion == "" {
					t.Fatalf("http trace %+v", a)
				}
				want := "HTTP/1.1"
				if h2 {
					want = "HTTP/2.0"
				}
				if a.HTTPVersion != want {
					t.Fatalf("version %s", a.HTTPVersion)
				}
				if i == 0 {
					firstID = a.Connection.ID
				} else if a.Connection.ID != firstID || !a.Reused {
					t.Fatal("DoH reuse lost")
				}
			}
		})
	}
}

func TestMonitorDoTHandshakeAndAnswer(t *testing.T) {
	ctx, m := monitorTest(t)
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					q, err := ReadMessage(conn)
					if err != nil {
						return
					}
					response := new(dns.Msg)
					response.SetReply(q)
					if WriteMessage(conn, q.Id, response) != nil {
						return
					}
				}
			}()
		}
	}()
	config, err := boxTLS.NewClient(ctx, log.NewNOPFactory().Logger(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	tt := NewTLSRaw(log.NewNOPFactory().Logger(), boxDNS.NewTransportAdapter("tls", "dot", nil), monitorDialer{}, M.SocksaddrFromNet(listener.Addr()), config)
	defer tt.multiplexer.Close()
	// Force shared mode here; the separate probe tests cover capability discovery.
	tt.multiplexer.reuseState.Store(reuseStateSupported)
	ctx, trace, request := monitorQuery(t, ctx, tt)
	response, err := tt.Exchange(ctx, request)
	trace.End(response, err)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := m.Get(trace.ID())
	if q.Attempts[0].Protocol != "tls" || q.Attempts[0].Connection.TLSVersion == "" {
		t.Fatalf("TLS evidence: %+v", q.Attempts)
	}
}

func TestMonitorHTTPFailureDetails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"http_status", 503, "unavailable"}, {"malformed_dns", 200, "invalid DNS response"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, m := monitorTest(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			destination, _ := url.Parse(server.URL)
			tt := NewHTTPSRaw(boxDNS.NewTransportAdapter("https", "failure", nil), log.NewNOPFactory().Logger(), monitorDialer{}, destination, http.Header{}, M.SocksaddrFromNet(server.Listener.Addr()), nil)
			defer tt.Reset()
			qctx, trace, request := monitorQuery(t, ctx, tt)
			response, err := tt.Exchange(qctx, request)
			trace.End(response, err)
			q, _ := m.Get(trace.ID())
			if err == nil || q.Status != "error" || q.Attempts[0].Error == nil || q.Attempts[0].HTTPStatus != tc.status {
				t.Fatalf("HTTP failure: %+v", q)
			}
		})
	}
}

func TestMonitorTLSHandshakeFailure(t *testing.T) {
	ctx, m := monitorTest(t)
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	config, err := boxTLS.NewClient(ctx, log.NewNOPFactory().Logger(), "localhost", option.OutboundTLSOptions{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tt := NewTLSRaw(log.NewNOPFactory().Logger(), boxDNS.NewTransportAdapter("tls", "bad-certificate", nil), monitorDialer{}, M.SocksaddrFromNet(server.Listener.Addr()), config)
	defer tt.multiplexer.Close()
	tt.multiplexer.reuseState.Store(reuseStateSupported)
	qctx, trace, request := monitorQuery(t, ctx, tt)
	response, err := tt.Exchange(qctx, request)
	trace.End(response, err)
	q, _ := m.Get(trace.ID())
	if err == nil || q.Attempts[0].Error == nil || q.Attempts[0].Error.Stage != "dial_or_handshake" {
		t.Fatalf("handshake: %+v", q)
	}
}
