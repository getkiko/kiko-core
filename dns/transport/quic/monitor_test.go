package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func testMonitor(t *testing.T) (context.Context, *dnsmonitor.Manager) {
	m := dnsmonitor.New(dnsmonitor.Options{})
	t.Cleanup(func() { m.Close() })
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, m)
	return ctx, m
}
func serverTLS(t *testing.T, alpn string) *tls.Config {
	t.Helper()
	s := httptest.NewTLSServer(http.NotFoundHandler())
	cert := s.TLS.Certificates[0]
	s.Close()
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}
}
func optionsFor(address string) option.RemoteTLSDNSServerOptions {
	addr := netip.MustParseAddrPort(address)
	return option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: option.RemoteDNSServerOptions{DNSServerAddressOptions: option.DNSServerAddressOptions{Server: addr.Addr().String(), ServerPort: addr.Port()}}, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "localhost"}}}
}

func verifyQUICQueries(t *testing.T, ctx context.Context, m *dnsmonitor.Manager, tt adapter.DNSTransport, protocol string) {
	t.Helper()
	var connID string
	var streamID string
	for i := range 2 {
		request := new(dns.Msg)
		request.SetQuestion("quic.example.", dns.TypeA)
		qctx, trace := dnsmonitor.Begin(ctx, request, "query")
		qctx = dnsmonitor.WithResolver(qctx, tt.Tag(), tt.Type())
		qctx = dnsmonitor.WithDialConfig(qctx, "")
		qctx, cancel := context.WithTimeout(qctx, 3*time.Second)
		response, err := tt.Exchange(qctx, request)
		cancel()
		trace.End(response, err)
		if err != nil {
			t.Fatal(err)
		}
		q, _ := m.Get(trace.ID())
		if len(q.Attempts) != 1 || q.Attempts[0].Connection == nil {
			t.Fatalf("attempt binding: %+v", q.Attempts)
		}
		a := q.Attempts[0]
		if a.Protocol != protocol || a.Connection.TLSVersion != "TLS 1.3" {
			t.Fatalf("QUIC TLS: %+v", a)
		}
		if i == 0 {
			connID = a.Connection.ID
			streamID = a.StreamID
		} else {
			if a.Connection.ID != connID || !a.Reused {
				t.Fatalf("QUIC reuse: %+v", a)
			}
			if protocol == "quic" && a.StreamID == streamID {
				t.Fatal("stream identity reused")
			}
		}
		if protocol == "h3" && (a.HTTPVersion != "HTTP/3.0" || a.HTTPStatus != 200) {
			t.Fatalf("HTTP/3 response: %+v", a)
		}
	}
}

func TestMonitorDoQConnectionStreamAndReuse(t *testing.T) {
	ctx, m := testMonitor(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS(t, "doq"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			conn, err := listener.Accept(serverCtx)
			if err != nil {
				return
			}
			go func() {
				defer conn.CloseWithError(0, "")
				for {
					stream, err := conn.AcceptStream(serverCtx)
					if err != nil {
						return
					}
					go func() {
						defer stream.Close()
						q, err := transport.ReadMessage(stream)
						if err != nil {
							return
						}
						response := new(dns.Msg)
						response.SetReply(q)
						_ = transport.WriteMessage(stream, 0, response)
					}()
				}
			}()
		}
	}()
	tt, err := NewQUIC(ctx, log.NewNOPFactory().Logger(), "doq", optionsFor(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Reset()
	verifyQUICQueries(t, ctx, m, tt, "quic")
}

func TestMonitorHTTP3ConnectionAndReuse(t *testing.T) {
	ctx, m := testMonitor(t)
	config := serverTLS(t, "h3")
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", http3.ConfigureTLSConfig(config), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http3.Server{TLSConfig: config, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var q dns.Msg
		if q.Unpack(raw) != nil {
			w.WriteHeader(400)
			return
		}
		response := new(dns.Msg)
		response.SetReply(&q)
		raw, _ = response.Pack()
		w.Header().Set("Content-Type", transport.MimeType)
		_, _ = w.Write(raw)
	})}
	defer server.Close()
	go server.ServeListener(listener)
	tt, err := NewHTTP3(ctx, log.NewNOPFactory().Logger(), "h3", option.RemoteHTTPSDNSServerOptions{RemoteTLSDNSServerOptions: optionsFor(listener.Addr().String())})
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Reset()
	verifyQUICQueries(t, ctx, m, tt, "h3")
}
