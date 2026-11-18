package dns

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
)

func (r *Router) Exchange(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
	ctx, t := dnsmonitor.BeginRouter(ctx, message)
	response, err := r.exchange(ctx, message, options)
	t.End(response, err)
	return response, err
}

func (r *Router) ExchangeAsync(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions, callback func(*dns.Msg, error)) {
	ctx, t := dnsmonitor.BeginRouter(ctx, message)
	r.exchangeAsync(ctx, message, options, func(response *dns.Msg, err error) { t.End(response, err); callback(response, err) })
}

func (r *Router) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	ctx = dnsmonitor.WithOperation(ctx)
	ctx, trace := dnsmonitor.Begin(ctx, nil, "lookup_operation")
	dnsmonitor.LookupResult(ctx, domain, nil)
	addresses, err := r.lookup(ctx, domain, options)
	dnsmonitor.LookupResult(ctx, domain, addresses)
	trace.End(nil, err)
	return addresses, err
}

func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, checker func(*dns.Msg) bool) (*dns.Msg, error) {
	ctx, t, owner := dnsmonitor.Ensure(ctx, message)
	ctx = dnsmonitor.WithResolver(ctx, transport.Tag(), transport.Type())
	response, err := c.exchange(ctx, transport, message, options, checker)
	if owner {
		t.End(response, err)
	} else {
		dnsmonitor.Result(ctx, response)
	}
	return response, err
}

func (c *Client) ExchangeAsync(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, checker func(*dns.Msg) bool, callback func(*dns.Msg, error)) {
	ctx, t, owner := dnsmonitor.Ensure(ctx, message)
	ctx = dnsmonitor.WithResolver(ctx, transport.Tag(), transport.Type())
	c.exchangeAsync(ctx, transport, message, options, checker, func(response *dns.Msg, err error) {
		if owner {
			t.End(response, err)
		} else {
			dnsmonitor.Result(ctx, response)
		}
		callback(response, err)
	})
}

// Transport-level implementations add precise attempts when they own a socket.
// This fallback retains errors and visibility for platform/synthetic transports.
func monitorTransport(ctx context.Context, transport adapter.DNSTransport) (context.Context, *dnsmonitor.AttemptTrace) {
	if config, ok := transport.(interface{ DNSMonitorDetour() (string, bool) }); ok {
		detour, known := config.DNSMonitorDetour()
		if !known {
			detour = "<unknown>"
		}
		ctx = dnsmonitor.WithDialConfig(ctx, detour)
	}
	switch transport.Type() {
	case "udp", "tcp", "tls", "https", "quic", "h3":
		return ctx, nil
	}
	ctx, a := dnsmonitor.StartAttempt(ctx, transport.Type())
	a.Update(func(v *dnsmonitor.Attempt) {
		v.NetworkUsed = false
		v.Visibility = "transport_managed"
		switch transport.Type() {
		case "hosts", "fakeip", "predefined":
			v.Visibility = "local"
		default:
			v.Visibility = "platform_managed"
		}
	})
	return ctx, a
}
