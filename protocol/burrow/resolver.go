package burrow

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/getkiko/burrow"
)

// newSignalResolverWithHosts puts a static hosts table in front of DNS
// resolution. A domain in the table resolves to the mapped IP; other domains
// fall back to the DNS behavior of fallback. With empty hosts it returns
// fallback unchanged at no extra cost.
func newSignalResolverWithHosts(hosts map[string]string, fallback burrow.ResolveIPFunc) (burrow.ResolveIPFunc, error) {
	if len(hosts) == 0 {
		return fallback, nil
	}
	table := make(map[string][]netip.Addr, len(hosts))
	for host, value := range hosts {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, E.Cause(err, "invalid IP in hosts for "+host+": "+value)
		}
		table[host] = []netip.Addr{address}
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		if addresses, loaded := table[host]; loaded {
			return addresses, nil
		}
		if fallback == nil {
			return nil, E.New("no address found for " + host + ": not in hosts and no domain resolver configured")
		}
		return fallback(ctx, host)
	}, nil
}

func newSignalResolver(ctx context.Context, options *option.DomainResolveOptions) (burrow.ResolveIPFunc, error) {
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	var queryOptions adapter.DNSQueryOptions
	if options != nil {
		resolvedOptions, err := dialer.NewDNSQueryOptions(ctx, options, false)
		if err != nil {
			return nil, err
		}
		queryOptions = resolvedOptions
	} else {
		networkManager := service.FromContext[adapter.NetworkManager](ctx)
		if networkManager == nil {
			return nil, nil
		}
		defaultOptions := networkManager.DefaultOptions()
		if defaultOptions.DomainResolver == "" {
			return nil, nil
		}
		transportManager := service.FromContext[adapter.DNSTransportManager](ctx)
		if transportManager == nil {
			return nil, E.New("missing DNS transport manager for burrow domain resolver")
		}
		transport, loaded := transportManager.Transport(defaultOptions.DomainResolver)
		if !loaded {
			return nil, E.New("domain resolver not found: " + defaultOptions.DomainResolver)
		}
		queryOptions = defaultOptions.DomainResolveOptions
		queryOptions.Transport = transport
	}
	if dnsRouter == nil {
		return nil, E.New("missing DNS router for burrow domain resolver")
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return dnsRouter.Lookup(log.ContextWithOverrideLevel(ctx, log.LevelDebug), host, queryOptions)
	}, nil
}
