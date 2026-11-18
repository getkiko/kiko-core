package daemon

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/lifecycle"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *StartedService) TestPolicy(ctx context.Context, request *PolicyTestRequest) (*PolicyTestResult, error) {
	s.serviceAccess.RLock()
	instance := s.instance
	started := s.serviceStatus.Status == ServiceStatus_STARTED
	s.serviceAccess.RUnlock()
	if !started || instance == nil {
		return nil, status.Error(codes.FailedPrecondition, "sing-box is not running")
	}
	if request.GetSection() != "route" && request.GetSection() != "dns" {
		return nil, status.Error(codes.InvalidArgument, "invalid policy section")
	}
	source, err := netip.ParseAddr(request.GetSourceIp())
	if err != nil || request.GetInbound() == "" || request.GetDestinationPort() > 65535 || request.GetSourcePort() > 65535 {
		return nil, status.Error(codes.InvalidArgument, "invalid source, inbound, or port")
	}
	if request.GetDomain() == "" && request.GetDestinationIp() == "" {
		return nil, status.Error(codes.InvalidArgument, "domain or destination IP required")
	}
	if request.GetNetwork() != "tcp" && request.GetNetwork() != "udp" {
		return nil, status.Error(codes.InvalidArgument, "invalid network")
	}
	var destination netip.Addr
	if request.GetDestinationIp() != "" {
		destination, err = netip.ParseAddr(request.GetDestinationIp())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid destination IP")
		}
	}
	inboundType := ""
	if inbound, loaded := service.FromContext[adapter.InboundManager](instance.ctx).Get(request.GetInbound()); loaded {
		inboundType = inbound.Type()
	} else if endpoint, loaded := instance.endpointManager.Get(request.GetInbound()); loaded {
		inboundType = endpoint.Type()
	} else {
		return nil, status.Error(codes.InvalidArgument, "inbound is not active")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ctx, metadata := adapter.ExtendContext(ctx)
	*metadata = adapter.InboundContext{
		Inbound: request.GetInbound(), InboundType: inboundType,
		Network: request.GetNetwork(), Protocol: request.GetProtocol(),
		Source:      M.Socksaddr{Addr: source, Port: uint16(request.GetSourcePort())},
		Destination: M.Socksaddr{Addr: destination, Port: uint16(request.GetDestinationPort())},
		Domain:      strings.TrimSuffix(strings.ToLower(request.GetDomain()), "."),
	}
	answer := &PolicyTestResult{RuleIndex: -1, TestedAt: time.Now().UnixMilli()}
	if revision := service.FromContext[*lifecycle.Instance](instance.ctx); revision != nil {
		answer.ConfigRevision = revision.CurrentRevision()
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](instance.ctx)
	router, ok := service.FromContext[adapter.Router](instance.ctx).(*route.Router)
	if !ok {
		return nil, status.Error(codes.Unavailable, "active router unavailable")
	}
	if request.GetSection() == "dns" {
		if metadata.Domain == "" {
			return nil, status.Error(codes.InvalidArgument, "DNS test requires a domain")
		}
		trace := &boxDNS.PolicyTrace{}
		queryCtx := boxDNS.WithPolicyTrace(ctx, trace)
		query := new(mDNS.Msg)
		query.SetQuestion(mDNS.Fqdn(metadata.Domain), mDNS.TypeA)
		response, queryErr := dnsRouter.Exchange(queryCtx, query, adapter.DNSQueryOptions{})
		var ruleIndex int
		answer.Rule, ruleIndex, answer.DnsServer, answer.DnsDetour = trace.Snapshot()
		answer.RuleIndex = int32(ruleIndex)
		if queryErr != nil {
			return nil, status.Error(codes.Unavailable, queryErr.Error())
		}
		if answer.DnsDetour != "" {
			answer.OutboundPath, err = router.OutboundPath(answer.DnsDetour)
			if err != nil {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
		}
		answer.Action = "dns"
		answer.DnsRcode = mDNS.RcodeToString[response.Rcode]
		for _, address := range boxDNS.MessageToAddresses(response) {
			answer.ResolvedAddresses = append(answer.ResolvedAddresses, address.String())
		}
		return answer, nil
	}
	if !destination.IsValid() {
		addresses, lookupErr := dnsRouter.Lookup(ctx, metadata.Domain, adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
		if lookupErr != nil || len(addresses) == 0 {
			return nil, status.Error(codes.Unavailable, "domain has no usable IPv4 DNS answer")
		}
		for _, address := range addresses {
			answer.ResolvedAddresses = append(answer.ResolvedAddresses, address.String())
		}
		destination = addresses[0]
		metadata.Destination.Addr = destination
	}
	answer.SelectedIp = destination.String()
	result, routeErr := router.TestPolicy(ctx, *metadata)
	if routeErr != nil {
		return nil, status.Error(codes.Unavailable, routeErr.Error())
	}
	answer.Action, answer.Rule, answer.RuleIndex, answer.OutboundPath = result.Action, result.Rule, int32(result.RuleIndex), result.OutboundPath
	return answer, nil
}
