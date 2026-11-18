package box

import (
	"bytes"
	"context"
	"reflect"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/lifecycle"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var _ adapter.LiveConfigApplier = (*Box)(nil)

var (
	// liveRetireDelay is the minimum time replaced outbounds and DNS servers
	// stay open, so that dials that already resolved them can finish.
	liveRetireDelay = 60 * time.Second
	// liveRetirePoll is the interval to recheck pins that still hold a
	// replaced outbound or DNS server.
	liveRetirePoll = 10 * time.Second
	// liveRuleCloseDelay keeps replaced rules open for in-flight matches.
	liveRuleCloseDelay = 5 * time.Second
)

// LiveSnapshot returns the configuration applied by the last successful live
// apply, or nil if the instance still runs the configuration it was created with.
func (s *Box) LiveSnapshot() []byte {
	s.liveAccess.Lock()
	defer s.liveAccess.Unlock()
	if !s.liveApplied {
		return nil
	}
	return s.liveSnapshot
}

// ApplyLiveConfig applies changes to route rules, route.final, outbounds,
// DNS servers and DNS rules without recreating the instance. Other changes
// are reported as RestartRequired. A non-nil error means nothing was applied.
func (s *Box) ApplyLiveConfig(ctx context.Context, content []byte, revision int64) (adapter.LiveConfigResult, error) {
	s.liveAccess.Lock()
	defer s.liveAccess.Unlock()
	if s.liveSnapshot == nil {
		return adapter.LiveConfigResult{}, E.New("live apply is unavailable for this instance")
	}
	if s.scope.Context().Err() != nil {
		return adapter.LiveConfigResult{}, E.New("instance is closed")
	}
	oldOptions, err := json.UnmarshalExtendedContext[option.Options](s.ctx, s.liveSnapshot)
	if err != nil {
		return adapter.LiveConfigResult{}, E.Cause(err, "decode current configuration")
	}
	newOptions, err := json.UnmarshalExtendedContext[option.Options](s.ctx, content)
	if err != nil {
		return adapter.LiveConfigResult{}, E.Cause(err, "decode configuration")
	}
	reason, err := s.liveRestartReason(oldOptions, newOptions)
	if err != nil {
		return adapter.LiveConfigResult{}, err
	}
	if reason != "" {
		return adapter.LiveConfigResult{RestartRequired: true, Reason: reason}, nil
	}
	err = s.applyLive(oldOptions, newOptions)
	if err != nil {
		return adapter.LiveConfigResult{}, err
	}
	s.liveSnapshot = append([]byte(nil), content...)
	s.liveApplied = true
	if state := service.FromContext[*lifecycle.Instance](s.ctx); state != nil {
		configRevision := apiConfigRevision(newOptions)
		if configRevision == "" {
			configRevision = strconv.FormatInt(revision, 10)
		}
		state.SetRevision(configRevision)
	}
	s.logger.Info("live apply: configuration applied")
	return adapter.LiveConfigResult{Applied: true}, nil
}

func apiConfigRevision(options option.Options) string {
	var revision string
	for _, entry := range options.Services {
		if api, isAPI := entry.Options.(*option.APIServiceOptions); isAPI {
			revision = api.ConfigRevision
			if entry.Tag == "kiko-api" {
				break
			}
		}
	}
	return revision
}

func (s *Box) liveRestartReason(oldOptions, newOptions option.Options) (string, error) {
	type section struct {
		reason   string
		oldValue any
		newValue any
	}
	oldRoute := common.PtrValueOrDefault(oldOptions.Route)
	newRoute := common.PtrValueOrDefault(newOptions.Route)
	oldDNS := common.PtrValueOrDefault(oldOptions.DNS)
	newDNS := common.PtrValueOrDefault(newOptions.DNS)
	sections := []section{
		{"inbounds or TUN changed, restart required", oldOptions.Inbounds, newOptions.Inbounds},
		{"endpoints changed, restart required", oldOptions.Endpoints, newOptions.Endpoints},
		{"services changed, restart required", liveServices(oldOptions.Services), liveServices(newOptions.Services)},
		{"HTTP clients changed, restart required", oldOptions.HTTPClients, newOptions.HTTPClients},
		{"experimental options (cache, API and others) changed, restart required", oldOptions.Experimental, newOptions.Experimental},
		{"log options changed, restart required", oldOptions.Log, newOptions.Log},
		{"NTP options changed, restart required", oldOptions.NTP, newOptions.NTP},
		{"certificate options changed, restart required", oldOptions.Certificate, newOptions.Certificate},
		{"certificate providers changed, restart required", oldOptions.CertificateProviders, newOptions.CertificateProviders},
		{"network namespaces changed, restart required", oldOptions.NetworkNamespaces, newOptions.NetworkNamespaces},
		{"rule sets changed, restart required", liveRuleSets(oldRoute.RuleSet), liveRuleSets(newRoute.RuleSet)},
		{"DHCP lease files changed, restart required", oldRoute.DHCPLeaseFiles, newRoute.DHCPLeaseFiles},
		{"global route options changed, restart required", liveRouteRest(oldRoute), liveRouteRest(newRoute)},
		{"global DNS options changed, restart required", liveDNSRest(oldDNS), liveDNSRest(newDNS)},
		{"FakeIP servers changed, restart required", fakeIPServers(oldDNS), fakeIPServers(newDNS)},
		{"default DNS server type changed, restart required", defaultDNSServerType(oldDNS), defaultDNSServerType(newDNS)},
	}
	for _, it := range sections {
		equal, err := s.optionsEqual(it.oldValue, it.newValue)
		if err != nil {
			return "", err
		}
		if !equal {
			return it.reason, nil
		}
	}
	if route.NeedFindProcess(newRoute, newDNS) && !s.router.NeedFindProcess() {
		return "new rules need process matching, restart required", nil
	}
	if route.NeedFindNeighbor(newRoute, newDNS) && !s.router.NeedFindNeighbor() {
		return "new rules need neighbor device resolution, restart required", nil
	}
	return "", nil
}

func (s *Box) optionsEqual(oldValue, newValue any) (bool, error) {
	oldContent, err := json.MarshalContext(s.ctx, addressableOptions(oldValue))
	if err != nil {
		return false, err
	}
	newContent, err := json.MarshalContext(s.ctx, addressableOptions(newValue))
	if err != nil {
		return false, err
	}
	return bytes.Equal(oldContent, newContent), nil
}

// addressableOptions converts slices to element pointers, since typed option
// wrappers implement context marshaling on pointer receivers.
func addressableOptions(value any) any {
	reflectValue := reflect.ValueOf(value)
	if reflectValue.Kind() != reflect.Slice {
		return value
	}
	elements := make([]any, reflectValue.Len())
	for i := range elements {
		elements[i] = reflectValue.Index(i).Addr().Interface()
	}
	return elements
}

func liveServices(services []option.Service) []option.Service {
	services = append([]option.Service(nil), services...)
	for i, entry := range services {
		if api, isAPI := entry.Options.(*option.APIServiceOptions); isAPI && api.ConfigRevision != "" {
			apiCopy := *api
			apiCopy.ConfigRevision = ""
			services[i].Options = &apiCopy
		}
	}
	return services
}

// liveRuleSets are rule sets without the rules of the inline ones, which a
// live apply reloads in place (reloadInlineRuleSets).
func liveRuleSets(ruleSets []option.RuleSet) []option.RuleSet {
	ruleSets = append([]option.RuleSet(nil), ruleSets...)
	for i := range ruleSets {
		if ruleSets[i].Type == C.RuleSetTypeInline {
			ruleSets[i].InlineOptions = option.PlainRuleSet{}
		}
	}
	return ruleSets
}

// reloadInlineRuleSets gives the running inline rule sets the rules of
// newSets that changed. liveRestartReason has made sure both lists hold
// the same rule sets in the same order.
func (s *Box) reloadInlineRuleSets(oldSets, newSets []option.RuleSet) error {
	for i, ruleSet := range newSets {
		if ruleSet.Type != C.RuleSetTypeInline || i >= len(oldSets) {
			continue
		}
		equal, err := s.optionsEqual(oldSets[i].InlineOptions.Rules, ruleSet.InlineOptions.Rules)
		if err != nil {
			return err
		}
		if equal {
			continue
		}
		for _, tag := range ruleSet.Tag {
			current, loaded := s.router.RuleSet(tag)
			reloader, canReload := current.(interface {
				ReloadInline(rules []option.HeadlessRule) error
			})
			if !loaded || !canReload {
				return E.New("rule-set ", tag, " cannot be reloaded")
			}
			err = reloader.ReloadInline(ruleSet.InlineOptions.Rules)
			if err != nil {
				return E.Cause(err, "reload rule-set ", tag)
			}
			s.logger.Info("live apply: reloaded rule-set ", tag)
		}
	}
	return nil
}

func liveRouteRest(options option.RouteOptions) *option.RouteOptions {
	options.Rules = nil
	options.RuleSet = nil
	options.Final = ""
	options.FindProcess = false
	options.FindNeighbor = false
	options.DHCPLeaseFiles = nil
	return &options
}

func liveDNSRest(options option.DNSOptions) *option.DNSOptions {
	options.Servers = nil
	options.Rules = nil
	options.Final = ""
	return &options
}

func fakeIPServers(options option.DNSOptions) []option.DNSServerOptions {
	return common.Filter(options.Servers, func(it option.DNSServerOptions) bool {
		return it.Type == C.DNSTypeFakeIP
	})
}

func defaultDNSServerType(options option.DNSOptions) string {
	for i, server := range options.Servers {
		if options.Final == "" || dnsServerTag(i, server) == options.Final {
			return server.Type
		}
	}
	return C.DNSTypeLocal
}

func outboundTag(index int, options option.Outbound) string {
	if options.Tag != "" {
		return options.Tag
	}
	return F.ToString(index)
}

func dnsServerTag(index int, options option.DNSServerOptions) string {
	if options.Tag != "" {
		return options.Tag
	}
	return F.ToString(index)
}

func (s *Box) applyLive(oldOptions, newOptions option.Options) error {
	newRoute := common.PtrValueOrDefault(newOptions.Route)
	newDNS := common.PtrValueOrDefault(newOptions.DNS)

	oldOutbounds := make(map[string][]byte)
	for i, outboundOptions := range oldOptions.Outbounds {
		content, err := json.MarshalContext(s.ctx, &outboundOptions)
		if err != nil {
			return err
		}
		oldOutbounds[outboundTag(i, outboundOptions)] = content
	}
	outboundOrder := make([]string, 0, len(newOptions.Outbounds))
	newOutbounds := make(map[string]option.Outbound)
	changedOutbounds := make(map[string]bool)
	for i, outboundOptions := range newOptions.Outbounds {
		tag := outboundTag(i, outboundOptions)
		if _, loaded := newOutbounds[tag]; loaded {
			return E.New("duplicate outbound tag: ", tag)
		}
		outboundOrder = append(outboundOrder, tag)
		newOutbounds[tag] = outboundOptions
		content, err := json.MarshalContext(s.ctx, &outboundOptions)
		if err != nil {
			return err
		}
		if !bytes.Equal(oldOutbounds[tag], content) {
			changedOutbounds[tag] = true
		}
	}
	removedOutbounds := make(map[string]bool)
	for tag := range oldOutbounds {
		if _, loaded := newOutbounds[tag]; !loaded {
			removedOutbounds[tag] = true
		}
	}
	// Groups and detour users cache resolved outbounds, so rebuild dependents transitively.
	for {
		var added bool
		for _, tag := range outboundOrder {
			if changedOutbounds[tag] {
				continue
			}
			current, loaded := s.outbound.Outbound(tag)
			if !loaded {
				changedOutbounds[tag] = true
				added = true
				continue
			}
			if common.Any(current.Dependencies(), func(it string) bool {
				return changedOutbounds[it] || removedOutbounds[it]
			}) {
				changedOutbounds[tag] = true
				added = true
			}
		}
		if !added {
			break
		}
	}

	oldServers := make(map[string][]byte)
	for i, serverOptions := range common.PtrValueOrDefault(oldOptions.DNS).Servers {
		content, err := json.MarshalContext(s.ctx, &serverOptions)
		if err != nil {
			return err
		}
		oldServers[dnsServerTag(i, serverOptions)] = content
	}
	serverOrder := make([]string, 0, len(newDNS.Servers))
	newServers := make(map[string]option.DNSServerOptions)
	changedServers := make(map[string]bool)
	for i, serverOptions := range newDNS.Servers {
		tag := dnsServerTag(i, serverOptions)
		if _, loaded := newServers[tag]; loaded {
			return E.New("duplicate DNS server tag: ", tag)
		}
		serverOrder = append(serverOrder, tag)
		newServers[tag] = serverOptions
		content, err := json.MarshalContext(s.ctx, &serverOptions)
		if err != nil {
			return err
		}
		if !bytes.Equal(oldServers[tag], content) {
			changedServers[tag] = true
		}
	}
	removedServers := make(map[string]bool)
	for tag := range oldServers {
		if _, loaded := newServers[tag]; !loaded {
			removedServers[tag] = true
		}
	}
	for {
		var added bool
		for _, tag := range serverOrder {
			if changedServers[tag] {
				continue
			}
			current, loaded := s.dnsTransport.Transport(tag)
			if !loaded {
				changedServers[tag] = true
				added = true
				continue
			}
			if common.Any(current.Dependencies(), func(it string) bool {
				return changedServers[it] || removedServers[it]
			}) {
				changedServers[tag] = true
				added = true
			}
		}
		if !added {
			break
		}
	}

	outboundStaging := s.outbound.NewStaging(newRoute.Final, outboundOrder)
	transportStaging := s.dnsTransport.NewStaging(newDNS.Final, serverOrder)
	stagingCtx := service.ExtendContext(s.ctx)
	stagingCtx = service.ContextWith[adapter.OutboundManager](stagingCtx, outboundStaging.View())
	stagingCtx = service.ContextWith[adapter.DNSTransportManager](stagingCtx, transportStaging.View())
	var (
		routeRules []adapter.Rule
		dnsRules   *dns.PreparedRules
		committed  bool
	)
	defer func() {
		if committed {
			return
		}
		for _, rule := range routeRules {
			_ = rule.Close()
		}
		dnsRules.Close()
		outboundStaging.Discard()
		transportStaging.Discard()
	}()
	for tag := range removedServers {
		transportStaging.Remove(tag)
	}
	for _, tag := range serverOrder {
		if !changedServers[tag] {
			continue
		}
		serverOptions := newServers[tag]
		err := transportStaging.Create(
			stagingCtx,
			s.logFactory.NewLogger(F.ToString("dns/", serverOptions.Type, "[", tag, "]")),
			tag,
			serverOptions.Type,
			serverOptions.Options,
		)
		if err != nil {
			return E.Cause(err, "initialize DNS server[", tag, "]")
		}
	}
	for tag := range removedOutbounds {
		outboundStaging.Remove(tag)
	}
	for _, tag := range outboundOrder {
		if !changedOutbounds[tag] {
			continue
		}
		outboundOptions := newOutbounds[tag]
		outboundCtx := adapter.WithContext(stagingCtx, &adapter.InboundContext{
			Outbound: tag,
		})
		err := outboundStaging.Create(
			outboundCtx,
			s.router,
			s.logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
			tag,
			outboundOptions.Type,
			outboundOptions.Options,
		)
		if err != nil {
			return E.Cause(err, "initialize outbound[", tag, "]")
		}
	}
	err := outboundStaging.Start()
	if err != nil {
		return E.Cause(err, "start outbounds")
	}
	err = transportStaging.Start()
	if err != nil {
		return E.Cause(err, "start DNS servers")
	}
	for _, outbound := range outboundStaging.Staged() {
		if outbound.Type() != C.TypeSelector {
			continue
		}
		current, loaded := s.outbound.Outbound(outbound.Tag())
		if !loaded || current.Type() != C.TypeSelector {
			continue
		}
		currentGroup, isGroup := current.(adapter.OutboundGroup)
		selector, isSelector := outbound.(interface{ SelectOutbound(tag string) bool })
		if !isGroup || !isSelector {
			continue
		}
		if selected := currentGroup.Selected(N.NetworkTCP); selected != nil {
			selector.SelectOutbound(selected.Tag())
		}
	}
	routeRules, err = s.router.BuildRules(stagingCtx, newRoute.Rules)
	if err != nil {
		return err
	}
	dnsRules, err = s.dnsRouter.BuildRules(stagingCtx, transportStaging.View(), newDNS.Rules)
	if err != nil {
		return err
	}
	err = s.reloadInlineRuleSets(common.PtrValueOrDefault(oldOptions.Route).RuleSet, newRoute.RuleSet)
	if err != nil {
		return err
	}
	oldDNSRules, err := s.dnsRouter.SwapRules(dnsRules)
	if err != nil {
		return err
	}
	committed = true
	retiredOutbounds := outboundStaging.Commit()
	retiredTransports := transportStaging.Commit()
	oldRouteRules := s.router.SwapRules(routeRules)
	s.dnsRouter.ClearCache()
	s.referenceManager.Reload(newOptions)
	time.AfterFunc(liveRuleCloseDelay, func() {
		for _, rule := range oldRouteRules {
			_ = rule.Close()
		}
		for _, rule := range oldDNSRules {
			_ = rule.Close()
		}
	})
	if len(retiredOutbounds) > 0 {
		s.logger.Info("live apply: replaced ", len(retiredOutbounds), " outbound(s)")
		s.retireLater(s.outbound, common.Map(retiredOutbounds, func(it adapter.Outbound) any { return it }), func() {
			for _, outbound := range retiredOutbounds {
				err := s.outbound.CloseRetired(outbound)
				if err != nil {
					s.logger.Warn(E.Cause(err, "close retired outbound/", outbound.Type(), "[", outbound.Tag(), "]"))
				}
			}
		})
	}
	if len(retiredTransports) > 0 {
		s.logger.Info("live apply: replaced ", len(retiredTransports), " DNS server(s)")
		s.retireLater(s.dnsTransport, common.Map(retiredTransports, func(it adapter.DNSTransport) any { return it }), func() {
			for _, transport := range retiredTransports {
				err := s.dnsTransport.CloseRetired(transport)
				if err != nil {
					s.logger.Warn(E.Cause(err, "close retired dns/", transport.Type(), "[", transport.Tag(), "]"))
				}
			}
		})
	}
	return nil
}

// retireLater closes replaced objects once the grace period has passed and
// none of objects is pinned by a connection, flow or exchange anymore.
func (s *Box) retireLater(pinner adapter.ObjectPinner, objects []any, closeFunc func()) {
	done := s.scope.Context().Done()
	s.liveRetiring.Add(1)
	go func() {
		defer s.liveRetiring.Add(-1)
		timer := time.NewTimer(liveRetireDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-done:
			return
		}
		for pinner.Pinned(objects...) > 0 {
			timer.Reset(liveRetirePoll)
			select {
			case <-timer.C:
			case <-done:
				return
			}
		}
		closeFunc()
	}()
}
