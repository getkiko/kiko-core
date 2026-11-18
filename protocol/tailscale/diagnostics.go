//go:build with_gvisor

package tailscale

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/tailscale/net/netcheck"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/types/opt"
	"github.com/sagernet/tailscale/wgengine/magicsock"
)

var _ adapter.TailscaleDiagnosticsProvider = (*Endpoint)(nil)

const (
	// diagnosticsRefreshWait bounds how long a refresh waits for a new
	// network check.
	diagnosticsRefreshWait = 8 * time.Second
	// diagnosticsChangeLimit is how many path changes a peer reports.
	diagnosticsChangeLimit = 20
)

func (t *Endpoint) magicConn() (conn *magicsock.Conn, err error) {
	defer func() {
		if recover() != nil {
			conn, err = nil, E.New("tailscale is not started")
		}
	}()
	conn = t.server.ExportLocalBackend().MagicConn()
	if conn == nil {
		return nil, E.New("tailscale is not started")
	}
	return conn, nil
}

// TailscaleDiagnostics reports the latest network check, after running a
// new one when refresh is set, and each peer's candidates, handshake and
// path changes.
func (t *Endpoint) TailscaleDiagnostics(ctx context.Context, refresh bool) (*adapter.TailscaleDiagnostics, error) {
	conn, err := t.magicConn()
	if err != nil {
		return nil, err
	}
	if refresh {
		waitNetcheck(ctx, conn)
	}
	localBackend := t.server.ExportLocalBackend()
	networkMap := localBackend.NetMapWithPeers()
	result := &adapter.TailscaleDiagnostics{
		Netcheck: convertNetcheck(conn.GetLastNetcheckReport(ctx), conn.GetDERPRegionLatency(), networkMap),
	}
	if t.udpPath != nil {
		result.Netcheck.STUNPath = t.udpPath.stunPath()
	}
	status := localBackend.Status()
	if networkMap == nil {
		return result, nil
	}
	for _, node := range networkMap.Peers {
		if !node.Valid() {
			continue
		}
		peer := &adapter.TailscalePeerDiagnostics{StableID: string(node.StableID())}
		endpoints := node.Endpoints()
		for index := range endpoints.Len() {
			address := endpoints.At(index)
			candidate := &adapter.TailscalePeerEndpoint{Address: address.String()}
			if t.udpPath != nil {
				candidate.Path = t.udpPath.candidatePath(address)
			}
			peer.Endpoints = append(peer.Endpoints, candidate)
		}
		if status != nil {
			if ps := status.Peer[node.Key()]; ps != nil {
				if !ps.LastHandshake.IsZero() {
					peer.LastHandshake = ps.LastHandshake.UnixMilli()
				}
				peer.PeerRelay = ps.PeerRelay
			}
		}
		if changes, err := conn.GetEndpointChanges(node); err == nil {
			peer.Changes = convertPathChanges(changes, derpRegionMap(networkMap))
		}
		result.Peers = append(result.Peers, peer)
	}
	return result, nil
}

// waitNetcheck starts a network check and waits for its report.
func waitNetcheck(ctx context.Context, conn *magicsock.Conn) {
	var since time.Time
	if report := conn.GetLastNetcheckReport(ctx); report != nil {
		since = report.Now
	}
	conn.ReSTUN("diagnostics")
	ctx, cancel := context.WithTimeout(ctx, diagnosticsRefreshWait)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if report := conn.GetLastNetcheckReport(ctx); report != nil && report.Now.After(since) {
				return
			}
		}
	}
}

func optBoolString(value opt.Bool) string {
	if v, ok := value.Get(); ok {
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

func addrPortString(address netip.AddrPort) string {
	if !address.IsValid() {
		return ""
	}
	return address.String()
}

func derpRegionMap(networkMap *netmap.NetworkMap) map[int]*tailcfg.DERPRegion {
	if networkMap == nil || networkMap.DERPMap == nil {
		return nil
	}
	return networkMap.DERPMap.Regions
}

// convertNetcheck converts the latest report. An incremental check probes
// only the fastest few regions, so the others take their best recent
// latency.
func convertNetcheck(report *netcheck.Report, recent map[int]time.Duration, networkMap *netmap.NetworkMap) *adapter.TailscaleNetcheck {
	result := &adapter.TailscaleNetcheck{}
	if networkMap != nil && networkMap.SelfNode.Valid() {
		endpoints := networkMap.SelfNode.Endpoints()
		for index := range endpoints.Len() {
			result.SelfEndpoints = append(result.SelfEndpoints, endpoints.At(index).String())
		}
	}
	if report == nil {
		return result
	}
	result.CheckedAt = report.Now.UnixMilli()
	result.UDP, result.IPv4, result.IPv6 = report.UDP, report.IPv4, report.IPv6
	result.IPv4CanSend, result.IPv6CanSend, result.OSHasIPv6 = report.IPv4CanSend, report.IPv6CanSend, report.OSHasIPv6
	result.GlobalV4, result.GlobalV6 = addrPortString(report.GlobalV4), addrPortString(report.GlobalV6)
	result.MappingVariesByDestIP = optBoolString(report.MappingVariesByDestIP)
	result.UPnP, result.PMP, result.PCP = optBoolString(report.UPnP), optBoolString(report.PMP), optBoolString(report.PCP)
	result.CaptivePortal = optBoolString(report.CaptivePortal)
	result.PreferredDERP = int32(report.PreferredDERP)
	latency := make(map[int]time.Duration, len(recent))
	for id, d := range recent {
		latency[id] = d
	}
	for id, d := range report.RegionLatency {
		latency[id] = d
	}
	result.Regions = derpRegions(derpRegionMap(networkMap), latency)
	return result
}

// derpRegions lists the DERP map's regions with their latencies, the
// answering ones fastest first, then the silent ones by name.
func derpRegions(regions map[int]*tailcfg.DERPRegion, latency map[int]time.Duration) []*adapter.TailscaleDERPRegion {
	var out []*adapter.TailscaleDERPRegion
	for id, region := range regions {
		if region == nil {
			continue
		}
		item := &adapter.TailscaleDERPRegion{ID: int32(id), Code: region.RegionCode, Name: region.RegionName}
		if d, ok := latency[id]; ok && d > 0 {
			item.LatencyMs = float64(d) / float64(time.Millisecond)
		}
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b *adapter.TailscaleDERPRegion) int {
		switch {
		case a.LatencyMs > 0 && b.LatencyMs > 0 && a.LatencyMs != b.LatencyMs:
			if a.LatencyMs < b.LatencyMs {
				return -1
			}
			return 1
		case (a.LatencyMs > 0) != (b.LatencyMs > 0):
			if a.LatencyMs > 0 {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name+a.Code, b.Name+b.Code)
	})
	return out
}

// convertPathChanges keeps a peer's path changes newest first, without the
// latency updates every pong records.
func convertPathChanges(changes []magicsock.EndpointChange, regions map[int]*tailcfg.DERPRegion) []*adapter.TailscalePathChange {
	var out []*adapter.TailscalePathChange
	for i := len(changes) - 1; i >= 0 && len(out) < diagnosticsChangeLimit; i-- {
		change := changes[i]
		if change.What == "handlePongConnLocked-bestAddr-latency" {
			continue
		}
		out = append(out, &adapter.TailscalePathChange{
			At: change.When.UnixMilli(), What: change.What,
			From: changeValue(change.From, regions), To: changeValue(change.To, regions),
		})
	}
	return out
}

// changeValue formats a path change value; a DERP address, the magic IP
// with the region ID as its port, is its region's code.
func changeValue(value any, regions map[int]*tailcfg.DERPRegion) string {
	if value == nil {
		return ""
	}
	if address, ok := value.(netip.AddrPort); ok && !address.IsValid() {
		return ""
	} else if ok && address.Addr() == tailcfg.DerpMagicIPAddr {
		if region := regions[int(address.Port())]; region != nil && region.RegionCode != "" {
			return region.RegionCode
		}
		return fmt.Sprint("DERP ", address.Port())
	}
	text := fmt.Sprint(value)
	if text == "<nil>" || text == "[]" || text == "{}" {
		return ""
	}
	return text
}
