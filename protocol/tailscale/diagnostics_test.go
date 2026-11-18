//go:build with_gvisor

package tailscale

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/tailscale/net/netcheck"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/types/opt"
	"github.com/sagernet/tailscale/wgengine/magicsock"
)

func TestConvertNetcheck(t *testing.T) {
	now := time.UnixMilli(1_790_000_000_000)
	report := &netcheck.Report{
		Now: now, UDP: true, IPv4: true, IPv4CanSend: true,
		GlobalV4:              netip.MustParseAddrPort("203.0.113.7:41641"),
		MappingVariesByDestIP: opt.NewBool(true), UPnP: opt.NewBool(false),
		PreferredDERP: 2,
		RegionLatency: map[int]time.Duration{1: 80 * time.Millisecond, 2: 30 * time.Millisecond},
	}
	networkMap := &netmap.NetworkMap{DERPMap: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "nyc", RegionName: "New York City"},
		2: {RegionID: 2, RegionCode: "tok", RegionName: "Tokyo"},
		3: {RegionID: 3, RegionCode: "fra", RegionName: "Frankfurt"},
		4: nil,
	}}}
	// Region 3 is outside the incremental check: its recent latency stands
	// in; the report's own latencies win.
	recent := map[int]time.Duration{2: 50 * time.Millisecond, 3: 120 * time.Millisecond}
	got := convertNetcheck(report, recent, networkMap)
	if got.CheckedAt != now.UnixMilli() || !got.UDP || !got.IPv4 || got.IPv6 || got.GlobalV4 != "203.0.113.7:41641" || got.GlobalV6 != "" {
		t.Fatalf("report %+v", got)
	}
	if got.MappingVariesByDestIP != "true" || got.UPnP != "false" || got.PMP != "" || got.PreferredDERP != 2 {
		t.Errorf("tri-states %+v", got)
	}
	var codes []string
	for _, region := range got.Regions {
		codes = append(codes, region.Code)
	}
	if len(codes) != 3 || codes[0] != "tok" || codes[1] != "nyc" || codes[2] != "fra" {
		t.Errorf("regions by latency, then silent: %v", codes)
	}
	if got.Regions[0].LatencyMs != 30 || got.Regions[2].LatencyMs != 120 {
		t.Errorf("latencies %+v %+v", got.Regions[0], got.Regions[2])
	}
	if silent := convertNetcheck(report, nil, networkMap); silent.Regions[2].LatencyMs != 0 {
		t.Errorf("silent region %+v", silent.Regions[2])
	}
	if empty := convertNetcheck(nil, recent, nil); empty.CheckedAt != 0 || empty.Regions != nil {
		t.Errorf("no report %+v", empty)
	}
}

func TestConvertPathChanges(t *testing.T) {
	at := func(s int) time.Time { return time.Unix(int64(s), 0) }
	var changes []magicsock.EndpointChange
	changes = append(changes,
		magicsock.EndpointChange{When: at(1), What: "updateFromNode-new-Endpoints", To: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:41641")}},
		magicsock.EndpointChange{When: at(2), What: "handlePongConnLocked-bestAddr-update", From: nil, To: "203.0.113.7:41641"},
		magicsock.EndpointChange{When: at(3), What: "handlePongConnLocked-bestAddr-latency", To: "x"},
	)
	for i := range 30 {
		changes = append(changes, magicsock.EndpointChange{When: at(10 + i), What: "handleCallMeMaybe-new-endpoints", To: []netip.AddrPort{}})
	}
	got := convertPathChanges(changes, nil)
	if len(got) != diagnosticsChangeLimit || got[0].At != at(39).UnixMilli() || got[0].To != "" {
		t.Fatalf("newest first, capped: %d %+v", len(got), got[0])
	}
	short := convertPathChanges(changes[:3], nil)
	if len(short) != 2 || short[0].What != "handlePongConnLocked-bestAddr-update" || short[0].From != "" || short[0].To != "203.0.113.7:41641" {
		t.Errorf("latency updates dropped: %+v", short)
	}
	if short[1].To != "[203.0.113.7:41641]" {
		t.Errorf("endpoints %q", short[1].To)
	}
}

func TestChangeValueDERP(t *testing.T) {
	regions := map[int]*tailcfg.DERPRegion{2: {RegionID: 2, RegionCode: "tok"}}
	for value, want := range map[any]string{
		netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 2): "tok",
		netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 9): "DERP 9",
		netip.AddrPort{}: "",
		netip.MustParseAddrPort("203.0.113.7:41641"): "203.0.113.7:41641",
	} {
		if got := changeValue(value, regions); got != want {
			t.Errorf("changeValue(%v) = %q, want %q", value, got, want)
		}
	}
}
