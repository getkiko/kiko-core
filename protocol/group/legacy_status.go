package group

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/grouphealth"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// Selector and URLTest keep their upstream implementations; this file
// gives them the member status and the connection feedback the other
// policy groups have, without changing how they choose.

var (
	_ adapter.GroupStatusReporter = (*Selector)(nil)
	_ adapter.GroupFeedback       = (*Selector)(nil)
	_ adapter.ManualSelectGroup   = (*Selector)(nil)
	_ adapter.GroupStatusReporter = (*URLTest)(nil)
	_ adapter.GroupFeedback       = (*URLTest)(nil)
)

func (s *Selector) GroupStatus() adapter.GroupStatus {
	return legacyStatus(C.GroupModeManual, s.outbound, s.history, s.tags, s.selected.Load())
}

// ReportDial records the outcome for the member's state; a suspect
// member, or a down one still carrying connections, is probed, which
// updates its state and latency only: the choice stays the user's.
func (s *Selector) ReportDial(member adapter.Outbound, metadata *adapter.InboundContext, report adapter.GroupDialReport) {
	leaf := reportedLeaf(member, metadata, reportNetwork(report))
	if leaf == nil {
		return
	}
	if grouphealth.For(s.history).ObserveDial(leaf.Tag(), destinationKey(metadata), C.DefaultGroupMaxFailures, report.Err) {
		go confirmLegacy(s.ctx, s.history, leaf, true)
	}
}

func (s *URLTest) GroupStatus() adapter.GroupStatus {
	var selected adapter.Outbound
	if s.group != nil {
		selected = s.group.selectedOutboundTCP
	}
	return legacyStatus(C.GroupModeFastest, s.outbound, s.group.historyStorage(), s.tags, selected)
}

// ReportDial records the outcome for the member's state only; URLTest
// itself reacts to failures as upstream does, by the router deleting
// the member's history. A member it makes suspect is probed for its
// state, as by any group, without touching the delay history URLTest
// chooses by: the store is shared, and a member left suspect would not
// be confirmed by the other groups with it.
func (s *URLTest) ReportDial(member adapter.Outbound, metadata *adapter.InboundContext, report adapter.GroupDialReport) {
	leaf := reportedLeaf(member, metadata, reportNetwork(report))
	if leaf == nil || s.group == nil {
		return
	}
	if grouphealth.For(s.group.history).ObserveDial(leaf.Tag(), destinationKey(metadata), C.DefaultGroupMaxFailures, report.Err) {
		ctx := s.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		go confirmLegacy(ctx, s.group.history, leaf, false)
	}
}

func (g *URLTestGroup) historyStorage() *urltest.HistoryStorage {
	if g == nil {
		return nil
	}
	return g.history
}

func reportNetwork(report adapter.GroupDialReport) string {
	if report.Network == "" {
		return N.NetworkTCP
	}
	return report.Network
}

func legacyStatus(mode string, manager adapter.OutboundManager, history *urltest.HistoryStorage, tags []string, selected adapter.Outbound) adapter.GroupStatus {
	store := grouphealth.For(history)
	status := adapter.GroupStatus{Mode: mode}
	for _, tag := range tags {
		item := adapter.GroupMemberStatus{Tag: tag, SuccessRate: -1}
		if member, loaded := manager.Outbound(tag); loaded {
			realTag := RealTag(member, N.NetworkTCP)
			stats := store.Stats(realTag)
			item.State = stats.State
			if realTag == "" {
				item.State = adapter.GroupMemberDown
			}
			if stats.SuccessWeight > 0 {
				item.SuccessRate = float32(stats.Success)
			}
			if stats.LatencyWeight > 0 {
				item.Latency = uint16(math.Min(stats.Latency, math.MaxUint16))
			}
			item.Active = selected != nil && member.Tag() == selected.Tag()
		}
		status.Members = append(status.Members, item)
	}
	return status
}

var legacyProbing sync.Map

// confirmLegacy probes a suspect outbound of a Selector or URLTest with
// the default URL; storeHistory records the delay as well.
func confirmLegacy(ctx context.Context, history *urltest.HistoryStorage, member adapter.Outbound, storeHistory bool) {
	realTag := member.Tag()
	if _, loaded := legacyProbing.LoadOrStore(realTag, struct{}{}); loaded {
		return
	}
	defer legacyProbing.Delete(realTag)
	testCtx, cancel := context.WithTimeout(ctx, C.DefaultGroupProbeTimeout)
	defer cancel()
	delay, err := urltest.URLTest(testCtx, "", member)
	if ctx.Err() != nil {
		return
	}
	if history != nil && storeHistory {
		if err != nil {
			history.DeleteURLTestHistory(realTag)
		} else {
			history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
		}
	}
	ObserveProbe(history, realTag, err)
}

// ObserveProbe records a URL test of realTag for the members' states,
// notifying clients when a state changes.
func ObserveProbe(history *urltest.HistoryStorage, realTag string, err error) {
	if grouphealth.For(history).ObserveProbe(realTag, err) && history != nil {
		history.NotifyUpdated()
	}
}
