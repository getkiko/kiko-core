package trafficcontrol

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/gofrs/uuid/v5"
)

// RejectOutboundType is the outbound type of a connection a reject rule
// refused.
const RejectOutboundType = "reject"

// rejectWindow is how long the refusals of one network, source address,
// destination and rule count on one record.
const rejectWindow = time.Second

// rejectLimit bounds the refusals remembered for merging.
const rejectLimit = 4096

type rejectKey struct {
	network, source, destination, rule string
}

type rejectRecord struct {
	at       time.Time
	metadata *TrackerMetadata
}

// RejectedConnection records a connection a reject rule refused as a
// closed connection without traffic. Refusals of the same network, source
// address, destination and rule within rejectWindow count on the first
// one's record, which is sent again with the new count.
func (m *Manager) RejectedConnection(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule) {
	var rule string
	if matchedRule != nil {
		rule = matchedRule.String()
	}
	key := rejectKey{
		network:     metadata.Network,
		source:      metadata.Source.Addr.String(),
		destination: metadata.Domain + "|" + metadata.Destination.String(),
		rule:        rule,
	}
	now := time.Now()
	m.rejectAccess.Lock()
	if record, loaded := m.rejects[key]; loaded && now.Sub(record.at) < rejectWindow {
		record.metadata.Rejects.Add(1)
		m.rejectAccess.Unlock()
		m.eventSubscriber.Emit(ConnectionEvent{
			Type:     ConnectionEventClosed,
			ID:       record.metadata.ID,
			Metadata: record.metadata,
			ClosedAt: record.metadata.ClosedAt,
		})
		return
	}
	if m.rejects == nil || len(m.rejects) >= rejectLimit {
		next := make(map[rejectKey]rejectRecord)
		for k, record := range m.rejects {
			if now.Sub(record.at) < rejectWindow {
				next[k] = record
			}
		}
		m.rejects = next
	}
	id, _ := uuid.NewV4()
	rejects := new(atomic.Int64)
	rejects.Store(1)
	tracker := &TrackerMetadata{
		ID:           id,
		Metadata:     metadata,
		CreatedAt:    now,
		ClosedAt:     now,
		Upload:       new(atomic.Int64),
		Download:     new(atomic.Int64),
		Rule:         matchedRule,
		OutboundType: RejectOutboundType,
		Rejects:      rejects,
	}
	if len(m.rejects) < rejectLimit {
		m.rejects[key] = rejectRecord{at: now, metadata: tracker}
	}
	m.rejectAccess.Unlock()
	m.closedConnectionsAccess.Lock()
	if m.rejectedConnections.Len() >= rejectedConnectionsLimit {
		m.rejectedConnections.PopFront()
	}
	m.rejectedConnections.PushBack(*tracker)
	m.closedConnectionsAccess.Unlock()
	m.eventSubscriber.Emit(ConnectionEvent{
		Type:     ConnectionEventClosed,
		ID:       id,
		Metadata: tracker,
		ClosedAt: now,
	})
}
