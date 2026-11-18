package script

import (
	"sync"
	"time"
)

// Ring sizes of the Hub.
const (
	HubLogRing          = 1000
	HubNotificationRing = 200
)

// LogRecord is a console line kept by the Hub, numbered in arrival order.
type LogRecord struct {
	Seq uint64
	LogEntry
}

// NotificationRecord is a notification kept by the Hub, numbered in arrival order.
type NotificationRecord struct {
	Seq uint64
	Notification
}

// Hub is the Logger and Notifier of a running engine. It forwards console lines to an inner
// Logger, keeps the most recent lines and notifications in rings and wakes subscribers. It
// never blocks the script that posts.
type Hub struct {
	inner Logger

	mu      sync.Mutex
	logs    []LogRecord
	logSeq  uint64
	notes   []NotificationRecord
	noteSeq uint64
	waiters map[chan struct{}]struct{}
}

// NewHub creates a Hub; inner (may be nil) also receives every console line.
func NewHub(inner Logger) *Hub {
	return &Hub{inner: inner, waiters: map[chan struct{}]struct{}{}}
}

// Log implements Logger.
func (h *Hub) Log(entry LogEntry) {
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	h.mu.Lock()
	h.logSeq++
	rec := LogRecord{Seq: h.logSeq, LogEntry: entry}
	h.logs = append(h.logs, rec)
	if len(h.logs) >= 2*HubLogRing {
		n := copy(h.logs, h.logs[len(h.logs)-HubLogRing:])
		clear(h.logs[n:])
		h.logs = h.logs[:n]
	}
	h.wakeLocked()
	h.mu.Unlock()
	if h.inner != nil {
		h.inner.Log(entry)
	}
}

// Notify implements Notifier.
func (h *Hub) Notify(n Notification) {
	if n.Time.IsZero() {
		n.Time = time.Now()
	}
	h.mu.Lock()
	h.noteSeq++
	rec := NotificationRecord{Seq: h.noteSeq, Notification: n}
	h.notes = append(h.notes, rec)
	if len(h.notes) >= 2*HubNotificationRing {
		n := copy(h.notes, h.notes[len(h.notes)-HubNotificationRing:])
		clear(h.notes[n:])
		h.notes = h.notes[:n]
	}
	h.wakeLocked()
	h.mu.Unlock()
}

func (h *Hub) wakeLocked() {
	for ch := range h.waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Subscribe returns a channel that receives a signal after new lines or notifications
// arrive (coalesced) and a function that ends the subscription.
func (h *Hub) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.waiters[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.waiters, ch)
		h.mu.Unlock()
	}
}

// LogsAfter returns the lines with a sequence number above after (all kept lines for 0),
// oldest first, at most limit of them (0 for no limit). When a gap exists because the ring
// dropped lines, the lines start at the oldest kept one.
func (h *Hub) LogsAfter(after uint64, limit int) []LogRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []LogRecord
	recs := h.logs
	if len(recs) > HubLogRing {
		recs = recs[len(recs)-HubLogRing:]
	}
	for _, rec := range recs {
		if rec.Seq > after {
			out = append(out, rec)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// NotificationsAfter is LogsAfter for notifications.
func (h *Hub) NotificationsAfter(after uint64, limit int) []NotificationRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []NotificationRecord
	recs := h.notes
	if len(recs) > HubNotificationRing {
		recs = recs[len(recs)-HubNotificationRing:]
	}
	for _, rec := range recs {
		if rec.Seq > after {
			out = append(out, rec)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// LogSeq is the sequence number of the newest console line, 0 when there is none.
func (h *Hub) LogSeq() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logSeq
}

// NotificationSeq is the sequence number of the newest notification, 0 when there is none.
func (h *Hub) NotificationSeq() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.noteSeq
}
