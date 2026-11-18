package script

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type captureLogger struct {
	mu      sync.Mutex
	entries []LogEntry
}

func (c *captureLogger) Log(e LogEntry) {
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
}

func TestHubRings(t *testing.T) {
	inner := &captureLogger{}
	hub := NewHub(inner)
	for i := range HubLogRing*2 + 10 {
		hub.Log(LogEntry{Script: "s", LogLine: LogLine{Level: "log", Message: strconv.Itoa(i)}})
	}
	require.Len(t, inner.entries, HubLogRing*2+10, "the inner logger sees every line")
	logs := hub.LogsAfter(0, 0)
	require.Len(t, logs, HubLogRing)
	require.Equal(t, strconv.Itoa(HubLogRing+10), logs[0].Message)
	require.EqualValues(t, HubLogRing*2+10, logs[len(logs)-1].Seq)
	require.False(t, logs[0].Time.IsZero())
	tail := hub.LogsAfter(logs[len(logs)-1].Seq-2, 0)
	require.Len(t, tail, 2)
	require.Len(t, hub.LogsAfter(0, 5), 5)
	require.Empty(t, hub.LogsAfter(logs[len(logs)-1].Seq, 0))

	for i := range HubNotificationRing*3 + 1 {
		hub.Notify(Notification{Script: "s", Title: strconv.Itoa(i)})
	}
	notes := hub.NotificationsAfter(0, 0)
	require.Len(t, notes, HubNotificationRing)
	require.Equal(t, strconv.Itoa(HubNotificationRing*2+1), notes[0].Title)
}

func TestHubWakesSubscribers(t *testing.T) {
	hub := NewHub(nil)
	wake, cancel := hub.Subscribe()
	select {
	case <-wake:
		t.Fatal("woke without news")
	default:
	}
	hub.Log(LogEntry{})
	hub.Notify(Notification{})
	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("not woken")
	}
	cancel()
	hub.Log(LogEntry{})
	select {
	case <-wake:
		t.Fatal("woken after cancel")
	default:
	}
}

func TestHubConcurrent(t *testing.T) {
	hub := NewHub(nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 500 {
				hub.Log(LogEntry{})
				hub.Notify(Notification{})
			}
		}()
		go func() {
			defer wg.Done()
			wake, cancel := hub.Subscribe()
			defer cancel()
			var after uint64
			for range 100 {
				for _, rec := range hub.LogsAfter(after, 50) {
					after = rec.Seq
				}
				select {
				case <-wake:
				case <-time.After(time.Millisecond):
				}
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 4000, hub.LogsAfter(0, 0)[HubLogRing-1].Seq)
}

func TestMemoryStoreEntryCaps(t *testing.T) {
	s := NewMemoryStore()
	for i := range MaxStoreNamespaceEntries {
		require.NoError(t, s.Set("a", strconv.Itoa(i), ""))
	}
	require.ErrorIs(t, s.Set("a", "extra", ""), ErrStoreTooMany)
	require.NoError(t, s.Set("a", "0", "overwrite"), "an existing key is not a new entry")
	require.EqualValues(t, MaxStoreNamespaceEntries*StoreEntryOverhead+sumKeys(MaxStoreNamespaceEntries)+len("overwrite"), s.Usage())
	require.NoError(t, s.Delete("a", "1"))
	require.NoError(t, s.Set("a", "extra", ""))

	// The whole store is capped too, and the overhead counts against the byte total.
	s = NewMemoryStore()
	for ns := range MaxStoreEntries / MaxStoreNamespaceEntries {
		for i := range MaxStoreNamespaceEntries {
			require.NoError(t, s.Set("n"+strconv.Itoa(ns), strconv.Itoa(i), ""))
		}
	}
	require.ErrorIs(t, s.Set("other", "k", ""), ErrStoreTooMany)

	s = NewMemoryStore()
	for i := 0; ; i++ {
		err := s.Set("x"+strconv.Itoa(i/1000), strconv.Itoa(i), "")
		if err != nil {
			require.ErrorIs(t, err, ErrStoreTooMany)
			break
		}
	}
}

func sumKeys(n int) int {
	total := 0
	for i := range n {
		total += len(strconv.Itoa(i))
	}
	return total
}
