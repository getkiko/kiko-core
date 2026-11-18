package script

import (
	"sort"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// Errors of store implementations.
var (
	ErrStoreKey           = E.New("invalid key")
	ErrStoreValueTooLarge = E.New("value larger than 1 MiB")
	ErrStoreFull          = E.New("store is full (16 MiB)")
	ErrStoreTooMany       = E.New("too many entries (4096 per namespace, 65536 in total)")
)

// MemoryStore is an in-memory Store with the documented limits. The host uses it until a
// persistent store is attached, and tests use it.
type MemoryStore struct {
	mu    sync.Mutex
	data  map[string]map[string]string
	total int
	count int
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]map[string]string{}}
}

func (s *MemoryStore) Get(namespace, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[namespace][key]
	return v, ok, nil
}

func (s *MemoryStore) Set(namespace, key, value string) error {
	if key == "" || len(key) > MaxStoreKey {
		return ErrStoreKey
	}
	if len(value) > MaxStoreValue {
		return ErrStoreValueTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.data[namespace]
	if ns == nil {
		ns = map[string]string{}
		s.data[namespace] = ns
	}
	old, existed := ns[key]
	delta := len(value) - len(old)
	if !existed {
		if len(ns) >= MaxStoreNamespaceEntries || s.count >= MaxStoreEntries {
			return ErrStoreTooMany
		}
		delta += len(key) + StoreEntryOverhead
	}
	if s.total+delta > MaxStoreTotal {
		return ErrStoreFull
	}
	ns[key] = value
	if !existed {
		s.count++
	}
	s.total += delta
	return nil
}

func (s *MemoryStore) Delete(namespace, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.data[namespace][key]; ok {
		s.total -= len(old) + len(key) + StoreEntryOverhead
		s.count--
		delete(s.data[namespace], key)
	}
	return nil
}

func (s *MemoryStore) List(namespace string) ([]StoreEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StoreEntry
	for k, v := range s.data[namespace] {
		out = append(out, StoreEntry{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return strings.Compare(out[i].Key, out[j].Key) < 0 })
	return out, nil
}

// NamespaceInfo describes a namespace of a store.
type NamespaceInfo struct {
	Name    string
	Entries int
	Bytes   int64
}

// StoreInfo is implemented by stores that report their usage; both stores of the host do.
type StoreInfo interface {
	// Persistent reports whether values survive a restart of the core.
	Persistent() bool
	// Usage is the bytes counted against MaxStoreTotal.
	Usage() int64
	// Namespaces lists the namespaces that hold entries, sorted by name.
	Namespaces() ([]NamespaceInfo, error)
}

// Persistent implements StoreInfo.
func (s *MemoryStore) Persistent() bool { return false }

// Usage implements StoreInfo.
func (s *MemoryStore) Usage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(s.total)
}

// Namespaces implements StoreInfo.
func (s *MemoryStore) Namespaces() ([]NamespaceInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []NamespaceInfo
	for name, ns := range s.data {
		if len(ns) == 0 {
			continue
		}
		info := NamespaceInfo{Name: name, Entries: len(ns)}
		for k, v := range ns {
			info.Bytes += int64(len(k) + len(v))
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
