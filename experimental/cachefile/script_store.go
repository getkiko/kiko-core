package cachefile

import (
	"sync"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/script"
	E "github.com/sagernet/sing/common/exceptions"
)

// ScriptStore returns the $persistentStore backing of scripts: the bucket "script_store"
// holds one sub-bucket per namespace (a script tag or "@shared") with the keys and values.
// The values are mirrored in memory after the first access, so reads never touch the disk;
// writes go through to the database before they return. The limits (key 256 B, value 1 MiB,
// total 16 MiB) are those of script.MemoryStore, which the mirror reuses.
func (c *CacheFile) ScriptStore() script.Store {
	c.scriptStoreOnce.Do(func() {
		c.scriptStore = &scriptStore{cache: c, mirror: script.NewMemoryStore()}
	})
	return c.scriptStore
}

type scriptStore struct {
	cache *CacheFile

	mu     sync.Mutex
	loaded bool
	mirror *script.MemoryStore
}

var (
	_ script.Store     = (*scriptStore)(nil)
	_ script.StoreInfo = (*scriptStore)(nil)
)

// load reads the database into the mirror once. It fails while the database is not open.
func (s *scriptStore) load() error {
	if s.loaded {
		return nil
	}
	if s.cache.database() == nil {
		return E.New("cache file is not open")
	}
	err := s.cache.view(func(tx *bbolt.Tx) error {
		root := s.cache.bucket(tx, bucketScriptStore)
		if root == nil {
			return nil
		}
		return root.ForEachBucket(func(name []byte) error {
			ns := root.Bucket(name)
			if ns == nil {
				return nil
			}
			return ns.ForEach(func(k, v []byte) error {
				// Entries over a limit (a store written by something else) are dropped from
				// the mirror rather than failing the whole store.
				_ = s.mirror.Set(string(name), string(k), string(v))
				return nil
			})
		})
	})
	if err != nil {
		return err
	}
	s.loaded = true
	return nil
}

func (s *scriptStore) Get(namespace, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", false, err
	}
	return s.mirror.Get(namespace, key)
}

func (s *scriptStore) Set(namespace, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	if namespace == "" {
		return E.New("invalid namespace")
	}
	old, existed, _ := s.mirror.Get(namespace, key)
	if err := s.mirror.Set(namespace, key, value); err != nil {
		return err
	}
	err := s.cache.update(func(tx *bbolt.Tx) error {
		root, err := s.cache.createBucket(tx, bucketScriptStore)
		if err != nil {
			return err
		}
		ns, err := root.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return err
		}
		return ns.Put([]byte(key), []byte(value))
	})
	if err != nil {
		if existed {
			_ = s.mirror.Set(namespace, key, old)
		} else {
			_ = s.mirror.Delete(namespace, key)
		}
		return err
	}
	return nil
}

func (s *scriptStore) Delete(namespace, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	_, existed, _ := s.mirror.Get(namespace, key)
	if !existed {
		return nil
	}
	err := s.cache.update(func(tx *bbolt.Tx) error {
		root := s.cache.bucket(tx, bucketScriptStore)
		if root == nil {
			return nil
		}
		ns := root.Bucket([]byte(namespace))
		if ns == nil {
			return nil
		}
		if err := ns.Delete([]byte(key)); err != nil {
			return err
		}
		if k, _ := ns.Cursor().First(); k == nil {
			return root.DeleteBucket([]byte(namespace))
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.mirror.Delete(namespace, key)
}

func (s *scriptStore) List(namespace string) ([]script.StoreEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	return s.mirror.List(namespace)
}

// Persistent implements script.StoreInfo.
func (s *scriptStore) Persistent() bool { return true }

// Usage implements script.StoreInfo.
func (s *scriptStore) Usage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return 0
	}
	return s.mirror.Usage()
}

// Namespaces implements script.StoreInfo.
func (s *scriptStore) Namespaces() ([]script.NamespaceInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	return s.mirror.Namespaces()
}
