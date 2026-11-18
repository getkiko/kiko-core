package cachefile

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/script"

	"github.com/stretchr/testify/require"
)

func openTestCache(t *testing.T, path, cacheID string) *CacheFile {
	t.Helper()
	cache := New(context.Background(), log.NewNOPFactory().NewLogger("cache"), option.CacheFileOptions{Enabled: true, Path: path, CacheID: cacheID})
	require.NoError(t, cache.start())
	return cache
}

func closeTestCache(t *testing.T, cache *CacheFile) {
	t.Helper()
	require.NoError(t, cache.database().Close())
}

func TestScriptStoreBeforeStart(t *testing.T) {
	cache := New(context.Background(), log.NewNOPFactory().NewLogger("cache"), option.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "c.db")})
	store := cache.ScriptStore()
	_, _, err := store.Get("a", "k")
	require.Error(t, err)
	require.Error(t, store.Set("a", "k", "v"))
	require.Nil(t, cache.database())
}

func TestScriptStorePersistsAcrossRestart(t *testing.T) {
	for _, cacheID := range []string{"", "profile-1"} {
		t.Run("cache_id="+cacheID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.db")
			cache := openTestCache(t, path, cacheID)
			store := cache.ScriptStore()
			require.True(t, store.(script.StoreInfo).Persistent())
			require.NoError(t, store.Set("fix-feed", "count", "7"))
			require.NoError(t, store.Set("fix-feed", "other", "x"))
			require.NoError(t, store.Set("@shared", "token", "abc"))
			require.NoError(t, store.Set("gone", "k", "v"))
			require.NoError(t, store.Delete("gone", "k"))
			require.NoError(t, store.Set("fix-feed", "count", "8"))
			closeTestCache(t, cache)

			cache = openTestCache(t, path, cacheID)
			defer closeTestCache(t, cache)
			store = cache.ScriptStore()
			value, ok, err := store.Get("fix-feed", "count")
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, "8", value)
			value, ok, _ = store.Get("@shared", "token")
			require.True(t, ok)
			require.Equal(t, "abc", value)
			_, ok, _ = store.Get("gone", "k")
			require.False(t, ok)
			list, err := store.List("fix-feed")
			require.NoError(t, err)
			require.Equal(t, []script.StoreEntry{{Key: "count", Value: "8"}, {Key: "other", Value: "x"}}, list)
			namespaces, err := store.(script.StoreInfo).Namespaces()
			require.NoError(t, err)
			require.Equal(t, []script.NamespaceInfo{
				{Name: "@shared", Entries: 1, Bytes: int64(len("token") + len("abc"))},
				{Name: "fix-feed", Entries: 2, Bytes: int64(len("count") + 1 + len("other") + 1)},
			}, namespaces)
			require.EqualValues(t, len("token")+3+len("count")+1+len("other")+1+3*script.StoreEntryOverhead, store.(script.StoreInfo).Usage())
		})
	}
}

func TestScriptStoreSurvivesBucketCleanup(t *testing.T) {
	// The cleanup at open deletes buckets that are not in bucketNameList.
	path := filepath.Join(t.TempDir(), "cache.db")
	cache := openTestCache(t, path, "")
	require.NoError(t, cache.ScriptStore().Set("a", "k", "v"))
	closeTestCache(t, cache)
	for range 2 {
		cache = openTestCache(t, path, "")
		value, ok, err := cache.ScriptStore().Get("a", "k")
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, "v", value)
		closeTestCache(t, cache)
	}
}

func TestScriptStoreLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cache := openTestCache(t, path, "")
	store := cache.ScriptStore()

	require.ErrorIs(t, store.Set("a", "", "v"), script.ErrStoreKey)
	require.ErrorIs(t, store.Set("a", strings.Repeat("k", 257), "v"), script.ErrStoreKey)
	require.NoError(t, store.Set("a", strings.Repeat("k", 256), "v"))
	require.ErrorIs(t, store.Set("a", "big", strings.Repeat("x", script.MaxStoreValue+1)), script.ErrStoreValueTooLarge)
	require.NoError(t, store.Set("a", "max", strings.Repeat("x", script.MaxStoreValue)))

	// Fill up to the total, one value at a time; the failing write leaves no trace.
	i := 0
	var fullErr error
	for ; i < 40; i++ {
		fullErr = store.Set("fill", "k"+string(rune('a'+i%26))+string(rune('a'+i/26)), strings.Repeat("y", script.MaxStoreValue))
		if fullErr != nil {
			break
		}
	}
	require.ErrorIs(t, fullErr, script.ErrStoreFull)
	require.Less(t, i, 17)
	used := store.(script.StoreInfo).Usage()
	require.LessOrEqual(t, used, int64(script.MaxStoreTotal))
	_, ok, _ := store.Get("fill", "k"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	require.False(t, ok)
	closeTestCache(t, cache)

	// The failed write is not on disk either, and the usage is the same after a restart.
	cache = openTestCache(t, path, "")
	defer closeTestCache(t, cache)
	require.Equal(t, used, cache.ScriptStore().(script.StoreInfo).Usage())
	// Overwriting a value in a full store with a smaller one works, and frees space.
	require.NoError(t, cache.ScriptStore().Set("fill", "kaa", "tiny"))
	require.Less(t, cache.ScriptStore().(script.StoreInfo).Usage(), used)
}

func TestScriptStoreConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cache := openTestCache(t, path, "")
	store := cache.ScriptStore()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				key := string(rune('a'+g)) + string(rune('a'+i))
				if err := store.Set("c", key, key); err != nil {
					t.Error(err)
					return
				}
				if v, ok, _ := store.Get("c", key); !ok || v != key {
					t.Errorf("read back %q: %q %v", key, v, ok)
				}
				if i%3 == 0 {
					_ = store.Delete("c", key)
				}
			}
		}()
	}
	wg.Wait()
	before, _ := store.List("c")
	closeTestCache(t, cache)
	cache = openTestCache(t, path, "")
	defer closeTestCache(t, cache)
	after, err := cache.ScriptStore().List("c")
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestScriptStoreRemovingLastKeyDropsNamespace(t *testing.T) {
	cache := openTestCache(t, filepath.Join(t.TempDir(), "cache.db"), "")
	defer closeTestCache(t, cache)
	store := cache.ScriptStore()
	require.NoError(t, store.Set("a", "k", "v"))
	require.NoError(t, store.Delete("a", "k"))
	require.NoError(t, store.Delete("a", "never"))
	namespaces, err := store.(script.StoreInfo).Namespaces()
	require.NoError(t, err)
	require.Empty(t, namespaces)
	require.Zero(t, store.(script.StoreInfo).Usage())
}

func TestScriptStoreEntryCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cache := openTestCache(t, path, "")
	store := cache.ScriptStore()
	for i := range script.MaxStoreNamespaceEntries {
		require.NoError(t, store.Set("a", strings.Repeat("k", 1)+string(rune('0'+i%10))+string(rune('a'+i/10%26))+string(rune('a'+i/260%26))+string(rune('a'+i/6760)), ""))
	}
	require.ErrorIs(t, store.Set("a", "one-more", ""), script.ErrStoreTooMany)
	require.NoError(t, store.Set("b", "k", ""), "another namespace has its own allowance")
	closeTestCache(t, cache)
	cache = openTestCache(t, path, "")
	defer closeTestCache(t, cache)
	list, err := cache.ScriptStore().List("a")
	require.NoError(t, err)
	require.Len(t, list, script.MaxStoreNamespaceEntries)
	require.ErrorIs(t, cache.ScriptStore().Set("a", "one-more", ""), script.ErrStoreTooMany)
}
