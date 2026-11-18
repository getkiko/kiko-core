package capture

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

const (
	secretToken  = "SECRET-BEARER-VALUE-1f9c"
	secretCookie = "sid=SECRET-COOKIE-VALUE-77aa"
	secretSet    = "session=SECRET-SETCOOKIE-VALUE-5d2e"
	secretExtra  = "SECRET-EXTRA-HEADER-VALUE-90bb"
	secretQuery  = "SECRET-QUERY-VALUE-42cd"
	bodyMarker   = "BODY-MARKER-ab12cd34"
)

func persistOptions(dir string) PersistOptions {
	return PersistOptions{Enabled: true, Path: dir, MaxBytes: 4 << 20, MaxRecords: 1000, Retention: time.Hour}
}

func waitPersist(t *testing.T, m *Manager, written uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.PersistStats().Written >= written {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("persist stats %+v, want %d written", m.PersistStats(), written)
}

func sensitiveExchange(m *Manager, path string, body string) string {
	x := m.NewExchange(&flow.ConnectionInfo{ID: "c", ProcessName: "curl", Host: "example.com"})
	x.RequestHead(flow.RequestHead{
		Method: "POST", Scheme: "https", Authority: "example.com", Path: path, Proto: "http/1.1",
		Headers: []flow.Header{
			{Name: "Host", Value: "example.com"},
			{Name: "Authorization", Value: "Bearer " + secretToken},
			{Name: "cookie", Value: secretCookie},
			{Name: "X-Internal-Key", Value: secretExtra},
			{Name: "Accept", Value: "*/*"},
		},
	})
	if body != "" {
		rb := x.RequestBody()
		rb.Write([]byte(body))
		rb.Done()
	}
	x.ResponseHead(200, []flow.Header{{Name: "Set-Cookie", Value: secretSet}, {Name: "Content-Type", Value: "text/plain"}})
	if body != "" {
		sb := x.ResponseBody()
		sb.Write([]byte("resp " + body))
		sb.Done()
	}
	x.Trailers(flow.Response, []flow.Header{{Name: "Authorization", Value: secretToken}})
	x.Finish(nil)
	return path
}

func readAll(t *testing.T, dir string) []byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var all []byte
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, data...)
	}
	return all
}

func segmentFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), segmentPrefix) {
			names = append(names, filepath.Join(dir, e.Name()))
		}
	}
	return names
}

func TestPersistDefaultOffWritesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	m := New(Options{Enabled: true, Body: true})
	m.SetOptions(Options{Enabled: true, Body: true, Persist: PersistOptions{Path: dir}})
	sensitiveExchange(m, "/off", "x")
	if m.persist != nil {
		t.Fatal("persister created while disabled")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory created: %v", err)
	}
	if stats := m.PersistStats(); stats.Enabled || stats.Written != 0 {
		t.Fatalf("%+v", stats)
	}
	allocs := testing.AllocsPerRun(50, func() { sensitiveExchange(m, "/off", "") })
	base := New(Options{Enabled: true, Body: true})
	reference := testing.AllocsPerRun(50, func() { sensitiveExchange(base, "/off", "") })
	if allocs > reference+1 {
		t.Fatalf("allocations with persistence off: %.0f, plain: %.0f", allocs, reference)
	}
}

func TestPersistRoundTripAndRedaction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	options.Persist.Body = true
	options.Persist.RedactHeaders = []string{"X-Internal-Key"}
	m := New(options)
	m.SetOptions(options)
	sensitiveExchange(m, "/a?access_token="+secretQuery+"&x=1", bodyMarker)
	sensitiveExchange(m, "/b", "")
	waitPersist(t, m, 2)

	// The viewer keeps the originals.
	list := m.List(Filter{})
	if len(list.Records) != 2 {
		t.Fatalf("records %d", len(list.Records))
	}
	var original Record
	for _, r := range list.Records {
		if strings.HasPrefix(r.Path, "/a") {
			original = r
		}
	}
	if headerValue(original.RequestHeaders, "Authorization") != "Bearer "+secretToken || !strings.Contains(original.URL, secretQuery) {
		t.Fatalf("memory record was changed: %+v", original)
	}
	m.Close()

	data := readAll(t, dir)
	for _, secret := range []string{secretToken, secretCookie, secretSet, secretExtra, secretQuery} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("%q found on disk", secret)
		}
	}
	if !bytes.Contains(data, []byte(RedactedValue)) {
		t.Fatal("no redaction marker on disk")
	}

	// A new process shows the history.
	again := New(options)
	again.SetOptions(options)
	defer again.Close()
	records := again.List(Filter{}).Records
	if len(records) != 2 {
		t.Fatalf("loaded %d records", len(records))
	}
	var loaded Record
	for _, r := range records {
		if strings.HasPrefix(r.Path, "/a") {
			loaded = r
		}
	}
	if loaded.Method != "POST" || loaded.Status != 200 || loaded.State != StateComplete || loaded.Connection == nil || loaded.Connection.ProcessName != "curl" {
		t.Fatalf("loaded %+v", loaded)
	}
	if headerValue(loaded.RequestHeaders, "Authorization") != RedactedValue || headerValue(loaded.RequestHeaders, "Accept") != "*/*" {
		t.Fatalf("headers %+v", loaded.RequestHeaders)
	}
	if headerValue(loaded.RequestHeaders, "X-Internal-Key") != RedactedValue || headerValue(loaded.ResponseHeaders, "Set-Cookie") != RedactedValue {
		t.Fatalf("headers %+v %+v", loaded.RequestHeaders, loaded.ResponseHeaders)
	}
	if strings.Contains(loaded.URL, secretQuery) || !strings.Contains(loaded.URL, "x=1") {
		t.Fatalf("url %q", loaded.URL)
	}
	res, err := again.GetBody(BodyRequest{ID: loaded.ID, Side: flow.Response})
	if err != nil || string(res.Data) != "resp "+bodyMarker || !res.Saved {
		t.Fatalf("body %+v %v", res, err)
	}
	// New traffic is not mixed up with stored ids and is written too.
	sensitiveExchange(again, "/c", "")
	waitPersist(t, again, 1)
	if again.PersistStats().Records != 3 {
		t.Fatalf("%+v", again.PersistStats())
	}
}

func TestPersistBodyOffKeepsNoBody(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	m := New(options)
	m.SetOptions(options)
	sensitiveExchange(m, "/a", bodyMarker)
	waitPersist(t, m, 1)
	m.Close()
	if bytes.Contains(readAll(t, dir), []byte(bodyMarker)) {
		t.Fatal("body written while body persistence is off")
	}
	again := New(options)
	again.SetOptions(options)
	defer again.Close()
	r := again.List(Filter{}).Records[0]
	if r.RequestBodySaved || r.ResponseBodySaved {
		t.Fatalf("%+v", r)
	}
}

func TestPersistPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "capture")
	// An existing directory with wide permissions is tightened.
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	options := Options{Enabled: true, Persist: persistOptions(dir)}
	m := New(options)
	m.SetOptions(options)
	sensitiveExchange(m, "/p", "")
	waitPersist(t, m, 1)
	m.Close()
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", info, err)
	}
	files := segmentFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("no files")
	}
	for _, f := range files {
		info, err = os.Stat(f)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("file %s %v %v", f, info.Mode(), err)
		}
	}
}

func TestPersistByteAndCountLimits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, MaxBody: 1 << 20, Persist: PersistOptions{Enabled: true, Path: dir, MaxBytes: 1 << 20, MaxRecords: 100000, Retention: time.Hour, Body: true}}
	m := New(options)
	m.SetOptions(options)
	body := strings.Repeat("z", 40<<10)
	const total = 60
	for i := 0; i < total; i++ {
		sensitiveExchange(m, fmt.Sprintf("/n%03d", i), body)
		waitPersist(t, m, uint64(i+1))
	}
	stats := m.PersistStats()
	if stats.Bytes > 1<<20 || stats.Records >= total || stats.Records == 0 {
		t.Fatalf("%+v", stats)
	}
	var size int64
	for _, f := range segmentFiles(t, dir) {
		info, _ := os.Stat(f)
		size += info.Size()
	}
	if size > 1<<20 || size != stats.Bytes {
		t.Fatalf("on disk %d, stats %+v", size, stats)
	}
	m.Close()
	// The newest records survive.
	again := New(options)
	again.SetOptions(options)
	records := again.List(Filter{}).Records
	again.Close()
	if len(records) == 0 || records[0].Path != fmt.Sprintf("/n%03d", total-1) {
		t.Fatalf("newest missing: %d records", len(records))
	}

	counted := filepath.Join(t.TempDir(), "count")
	options.Persist.Path, options.Persist.MaxRecords = counted, 5
	c := New(options)
	c.SetOptions(options)
	for i := 0; i < 20; i++ {
		sensitiveExchange(c, fmt.Sprintf("/c%03d", i), "")
	}
	waitPersist(t, c, 20)
	if got := c.PersistStats().Records; got != 5 {
		t.Fatalf("records %d", got)
	}
	c.Close()
	reopen := New(options)
	reopen.SetOptions(options)
	defer reopen.Close()
	list := reopen.List(Filter{}).Records
	if len(list) != 5 || list[0].Path != "/c019" || list[4].Path != "/c015" {
		t.Fatalf("%d records, first %v", len(list), list)
	}
}

func TestPersistRetention(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	opts := PersistOptions{Path: dir, MaxBytes: 4 << 20, MaxRecords: 100, Retention: time.Hour}.normalize()
	store, err := openDiskStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, age := range []time.Duration{3 * time.Hour, 2 * time.Hour, 10 * time.Minute} {
		if err = store.Append(uint64(i+1), now.Add(-age), []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	store.Sweep(now)
	if got := store.Stats().Records; got != 1 {
		t.Fatalf("records %d", got)
	}
	store.Close()
	reopened, err := openDiskStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.Stats().Records; got != 1 {
		t.Fatalf("after reopen %d", got)
	}
	if _, err = reopened.Read(3); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.Read(1); err != ErrNotPersisted {
		t.Fatalf("expired record readable: %v", err)
	}
}

func TestPersistCrashRecovery(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, file string){
		"truncated": func(t *testing.T, file string) {
			info, _ := os.Stat(file)
			if err := os.Truncate(file, info.Size()-7); err != nil {
				t.Fatal(err)
			}
		},
		"garbage": func(t *testing.T, file string) {
			f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err = f.Write(bytes.Repeat([]byte{0xC7, 1, 0, 0, 0xff, 0xff, 0xff, 0x7f}, 20)); err != nil {
				t.Fatal(err)
			}
		},
		"flipped": func(t *testing.T, file string) {
			data, _ := os.ReadFile(file)
			data[len(data)-3] ^= 0xff
			if err := os.WriteFile(file, data, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "capture")
			options := Options{Enabled: true, Persist: persistOptions(dir)}
			m := New(options)
			m.SetOptions(options)
			for i := 0; i < 5; i++ {
				sensitiveExchange(m, fmt.Sprintf("/r%d", i), "")
			}
			waitPersist(t, m, 5)
			m.Close()
			files := segmentFiles(t, dir)
			damage(t, files[len(files)-1])

			again := New(options)
			again.SetOptions(options)
			records := again.List(Filter{}).Records
			// Every frame before the damage survives.
			want := 5
			if name != "garbage" {
				want = 4
			}
			if len(records) != want {
				t.Fatalf("%d records, want %d", len(records), want)
			}
			// The file accepts appends after recovery and reads back clean.
			sensitiveExchange(again, "/after", "")
			waitPersist(t, again, 1)
			again.Close()
			third := New(options)
			third.SetOptions(options)
			defer third.Close()
			paths := map[string]bool{}
			for _, r := range third.List(Filter{}).Records {
				paths[r.Path] = true
			}
			if !paths["/after"] || len(paths) != want+1 {
				t.Fatalf("%v", paths)
			}
		})
	}
}

func TestPersistDeleteRecordRemovesBytes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	options.Persist.Body = true
	m := New(options)
	m.SetOptions(options)
	sensitiveExchange(m, "/keep", "KEEP-BODY-0001")
	sensitiveExchange(m, "/drop", "DROP-BODY-0002")
	sensitiveExchange(m, "/keep2", "KEEP-BODY-0003")
	waitPersist(t, m, 3)
	b64 := func(s string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(s))) }
	before := readAll(t, dir)
	if !bytes.Contains(before, b64("DROP-BODY-0002")) || !bytes.Contains(before, []byte("/drop")) {
		t.Fatal("test data not on disk")
	}
	var id string
	for _, r := range m.List(Filter{}).Records {
		if r.Path == "/drop" {
			id = r.ID
		}
	}
	if err := m.Delete(id); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(id); err != ErrNotFound {
		t.Fatalf("second delete: %v", err)
	}
	if got := m.PersistStats().Records; got != 2 {
		t.Fatalf("records %d", got)
	}
	data := readAll(t, dir)
	if bytes.Contains(data, b64("DROP-BODY-0002")) || bytes.Contains(data, []byte("/drop")) || !bytes.Contains(data, b64("KEEP-BODY-0001")) {
		t.Fatal("deleted record is still on disk, or a kept one vanished")
	}
	// Appends after a rewrite of the active segment still work.
	sensitiveExchange(m, "/later", "")
	waitPersist(t, m, 4)
	m.Close()
	again := New(options)
	again.SetOptions(options)
	defer again.Close()
	var paths []string
	for _, r := range again.List(Filter{}).Records {
		paths = append(paths, r.Path)
	}
	if strings.Join(paths, ",") != "/later,/keep2,/keep" {
		t.Fatalf("%v", paths)
	}
	if err := again.Delete("999999"); err != ErrNotFound {
		t.Fatal(err)
	}
}

func TestPersistDeleteInProgressRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Persist: persistOptions(dir)}
	m := New(options)
	m.SetOptions(options)
	defer m.Close()
	x := m.NewExchange(newConn("c"))
	x.RequestHead(head("/slow"))
	id := m.List(Filter{}).Records[0].ID
	if err := m.Delete(id); err != ErrInProgress {
		t.Fatalf("%v", err)
	}
	x.Finish(nil)
}

func TestPersistPurgeAndDisable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	options.Persist.Body = true
	m := New(options)
	m.SetOptions(options)
	for i := 0; i < 4; i++ {
		sensitiveExchange(m, fmt.Sprintf("/p%d", i), "PURGE-BODY")
	}
	waitPersist(t, m, 4)

	// Disabling keeps the files and stops writing.
	off := options
	off.Persist.Enabled = false
	m.SetOptions(off)
	if len(segmentFiles(t, dir)) == 0 || m.PersistStats().Enabled {
		t.Fatal("files should stay after disabling")
	}
	sensitiveExchange(m, "/unsaved", "")
	time.Sleep(20 * time.Millisecond)
	if bytes.Contains(readAll(t, dir), []byte("/unsaved")) {
		t.Fatal("written while off")
	}
	// Purge works while off, and takes the viewer rows that were stored.
	if err := m.PurgePersisted(); err != nil {
		t.Fatal(err)
	}
	if got := len(segmentFiles(t, dir)); got != 0 {
		t.Fatalf("%d files left", got)
	}
	var left []string
	for _, r := range m.List(Filter{}).Records {
		left = append(left, r.Path)
	}
	if strings.Join(left, ",") != "/unsaved" {
		t.Fatalf("rows %v", left)
	}

	// Purge with persistence on, then writing continues.
	m.SetOptions(options)
	sensitiveExchange(m, "/again", "")
	waitPersist(t, m, 1)
	if err := m.PurgePersisted(); err != nil {
		t.Fatal(err)
	}
	if got := m.PersistStats(); got.Records != 0 || got.Bytes != 0 || len(segmentFiles(t, dir)) != 0 {
		t.Fatalf("%+v", got)
	}
	sensitiveExchange(m, "/final", "")
	waitPersist(t, m, 2)
	if m.PersistStats().Records != 1 {
		t.Fatalf("%+v", m.PersistStats())
	}
	m.Close()
}

func TestPurgeDirKeepsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"seg-000000000001.cap", "seg-000000000002.cap.tmp", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := PurgeDir(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "notes.txt" {
		t.Fatalf("%v", entries)
	}
	if err := PurgeDir(filepath.Join(dir, "missing")); err != nil {
		t.Fatal(err)
	}
}

func TestPersistBackpressureDropsAndCounts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	opts := persistOptions(dir)
	p, err := newPersister(opts.normalize())
	if err != nil {
		t.Fatal(err)
	}
	// The writer is not started, so the queue fills.
	accepted := 0
	for i := 0; i < persistQueueLen+50; i++ {
		if p.offer(&persistJob{pid: uint64(i + 1), size: 1}) {
			accepted++
		}
	}
	if accepted != persistQueueLen || p.dropped.Load() != 50 {
		t.Fatalf("accepted %d dropped %d", accepted, p.dropped.Load())
	}
	big := &persistJob{size: persistQueueBytes + 1}
	if p.offer(big) || p.dropped.Load() != 51 {
		t.Fatal("oversized job accepted")
	}
	p.start()
	p.close()
}

func TestPersistExchangeNeverBlocksOnSlowDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Persist: persistOptions(dir)}
	m := New(options)
	m.SetOptions(options)
	defer m.Close()
	// Hold the store lock as a slow disk would.
	m.persist.store.mu.Lock()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			sensitiveExchange(m, "/slow", "")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("exchanges blocked behind the writer")
	}
	m.persist.store.mu.Unlock()
	if m.persist.dropped.Load() == 0 {
		t.Fatal("expected drops under back pressure")
	}
}

func TestPersistConcurrentWritersAndDeletes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	options.Persist.Body = true
	m := New(options)
	m.SetOptions(options)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				sensitiveExchange(m, fmt.Sprintf("/w%d-%d", w, i), "b")
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			for _, r := range m.List(Filter{Limit: 3}).Records {
				_ = m.Delete(r.ID)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	m.Close()
	again := New(options)
	again.SetOptions(options)
	defer again.Close()
	if got := again.PersistStats(); got.Errors != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestRedactor(t *testing.T) {
	r := newRedactor([]string{" X-Mine "})
	for _, name := range []string{"Authorization", "PROXY-AUTHORIZATION", "Cookie", "set-cookie", "X-Api-Key", "x-mine"} {
		if !r.sensitive(name) {
			t.Fatalf("%s not masked", name)
		}
	}
	if r.sensitive("Accept") {
		t.Fatal("Accept masked")
	}
	cases := map[string]string{
		"/a?token=1&b=2":                 "/a?token=[redacted]&b=2",
		"/a?b=2":                         "/a?b=2",
		"/a?B=2&Access_Token=zz#frag":    "/a?B=2&Access_Token=[redacted]#frag",
		"https://h/p?x=1&password=a%20b": "https://h/p?x=1&password=[redacted]",
		"/a?tok%65n=1":                   "/a?tok%65n=[redacted]",
		"/noquery":                       "/noquery",
		"/a?code=1&sig=2&Key=3&jwt=4&sid=5&auth=6&x_session=7&my_passphrase=8&q=ok": "/a?code=[redacted]&sig=[redacted]&Key=[redacted]&jwt=[redacted]&sid=[redacted]&auth=[redacted]&x_session=[redacted]&my_passphrase=[redacted]&q=ok",
		"https://user:pw@h/p?q=1": "https://[redacted]@h/p?q=1",
		"https://user:pw@h/":      "https://[redacted]@h/",
	}
	for in, want := range cases {
		if got := redactTarget(in); got != want {
			t.Errorf("redactTarget(%q) = %q, want %q", in, got, want)
		}
	}
	hits := []flow.RewriteHit{{Kind: "script", Target: "t", Changes: []flow.RewriteChange{
		{Op: "set", Name: "Authorization", Before: "old", HadBefore: true, After: "new", HasAfter: true},
		{Op: "set", Name: "X-Ok", After: "v", HasAfter: true},
	}, Run: &flow.ScriptRun{Logs: []flow.ScriptLog{{Message: "token abc"}}}}}
	out := r.hits(hits)
	if out[0].Changes[0].Before != RedactedValue || out[0].Changes[0].After != RedactedValue || out[0].Changes[1].After != "v" || out[0].Run.Logs != nil {
		t.Fatalf("%+v", out)
	}
	if hits[0].Changes[0].Before != "old" || len(hits[0].Run.Logs) != 1 {
		t.Fatal("input was modified")
	}
}

func TestFrameChecksumDetectsFlip(t *testing.T) {
	frame := encodeFrame(7, 123, []byte("hello"))
	count := 0
	readFrames(bytes.NewReader(frame), func(h frameHeader, _ int64, p []byte) {
		if h.pid != 7 || string(p) != "hello" {
			t.Fatal("decode")
		}
		count++
	})
	if count != 1 {
		t.Fatal("frame not read")
	}
	for i := range frame {
		bad := append([]byte(nil), frame...)
		bad[i] ^= 0x01
		n := 0
		readFrames(bytes.NewReader(bad), func(frameHeader, int64, []byte) { n++ })
		// Bytes 2-3 are reserved padding and not covered.
		if n != 0 && i != 2 && i != 3 {
			t.Fatalf("flip at byte %d went unnoticed", i)
		}
	}
}

func TestPersistExtendedQueryRedactionOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	m := New(options)
	m.SetOptions(options)
	sensitiveExchange(m, "/cb?code=OAUTH-CODE-9f&sig=SIG-VALUE-3a&apiKey=APIKEY-77&user_passphrase=PASS-12&sid=SID-55&keep=visible", "")
	waitPersist(t, m, 1)
	m.Close()
	data := readAll(t, dir)
	for _, secret := range []string{"OAUTH-CODE-9f", "SIG-VALUE-3a", "APIKEY-77", "PASS-12", "SID-55"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("%q found on disk", secret)
		}
	}
	if !bytes.Contains(data, []byte("keep=visible")) {
		t.Fatal("ordinary parameter was masked")
	}
}
