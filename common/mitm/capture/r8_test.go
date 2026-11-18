package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

func TestRedactFragment(t *testing.T) {
	cases := map[string]string{
		"https://a.test/cb#access_token=SECRET&state=1": "https://a.test/cb#access_token=" + RedactedValue + "&state=1",
		"/p?x=1&code=C#id_token=J&page=2":               "/p?x=1&code=" + RedactedValue + "#id_token=" + RedactedValue + "&page=2",
		"/p#plain":                                      "/p#plain",
		"https://u:pw@a.test/#session=S":                "https://" + RedactedValue + "@a.test/#session=" + RedactedValue,
	}
	for in, want := range cases {
		if got := redactTarget(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	r := newRedactor(nil)
	for _, name := range []string{"Location", "Referer", "Refresh"} {
		if got := r.value(name, "https://a.test/#access_token=ZZZ"); strings.Contains(got, "ZZZ") {
			t.Errorf("%s leaks %s", name, got)
		}
	}
}

func TestRedactHeaderWordsR8(t *testing.T) {
	r := newRedactor(nil)
	for _, name := range []string{"X-Pass", "X-Passcode", "X-Pwd", "X-Signature", "X-Jwt", "X-Bearer", "X-Otp", "Sec-WebSocket-Protocol"} {
		if !r.sensitive(name) {
			t.Errorf("%s not masked", name)
		}
	}
	if r.sensitive("Sec-WebSocket-Key") || r.sensitive("Content-Type") {
		t.Error("harmless header masked")
	}
}

func TestRedactScriptRunError(t *testing.T) {
	r := newRedactor(nil)
	hits := r.hits([]flow.RewriteHit{{Run: &flow.ScriptRun{Error: "boom token=ABC", Reason: "x ABC"}}})
	if hits[0].Run.Error != "" || hits[0].Run.Reason != "" {
		t.Fatalf("%+v", hits[0].Run)
	}
}

func TestPersistDeleteWhileClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Body: true, Persist: persistOptions(dir)}
	options.Persist.Body = true
	m := New(options)
	m.SetOptions(options)
	sensitiveExchange(m, "/gone-closed", "CLOSED-BODY")
	sensitiveExchange(m, "/stay-closed", "STAY")
	waitPersist(t, m, 2)
	off := options
	off.Persist.Enabled = false
	m.SetOptions(off)
	var id string
	for _, r := range m.List(Filter{}).Records {
		if r.Path == "/gone-closed" {
			id = r.ID
		}
	}
	if err := m.Delete(id); err != nil {
		t.Fatal(err)
	}
	data := readAll(t, dir)
	if bytes.Contains(data, []byte("/gone-closed")) || !bytes.Contains(data, []byte("/stay-closed")) {
		t.Fatal("closed-copy delete wrong")
	}
}

func TestPersistPurgeDropsQueuedOfEvictedRows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	options := Options{Enabled: true, Persist: persistOptions(dir)}
	m := New(options)
	m.SetOptions(options)
	defer m.Close()
	p := m.persist
	job := &persistJob{pid: 77, rec: Record{Path: "/late"}, size: 1, gen: p.gen.Load()}
	if err := m.PurgePersisted(); err != nil {
		t.Fatal(err)
	}
	p.write(job)
	if bytes.Contains(readAll(t, dir), []byte("/late")) {
		t.Fatal("job queued before the purge landed after it")
	}
}

func TestEnsureDirRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if err := ensureDir(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o755 {
		t.Fatalf("target mode changed: %v", info.Mode())
	}
}
