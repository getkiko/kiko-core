package capture

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

func TestRedactHeaderNameWords(t *testing.T) {
	r := newRedactor(nil)
	for _, name := range []string{"X-Custom-Token", "X-Client-Secret", "X-Api-Key", "X-Authenticated-User", "X-Credential-Id", "X-Session-Id", "Private-KEY"} {
		if !r.sensitive(name) {
			t.Errorf("%s not masked", name)
		}
	}
	for _, name := range []string{"Accept-Encoding", "Accept-Language", "Content-Type", "Content-Length", "Cache-Control", "Access-Control-Allow-Credentials", ":authority", "Host", "User-Agent", "Sec-WebSocket-Key"} {
		if r.sensitive(name) {
			t.Errorf("%s masked", name)
		}
	}
}

func TestRedactURLHeaders(t *testing.T) {
	r := newRedactor(nil)
	headers := r.headerList([]flow.Header{
		{Name: "Location", Value: "https://a.test/cb?code=abc&x=1"},
		{Name: "Referer", Value: "https://a.test/p?access_token=zzz"},
		{Name: "Content-Location", Value: "/p?sig=1"},
		{Name: "Refresh", Value: "0; url=https://u:p@a.test/n?token=1"},
		{Name: "Origin", Value: "https://a.test"},
	})
	for _, h := range headers {
		if strings.Contains(h.Value, "abc") || strings.Contains(h.Value, "zzz") || strings.Contains(h.Value, "sig=1") || strings.Contains(h.Value, "u:p") || strings.Contains(h.Value, "token=1") {
			t.Errorf("%s leaks: %s", h.Name, h.Value)
		}
	}
	if headers[0].Value != "https://a.test/cb?code="+RedactedValue+"&x=1" || headers[4].Value != "https://a.test" {
		t.Errorf("unexpected values %v", headers)
	}
}

func TestRedactChangesURLAndWords(t *testing.T) {
	r := newRedactor(nil)
	hits := r.hits([]flow.RewriteHit{{Changes: []flow.RewriteChange{
		{Name: "Location", Before: "https://a.test/?code=1", HadBefore: true, After: "https://b.test/?code=2", HasAfter: true},
		{Name: "X-Session-Id", Before: "s1", HadBefore: true, After: "s2", HasAfter: true},
		{Name: "Accept", Before: "a", HadBefore: true},
	}}})
	c := hits[0].Changes
	if strings.Contains(c[0].Before, "=1") || strings.Contains(c[0].After, "=2") {
		t.Errorf("location change leaks: %+v", c[0])
	}
	if c[1].Before != RedactedValue || c[1].After != RedactedValue {
		t.Errorf("session change leaks: %+v", c[1])
	}
	if c[2].Before != "a" {
		t.Errorf("accept masked: %+v", c[2])
	}
}
