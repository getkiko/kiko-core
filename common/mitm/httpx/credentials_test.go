package httpx

import "testing"

func TestCredentialHeaders(t *testing.T) {
	want := []string{"Cookie", "Cookie2", "Authorization", "Proxy-Authorization", "X-API-Key", "X-CSRF-Token", "X-XSRF-Token", "X-Auth-Token", "X-Access-Token"}
	have := map[string]bool{}
	for _, name := range CredentialHeaders {
		have[name] = true
	}
	for _, name := range want {
		if !have[name] {
			t.Errorf("%s missing", name)
		}
	}
	for _, name := range []string{"Referer", "Origin"} {
		if have[name] {
			t.Errorf("%s must stay", name)
		}
	}
}
