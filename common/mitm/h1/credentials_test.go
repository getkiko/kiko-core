package h1

import (
	"testing"

	"github.com/sagernet/sing-box/common/mitm/httpx"
)

func TestDropCredentialsExtended(t *testing.T) {
	var h httpx.Header
	for _, name := range httpx.CredentialHeaders {
		h.Add(name, "secret")
	}
	h.Add("Referer", "https://a.test/")
	h.Add("Origin", "https://a.test")
	h.Add("X-Other", "1")
	dropCredentials(&h)
	for _, name := range httpx.CredentialHeaders {
		if h.Get(name) != "" {
			t.Errorf("%s kept", name)
		}
	}
	if h.Get("Referer") == "" || h.Get("Origin") == "" || h.Get("X-Other") == "" {
		t.Error("harmless headers dropped")
	}
}
