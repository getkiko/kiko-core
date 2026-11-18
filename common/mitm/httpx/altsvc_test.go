package httpx

import "testing"

func TestFilterAltSvc(t *testing.T) {
	cases := []struct {
		in      string
		out     string
		changed bool
	}{
		{`clear`, `clear`, false},
		{`h3=":443"; ma=86400`, ``, true},
		{`h3=":443"; ma=86400, h3-29=":443"; ma=86400`, ``, true},
		{`h2=":443", h3=":443"`, `h2=":443"`, true},
		{`h3=":443"; note="a,b", h2="alt.example:443"`, `h2="alt.example:443"`, true},
		{`h2="h3.example.com:443"`, `h2="h3.example.com:443"`, false},
		{`quic=":443"; v="46", h2=":443"`, `h2=":443"`, true},
		{`H3=":443"`, ``, true},
		{`h2=":443"`, `h2=":443"`, false},
		{``, ``, false},
	}
	for _, c := range cases {
		out, changed := FilterAltSvc(c.in)
		if out != c.out || changed != c.changed {
			t.Errorf("FilterAltSvc(%q) = %q, %v; want %q, %v", c.in, out, changed, c.out, c.changed)
		}
	}
}
