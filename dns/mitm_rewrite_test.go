package dns

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

type hostEngine struct {
	adapter.MITMEngine
	hosts map[string]bool
}

func (e *hostEngine) MatchHost(domain string) bool { return e.hosts[domain] }

func svcbValues(rr dns.RR) []dns.SVCBKeyValue {
	switch record := rr.(type) {
	case *dns.HTTPS:
		return record.Value
	case *dns.SVCB:
		return record.Value
	}
	return nil
}

func httpsAnswer(name string, priority uint16, values ...dns.SVCBKeyValue) *dns.Msg {
	response := new(dns.Msg)
	response.SetQuestion(name, dns.TypeHTTPS)
	response.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
		Priority: priority, Target: ".", Value: values,
	}}}
	return response
}

func keys(values []dns.SVCBKeyValue) []string {
	var result []string
	for _, value := range values {
		result = append(result, value.Key().String())
	}
	return result
}

func TestRewriteSVCBValues(t *testing.T) {
	ech := &dns.SVCBECHConfig{ECH: []byte{1, 2, 3}}
	hint := &dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.1").To4()}}
	unknown := &dns.SVCBLocal{KeyCode: 65400, Data: []byte{9}}
	port := &dns.SVCBPort{Port: 8443}
	for _, test := range []struct {
		name    string
		in      []dns.SVCBKeyValue
		want    []string
		alpn    []string
		changed bool
	}{
		{"h2 and h3", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}, hint}, []string{"alpn", "ipv4hint"}, []string{"h2"}, true},
		{"h3 variants", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3-29", "h3", "h2", "http/1.1"}}}, []string{"alpn"}, []string{"h2", "http/1.1"}, true},
		{"h3 only", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3"}}, hint}, []string{"ipv4hint"}, nil, true},
		{"h3 only with no-default-alpn", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3"}}, &dns.SVCBNoDefaultAlpn{}, hint}, []string{"ipv4hint"}, nil, true},
		{"no-default-alpn kept with remaining alpn", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}, &dns.SVCBNoDefaultAlpn{}}, []string{"alpn", "no-default-alpn"}, []string{"h2"}, true},
		{"ech only", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2"}}, port, ech, hint, unknown}, []string{"alpn", "port", "ipv4hint", "key65400"}, []string{"h2"}, true},
		{"everything", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}, &dns.SVCBNoDefaultAlpn{}, port, ech, hint, unknown}, []string{"alpn", "no-default-alpn", "port", "ipv4hint", "key65400"}, []string{"h2"}, true},
		{"nothing to remove", []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2"}}, &dns.SVCBNoDefaultAlpn{}, hint}, []string{"alpn", "no-default-alpn", "ipv4hint"}, []string{"h2"}, false},
		{"no alpn", []dns.SVCBKeyValue{hint}, []string{"ipv4hint"}, nil, false},
	} {
		out, changed := rewriteSVCBValues(test.in)
		if changed != test.changed || !reflect.DeepEqual(keys(out), test.want) {
			t.Fatalf("%s: changed=%v keys=%v want %v", test.name, changed, keys(out), test.want)
		}
		var alpn []string
		for _, value := range out {
			if a, ok := value.(*dns.SVCBAlpn); ok {
				alpn = a.Alpn
			}
		}
		if !reflect.DeepEqual(alpn, test.alpn) {
			t.Fatalf("%s: alpn=%v want %v", test.name, alpn, test.alpn)
		}
	}
}

func TestRewriteForMITM(t *testing.T) {
	engine := &hostEngine{hosts: map[string]bool{"example.com": true}}
	ech := &dns.SVCBECHConfig{ECH: []byte{1}}
	alpn := func() dns.SVCBKeyValue { return &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}} }

	original := httpsAnswer("example.com.", 1, alpn(), ech)
	rewritten, changed := rewriteForMITM(engine, original)
	if !changed || rewritten == original {
		t.Fatal("matched host not rewritten into a copy")
	}
	if got := keys(svcbValues(rewritten.Answer[0])); !reflect.DeepEqual(got, []string{"alpn"}) {
		t.Fatalf("rewritten keys=%v", got)
	}
	if got := keys(svcbValues(original.Answer[0])); !reflect.DeepEqual(got, []string{"alpn", "ech"}) {
		t.Fatalf("original mutated: %v", got)
	}
	if got := svcbValues(original.Answer[0])[0].(*dns.SVCBAlpn).Alpn; !reflect.DeepEqual(got, []string{"h2", "h3"}) {
		t.Fatalf("original alpn mutated: %v", got)
	}

	other := httpsAnswer("other.org.", 1, alpn(), ech)
	if out, changed := rewriteForMITM(engine, other); changed || out != other {
		t.Fatal("unmatched host rewritten")
	}
	alias := httpsAnswer("example.com.", 0, alpn(), ech)
	if out, changed := rewriteForMITM(engine, alias); changed || out != alias {
		t.Fatal("alias mode record rewritten")
	}
	if out, changed := rewriteForMITM(nil, original); changed || out != original {
		t.Fatal("rewritten without an engine")
	}

	mixed := httpsAnswer("example.com.", 0, alpn())
	mixed.Answer = append(mixed.Answer, httpsAnswer("example.com.", 2, alpn(), ech).Answer[0], httpsAnswer("example.com.", 3, &dns.SVCBPort{Port: 1}).Answer[0])
	out, changed := rewriteForMITM(engine, mixed)
	if !changed || len(out.Answer) != 3 {
		t.Fatal("mixed answer not rewritten")
	}
	if !reflect.DeepEqual(keys(svcbValues(out.Answer[0])), []string{"alpn"}) || len(svcbValues(out.Answer[0])[0].(*dns.SVCBAlpn).Alpn) != 2 {
		t.Fatal("alias record changed")
	}
	if !reflect.DeepEqual(keys(svcbValues(out.Answer[1])), []string{"alpn"}) || !reflect.DeepEqual(keys(svcbValues(out.Answer[2])), []string{"port"}) {
		t.Fatalf("service records: %v %v", keys(svcbValues(out.Answer[1])), keys(svcbValues(out.Answer[2])))
	}

	svcb := new(dns.Msg)
	svcb.SetQuestion("example.com.", dns.TypeSVCB)
	svcb.Answer = []dns.RR{&dns.SVCB{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{alpn(), ech}}}
	out, changed = rewriteForMITM(engine, svcb)
	if !changed || !reflect.DeepEqual(keys(svcbValues(out.Answer[0])), []string{"alpn"}) {
		t.Fatal("SVCB record not rewritten")
	}

	aRecord := new(dns.Msg)
	aRecord.SetQuestion("example.com.", dns.TypeA)
	if out, changed := rewriteForMITM(engine, aRecord); changed || out != aRecord {
		t.Fatal("A query touched")
	}
}

func TestClientRewritesCachedAnswersWithoutChangingTheCache(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	engine := &hostEngine{hosts: map[string]bool{"example.com": true}}
	service.MustRegister[adapter.MITMEngine](ctx, engine)
	client := NewClient(ClientOptions{Context: ctx, Logger: log.NewNOPFactory().Logger()})
	response := httpsAnswer("example.com.", 1, &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}, &dns.SVCBECHConfig{ECH: []byte{1}})
	key := dnsCacheKey{Question: response.Question[0], transportTag: "t"}
	client.storeCache(key, response, 60)
	cached, _, _ := client.loadResponse(key)
	if cached == nil {
		t.Fatal("cache miss")
	}
	for range 2 {
		out := client.rewriteResponse(ctx, cached)
		if got := keys(svcbValues(out.Answer[0])); !reflect.DeepEqual(got, []string{"alpn"}) {
			t.Fatalf("rewritten keys=%v", got)
		}
		again, _, _ := client.loadResponse(key)
		if got := keys(svcbValues(again.Answer[0])); !reflect.DeepEqual(got, []string{"alpn", "ech"}) {
			t.Fatalf("cache mutated: %v", got)
		}
	}
}

func mandatoryCodes(values []dns.SVCBKeyValue) ([]dns.SVCBKey, bool) {
	for _, value := range values {
		if mandatory, ok := value.(*dns.SVCBMandatory); ok {
			return mandatory.Code, true
		}
	}
	return nil, false
}

func TestRewriteSVCBMandatory(t *testing.T) {
	ech := &dns.SVCBECHConfig{ECH: []byte{1, 2, 3}}
	hint := &dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.1").To4()}}
	for _, test := range []struct {
		name      string
		in        []dns.SVCBKeyValue
		want      []dns.SVCBKey
		mandatory bool
		keys      []string
	}{
		{"alpn and ech, ech dropped", []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_ECHCONFIG}}, &dns.SVCBAlpn{Alpn: []string{"h2"}}, ech}, []dns.SVCBKey{dns.SVCB_ALPN}, true, []string{"mandatory", "alpn"}},
		{"ech only", []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ECHCONFIG}}, &dns.SVCBAlpn{Alpn: []string{"h2"}}, ech}, nil, false, []string{"alpn"}},
		{"alpn dropped", []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_IPV4HINT}}, &dns.SVCBAlpn{Alpn: []string{"h3"}}, hint}, []dns.SVCBKey{dns.SVCB_IPV4HINT}, true, []string{"mandatory", "ipv4hint"}},
		{"alpn kept", []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN}}, &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}}, []dns.SVCBKey{dns.SVCB_ALPN}, true, []string{"mandatory", "alpn"}},
	} {
		out, changed := rewriteSVCBValues(test.in)
		if !changed || !reflect.DeepEqual(keys(out), test.keys) {
			t.Fatalf("%s: changed=%v keys=%v want %v", test.name, changed, keys(out), test.keys)
		}
		codes, present := mandatoryCodes(out)
		if present != test.mandatory || !reflect.DeepEqual(codes, test.want) {
			t.Fatalf("%s: mandatory=%v present=%v want %v", test.name, codes, present, test.want)
		}
	}
	// The input is not modified.
	in := []dns.SVCBKeyValue{&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_ECHCONFIG}}, ech}
	rewriteSVCBValues(in)
	if codes, _ := mandatoryCodes(in); len(codes) != 2 {
		t.Fatalf("input modified: %v", codes)
	}
}

func TestSVCBTargetHost(t *testing.T) {
	for name, want := range map[string]string{
		"example.com":               "example.com",
		"_8443._https.example.com":  "example.com",
		"_443._https.a.example.com": "a.example.com",
		"_8443._foo.example.com":    "example.com",
		"_dmarc.example.com":        "_dmarc.example.com",
		"_https.example.com":        "_https.example.com",
		"_8443._https":              "_8443._https",
		"_x1._https.example.com":    "_x1._https.example.com",
		"_8443.example.com":         "_8443.example.com",
		"":                          "",
	} {
		if got := svcbTargetHost(name); got != want {
			t.Fatalf("%q: got %q want %q", name, got, want)
		}
	}
}

func TestRewritePortPrefixedOwner(t *testing.T) {
	engine := &hostEngine{hosts: map[string]bool{"example.com": true}}
	response := httpsAnswer("_8443._https.example.com.", 1, &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}, &dns.SVCBECHConfig{ECH: []byte{1}})
	out, changed := rewriteForMITM(engine, response)
	if !changed || !reflect.DeepEqual(keys(svcbValues(out.Answer[0])), []string{"alpn"}) {
		t.Fatalf("port-prefixed owner not rewritten: changed=%v", changed)
	}
	other := httpsAnswer("_8443._https.other.test.", 1, &dns.SVCBECHConfig{ECH: []byte{1}})
	if _, changed := rewriteForMITM(engine, other); changed {
		t.Fatal("unrelated host rewritten")
	}
	// AliasMode records are left as they are.
	alias := httpsAnswer("_8443._https.example.com.", 0, &dns.SVCBECHConfig{ECH: []byte{1}})
	if _, changed := rewriteForMITM(engine, alias); changed {
		t.Fatal("alias record rewritten")
	}
}

type panicEngine struct {
	adapter.MITMEngine
}

func TestRewriteResponseChecksTypeBeforeEngine(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.MITMEngine](ctx, &panicEngine{})
	client := NewClient(ClientOptions{Context: ctx, Logger: log.NewNOPFactory().Logger()})
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1")}}
	if out := client.rewriteResponse(ctx, response); out != response {
		t.Fatal("A answer changed")
	}
}
