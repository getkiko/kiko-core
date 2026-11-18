package dns

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmonitor"
	"github.com/sagernet/sing/service"
)

// mitmRewriteNote is the dnsmonitor annotation of a rewritten answer.
const mitmRewriteNote = "mitm"

// rewriteForMITM removes the ech SvcParam and the h3 ALPN ids from HTTPS and
// SVCB answers for hosts the MITM engine decrypts, so that clients keep
// negotiating TLS over TCP. It returns response itself when nothing changes
// and otherwise a copy; response is never modified.
func rewriteForMITM(engine adapter.MITMEngine, response *dns.Msg) (*dns.Msg, bool) {
	if engine == nil || response == nil || len(response.Question) == 0 || len(response.Answer) == 0 {
		return response, false
	}
	switch response.Question[0].Qtype {
	case dns.TypeHTTPS, dns.TypeSVCB:
	default:
		return response, false
	}
	if !engine.MatchHost(svcbTargetHost(FqdnToDomain(response.Question[0].Name))) {
		return response, false
	}
	var rewritten *dns.Msg
	for index, rr := range response.Answer {
		var content *dns.SVCB
		switch record := rr.(type) {
		case *dns.HTTPS:
			content = &record.SVCB
		case *dns.SVCB:
			content = record
		default:
			continue
		}
		if content.Priority == 0 {
			continue
		}
		values, changed := rewriteSVCBValues(content.Value)
		if !changed {
			continue
		}
		if rewritten == nil {
			rewritten = response.Copy()
		}
		switch record := rewritten.Answer[index].(type) {
		case *dns.HTTPS:
			record.Value = values
		case *dns.SVCB:
			record.Value = values
		}
	}
	if rewritten == nil {
		return response, false
	}
	return rewritten, true
}

// svcbTargetHost returns the host an SVCB or HTTPS owner name stands for. A
// service on a port other than the scheme default is queried as
// _<port>._<scheme>.<host> (RFC 9460 section 2.3). AliasMode records
// (priority 0) are not followed to their target: the rewrite leaves them as
// they are.
func svcbTargetHost(name string) string {
	if len(name) < 2 || name[0] != '_' {
		return name
	}
	portLabel, rest, found := strings.Cut(name, ".")
	if !found || len(portLabel) < 2 {
		return name
	}
	for i := 1; i < len(portLabel); i++ {
		if portLabel[i] < '0' || portLabel[i] > '9' {
			return name
		}
	}
	schemeLabel, host, found := strings.Cut(rest, ".")
	if !found || len(schemeLabel) < 2 || schemeLabel[0] != '_' || host == "" {
		return name
	}
	return host
}

func rewriteSVCBValues(values []dns.SVCBKeyValue) ([]dns.SVCBKeyValue, bool) {
	changed := false
	dropNoDefault := false
	removed := make(map[dns.SVCBKey]bool, 3)
	result := make([]dns.SVCBKeyValue, 0, len(values))
	for _, value := range values {
		switch value.Key() {
		case dns.SVCB_ECHCONFIG:
			changed = true
			removed[dns.SVCB_ECHCONFIG] = true
			continue
		case dns.SVCB_ALPN:
			alpn, isAlpn := value.(*dns.SVCBAlpn)
			if !isAlpn {
				break
			}
			kept := make([]string, 0, len(alpn.Alpn))
			for _, id := range alpn.Alpn {
				if id == "h3" || strings.HasPrefix(id, "h3-") {
					continue
				}
				kept = append(kept, id)
			}
			if len(kept) == len(alpn.Alpn) {
				break
			}
			changed = true
			if len(kept) == 0 {
				dropNoDefault = true
				removed[dns.SVCB_ALPN] = true
				removed[dns.SVCB_NO_DEFAULT_ALPN] = true
				continue
			}
			value = &dns.SVCBAlpn{Alpn: kept}
		}
		result = append(result, value)
	}
	if !changed {
		return values, false
	}
	if dropNoDefault {
		kept := result[:0]
		for _, value := range result {
			if value.Key() != dns.SVCB_NO_DEFAULT_ALPN {
				kept = append(kept, value)
			}
		}
		result = kept
	}
	// A mandatory list must not name a key that is gone.
	for index, value := range result {
		mandatory, isMandatory := value.(*dns.SVCBMandatory)
		if !isMandatory {
			continue
		}
		codes := make([]dns.SVCBKey, 0, len(mandatory.Code))
		for _, code := range mandatory.Code {
			if !removed[code] {
				codes = append(codes, code)
			}
		}
		if len(codes) == len(mandatory.Code) {
			break
		}
		if len(codes) == 0 {
			result = append(result[:index], result[index+1:]...)
		} else {
			result[index] = &dns.SVCBMandatory{Code: codes}
		}
		break
	}
	return result, true
}

func mitmEngine(client *Client) adapter.MITMEngine {
	if client.ctx == nil {
		return nil
	}
	return service.FromContext[adapter.MITMEngine](client.ctx)
}

// rewriteResponse applies rewriteForMITM and annotates the monitor trace.
// It runs on every response leaving the client, cached or fresh, so the
// cache keeps the original answer and a policy change applies at once.
func (c *Client) rewriteResponse(ctx context.Context, response *dns.Msg) *dns.Msg {
	if response == nil || len(response.Question) == 0 || len(response.Answer) == 0 {
		return response
	}
	switch response.Question[0].Qtype {
	case dns.TypeHTTPS, dns.TypeSVCB:
	default:
		return response
	}
	rewritten, changed := rewriteForMITM(mitmEngine(c), response)
	if changed {
		dnsmonitor.Rewritten(ctx, mitmRewriteNote)
	}
	return rewritten
}
