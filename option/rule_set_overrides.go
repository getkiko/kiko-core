package option

import (
	"context"
	"net/netip"
	"reflect"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// RuleSetOverrides change the rules a rule set loads from its source: the
// values in Remove leave the top-level default rules, then Add is appended.
// They apply each time the source content loads.
type RuleSetOverrides struct {
	Add    []HeadlessRule       `json:"add,omitempty"`
	Remove *DefaultHeadlessRule `json:"remove,omitempty"`
}

type _RuleSetOverrides RuleSetOverrides

// UnmarshalJSON refuses unknown keys, which the lenient first pass over a
// rule set would ignore.
func (o *RuleSetOverrides) UnmarshalJSON(content []byte) error {
	return json.UnmarshalContextDisallowUnknownFields(context.Background(), content, (*_RuleSetOverrides)(o))
}

// RuleSetOverrideRemoveFields are the rule fields Remove accepts.
var RuleSetOverrideRemoveFields = []string{
	"domain", "domain_suffix", "domain_keyword", "domain_regex",
	"ip_cidr", "source_ip_cidr", "process_name", "process_path", "package_name",
}

func (o *RuleSetOverrides) IsEmpty() bool {
	return o == nil || len(o.Add) == 0 && !o.HasRemove()
}

// HasRemove reports whether Remove names any value.
func (o *RuleSetOverrides) HasRemove() bool {
	if o == nil || o.Remove == nil {
		return false
	}
	r := o.Remove
	return len(r.Domain) > 0 || len(r.DomainSuffix) > 0 || len(r.DomainKeyword) > 0 || len(r.DomainRegex) > 0 ||
		len(r.IPCIDR) > 0 || len(r.SourceIPCIDR) > 0 || len(r.ProcessName) > 0 || len(r.ProcessPath) > 0 || len(r.PackageName) > 0
}

func (o *RuleSetOverrides) Validate() error {
	for i, rule := range o.Add {
		if !rule.IsValid() {
			return E.New("add[", i, "]: missing conditions")
		}
	}
	if o.Remove == nil {
		return nil
	}
	r := *o.Remove
	allowed := DefaultHeadlessRule{
		Domain:        r.Domain,
		DomainSuffix:  r.DomainSuffix,
		DomainKeyword: r.DomainKeyword,
		DomainRegex:   r.DomainRegex,
		IPCIDR:        r.IPCIDR,
		SourceIPCIDR:  r.SourceIPCIDR,
		ProcessName:   r.ProcessName,
		ProcessPath:   r.ProcessPath,
		PackageName:   r.PackageName,
	}
	if !reflect.DeepEqual(r, allowed) {
		return E.New("remove only supports domain, domain_suffix, domain_keyword, domain_regex, ip_cidr, source_ip_cidr, process_name, process_path and package_name")
	}
	for _, list := range [][]string{r.IPCIDR, r.SourceIPCIDR} {
		for _, value := range list {
			if _, err := ParseRuleSetOverridePrefix(value); err != nil {
				return E.Cause(err, "remove")
			}
		}
	}
	return nil
}

// ParseRuleSetOverridePrefix parses an ip_cidr value as rules do: a prefix
// or a single address.
func ParseRuleSetOverridePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix.Masked(), nil
	}
	addr, addrErr := netip.ParseAddr(value)
	if addrErr == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, E.Cause(err, "parse ", value)
}

func (o RuleSetOverrides) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("RuleSetOverrides", func() (*schema.Node, error) {
		headlessRef, err := builder.Describe(reflect.TypeFor[HeadlessRule]())
		if err != nil {
			return nil, err
		}
		remove := schema.StrictObject()
		for _, field := range RuleSetOverrideRemoveFields {
			remove.Properties.Put(field, schema.ListableOf(schema.StringNode()))
		}
		node := schema.StrictObject()
		node.Properties.Put("add", &schema.Node{Type: "array", Items: headlessRef})
		node.Properties.Put("remove", remove)
		return node, nil
	})
}
