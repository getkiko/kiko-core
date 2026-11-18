package group

import (
	"github.com/sagernet/sing-box/adapter"

	"golang.org/x/net/publicsuffix"
)

// destinationKey is what keys a destination: its registrable domain,
// else its address.
func destinationKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	domain := metadata.Domain
	if metadata.Destination.IsFqdn() {
		domain = metadata.Destination.Fqdn
	}
	if domain != "" {
		if registrable, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
			return registrable
		}
		return domain
	}
	if metadata.Destination.Addr.IsValid() {
		return metadata.Destination.Addr.String()
	}
	return ""
}
