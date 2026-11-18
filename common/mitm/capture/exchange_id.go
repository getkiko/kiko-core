package capture

import "github.com/sagernet/sing-box/common/mitm/flow"

// ExchangeID returns the record id of an exchange the manager created, or
// the empty string for any other exchange (a disabled store hands out
// no-op exchanges).
func ExchangeID(x flow.Exchange) string {
	if recorded, ok := x.(*exchange); ok {
		return recorded.e.rec.ID
	}
	return ""
}
