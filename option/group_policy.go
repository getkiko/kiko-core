package option

import "github.com/sagernet/sing/common/json/badoption"

// GroupHealthCheckOptions are the health check of the fallback,
// loadbalance and smart groups, with the names urltest uses.
type GroupHealthCheckOptions struct {
	URL         string             `json:"url,omitempty"`
	Interval    badoption.Duration `json:"interval,omitempty"`
	Timeout     badoption.Duration `json:"timeout,omitempty"`
	IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`
	// MaxFailures is how many failed connections in a row, to at least
	// two destinations, make a member suspect, which probes it at once.
	MaxFailures uint32 `json:"max_failures,omitempty"`
}

type FallbackOutboundOptions struct {
	Outbounds []string `json:"outbounds" reference:"outbound"`
	GroupHealthCheckOptions
	// NoReturn keeps the current member when a member before it recovers.
	NoReturn                  bool `json:"no_return,omitempty"`
	InterruptExistConnections bool `json:"interrupt_exist_connections,omitempty"`
}

type LoadBalanceOutboundOptions struct {
	Outbounds []string `json:"outbounds" reference:"outbound"`
	GroupHealthCheckOptions
	Strategy                  string `json:"strategy,omitempty" enum:"round_robin,consistent_hashing,sticky_sessions"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}
