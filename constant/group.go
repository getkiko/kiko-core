package constant

import "time"

// Policy group types besides selector and urltest. They share one
// runtime (protocol/group.Group) and differ in how a member is chosen.
const (
	TypeFallback    = "fallback"
	TypeLoadBalance = "loadbalance"
	TypeSmart       = "smart"
)

// Load balance strategies.
const (
	LoadBalanceRoundRobin        = "round_robin"
	LoadBalanceConsistentHashing = "consistent_hashing"
	LoadBalanceStickySessions    = "sticky_sessions"
)

// Group modes, as reported to clients.
const (
	GroupModeManual      = "manual"
	GroupModeFastest     = "fastest"
	GroupModeFallback    = "fallback"
	GroupModeLoadBalance = "loadbalance"
	GroupModeSmart       = "smart"
)

const (
	DefaultGroupProbeTimeout = 5 * time.Second
	DefaultGroupMaxFailures  = 3
)

// GroupDisplayName is the Clash display name of a policy group type
// added by this fork, "" for other types.
func GroupDisplayName(groupType string) string {
	switch groupType {
	case TypeFallback:
		return "Fallback"
	case TypeLoadBalance:
		return "LoadBalance"
	case TypeSmart:
		return "Smart"
	default:
		return ""
	}
}
