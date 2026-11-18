package option

import "github.com/sagernet/sing/common/json/badoption"

type BurrowPredictiveOptions struct {
	PortScanRange  int                `json:"port_scan_range,omitempty"`
	Concurrency    int                `json:"concurrency,omitempty"`
	AttemptTimeout badoption.Duration `json:"attempt_timeout,omitempty"`
}

type BurrowBirthdayOptions struct {
	Selection            string             `json:"selection"`
	Candidates           int                `json:"candidates,omitempty"`
	MinPort              uint16             `json:"min_port,omitempty"`
	MaxPort              uint16             `json:"max_port,omitempty"`
	Warmup               badoption.Duration `json:"warmup,omitempty"`
	AttemptTimeout       badoption.Duration `json:"attempt_timeout,omitempty"`
	SuccessGrace         badoption.Duration `json:"success_grace,omitempty"`
	MaxSuccessCandidates int                `json:"max_success_candidates,omitempty"`
}

type BurrowNATProbeOptions struct {
	Targets        []string           `json:"targets,omitempty"`
	InitialSamples int                `json:"initial_samples,omitempty"`
	MaxSamples     int                `json:"max_samples,omitempty"`
	Timeout        badoption.Duration `json:"timeout,omitempty"`
	CacheTTL       badoption.Duration `json:"cache_ttl,omitempty"`
}

// BurrowSTUNOptions configures the STUN servers used by UDP hole punching
// (both direct and predictive need STUN to learn the public mapping). It only
// applies when network contains "udp"; TCP hole punching does not use STUN.
type BurrowSTUNOptions struct {
	Servers        []string           `json:"servers,omitempty"`
	InitialSamples int                `json:"initial_samples,omitempty"`
	MaxSamples     int                `json:"max_samples,omitempty"`
	Timeout        badoption.Duration `json:"timeout,omitempty"`
	CacheTTL       badoption.Duration `json:"cache_ttl,omitempty"`
}

type BurrowOptions struct {
	Room string `json:"room"`
	// Hosts is a static map from signaling domain names to IP addresses, such as
	// {"signal.example.com": "1.2.3.4"}. It applies to the domains in server and
	// nat_probe.targets: a matching domain uses the mapped IP without a DNS
	// query; other domains still go through domain_resolver.
	//
	// The domain in the WebSocket URL is kept, so the HTTP Host and TLS SNI
	// still carry it and the signaling traffic appears to reach that domain.
	Hosts map[string]string `json:"hosts,omitempty"`

	// SignalPath is the fixed path prefix of the signaling endpoint, such as
	// "/abc". Requests look like ws://server:port/abc?command={signal|probe|nat};
	// when empty, the root path ws://server:port/?command=xxx is used.
	//
	// If server is already a URL with a path (such as "ws://1.2.3.4:9960/abc"),
	// the path in server wins and this field is ignored.
	SignalPath string `json:"signal_path,omitempty"`

	// Mode optionally controls how signaling parameters are sent:
	//   ""       (default) parameters go in the URL query, such as
	//            ?command=nat&room=r&session=s.
	//   "header" parameters stay out of the URL and are sent base64 encoded in
	//            the Cookie request header, so on-path observers do not see
	//            command/room/session in clear text.
	// The signaling server always accepts both forms.
	Mode string `json:"mode,omitempty"`

	BindInterface string `json:"bind_interface,omitempty"`
	// AddressFamily selects the address family for TCP hole punching: ipv4 or
	// ipv6. Empty means ipv4. It only applies to the TCP path.
	AddressFamily  string                `json:"address_family,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
	PairTimeout    badoption.Duration    `json:"pair_timeout,omitempty"`

	// PortScanRange keeps compatibility with the original predictive mode.
	PortScanRange int `json:"port_scan_range,omitempty"`

	Strategy              string                   `json:"strategy,omitempty"`
	StableSide            bool                     `json:"stable_side,omitempty"`
	Predictive            *BurrowPredictiveOptions `json:"predictive,omitempty"`
	Birthday              *BurrowBirthdayOptions   `json:"birthday,omitempty"`
	NATProbe              *BurrowNATProbeOptions   `json:"nat_probe,omitempty"`
	MaxConcurrentAttempts int                      `json:"max_concurrent_attempts,omitempty"`

	// STUN configures the STUN servers for UDP hole punching. It is only used
	// when network contains "udp".
	STUN *BurrowSTUNOptions `json:"stun,omitempty"`

	// Password signs and verifies the proof carried by UDP hole punching
	// signaling messages (DIAL/READY). The signaling server requires a proof on
	// UDP signaling so that strangers cannot post messages into a room. It must
	// match the peer's password. Only used when network contains "udp"; TCP
	// hole punching does not need it.
	Password string `json:"password,omitempty"`

	// Network declares which tunnels this burrow inbound or outbound sets up:
	// "tcp" for TCP hole punching (the default) and "udp" for UDP hole punching,
	// used by UDP based inner protocols through a detour. Empty means ["tcp"].
	// TCP and UDP holes are different NAT mappings, so the inner protocol
	// decides which one is required: a UDP inner protocol reached through a
	// burrow detour needs network: ["udp"].
	Network badoption.Listable[string] `json:"network,omitempty"`
}

type BurrowInboundOptions struct {
	ServerOptions
	BurrowOptions
	Detour string `json:"detour,omitempty"`
	InboundOptions
}

type BurrowOutboundOptions struct {
	ServerOptions
	BurrowOptions
}
