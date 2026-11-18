package box

import "github.com/sagernet/sing-box/option"

// controlEndpoints lists the listen addresses of the core's own control APIs, which MITM
// internal rewrites must not reach.
func controlEndpoints(options option.ExperimentalOptions) []string {
	var endpoints []string
	if options.ClashAPI != nil {
		endpoints = append(endpoints, options.ClashAPI.ExternalController)
	}
	if options.V2RayAPI != nil {
		endpoints = append(endpoints, options.V2RayAPI.Listen)
	}
	if options.Debug != nil {
		endpoints = append(endpoints, options.Debug.Listen)
	}
	return endpoints
}

// listenPorts lists the fixed ports of the inbounds and services, which MITM internal
// rewrites aimed at this machine must not reach either.
func listenPorts(options option.Options) []int {
	var ports []int
	add := func(value any) {
		if wrapper, ok := value.(option.ListenOptionsWrapper); ok {
			if port := wrapper.TakeListenOptions().ListenPort; port != 0 {
				ports = append(ports, int(port))
			}
		}
	}
	for _, inbound := range options.Inbounds {
		add(inbound.Options)
	}
	for _, service := range options.Services {
		add(service.Options)
	}
	return ports
}
