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
