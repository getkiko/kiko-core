package option

type SmartOutboundOptions struct {
	Outbounds []string `json:"outbounds" reference:"outbound"`
	GroupHealthCheckOptions
	InterruptExistConnections bool `json:"interrupt_exist_connections,omitempty"`
}
