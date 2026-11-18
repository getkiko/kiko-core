package burrow

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/getkiko/burrow"
)

func TestApplySDKOptionsAddressFamily(t *testing.T) {
	options := option.BurrowOptions{AddressFamily: burrow.AddressFamilyIPv6}
	var config burrow.Config
	applySDKOptions(&config, options)
	if config.AddressFamily != burrow.AddressFamilyIPv6 {
		t.Fatalf("address family = %q", config.AddressFamily)
	}
}

func TestParseBurrowIPv6AddressFamily(t *testing.T) {
	raw := `{
		"type": "burrow",
		"tag": "burrow-warp",
		"server": "signal.example.com",
		"server_port": 443,
		"room": "warp-room",
		"network": ["tcp"],
		"bind_interface": "warp0",
		"address_family": "ipv6"
	}`
	var options option.BurrowOutboundOptions
	if err := json.Unmarshal([]byte(raw), &options); err != nil {
		t.Fatal(err)
	}
	if options.AddressFamily != burrow.AddressFamilyIPv6 {
		t.Fatalf("address_family = %q", options.AddressFamily)
	}
	if options.BindInterface != "warp0" {
		t.Fatalf("bind_interface = %q", options.BindInterface)
	}
}
