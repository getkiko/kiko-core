package burrow

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/getkiko/burrow"
)

// networkList: empty becomes ["tcp"]; explicit values are kept.
func TestNetworkListDefaultsToTCP(t *testing.T) {
	if got := networkList(nil); len(got) != 1 || got[0] != "tcp" {
		t.Fatalf("networkList(nil) = %v, want [tcp]", got)
	}
	if got := networkList([]string{"udp"}); len(got) != 1 || got[0] != "udp" {
		t.Fatalf("networkList([udp]) = %v, want [udp]", got)
	}
	if got := networkList([]string{"tcp", "udp"}); len(got) != 2 {
		t.Fatalf("networkList([tcp udp]) = %v, want len 2", got)
	}
}

// applyPacketSDKOptions maps the common fields and STUN to burrow.PacketConfig.
func TestApplyPacketSDKOptions(t *testing.T) {
	opts := option.BurrowOptions{
		Room:       "cap-room",
		Mode:       "header",
		Strategy:   "predictive",
		StableSide: true,
		Predictive: &option.BurrowPredictiveOptions{PortScanRange: 512, Concurrency: 64},
		STUN: &option.BurrowSTUNOptions{
			Servers: []string{"stun://stun.miwifi.com:3478"},
			Timeout: badoption.Duration(3 * time.Second),
		},
	}
	var cfg burrow.PacketConfig
	applyPacketSDKOptions(&cfg, opts)

	if cfg.Room != "cap-room" || cfg.Mode != "header" {
		t.Fatalf("room/mode not mapped: %+v", cfg)
	}
	if cfg.Strategy != burrow.Strategy("predictive") || !cfg.StableSide {
		t.Fatalf("strategy/stableSide not mapped: %+v", cfg)
	}
	if cfg.Predictive.PortScanRange != 512 || cfg.Predictive.Concurrency != 64 {
		t.Fatalf("predictive not mapped: %+v", cfg.Predictive)
	}
	if len(cfg.STUN.Servers) != 1 || cfg.STUN.Servers[0] != "stun://stun.miwifi.com:3478" {
		t.Fatalf("stun servers not mapped: %+v", cfg.STUN)
	}
	if cfg.STUN.Timeout != 3*time.Second {
		t.Fatalf("stun timeout not mapped: %v", cfg.STUN.Timeout)
	}
}

// A UDP burrow outbound configuration (network and stun) parses with the real
// options.
func TestParseUDPBurrowOutboundConfig(t *testing.T) {
	raw := `{
		"type": "burrow",
		"tag": "burrow-udp-out",
		"server": "wss://signal.example.com",
		"server_port": 443,
		"room": "cap-room",
		"strategy": "predictive",
		"stable_side": false,
		"predictive": { "port_scan_range": 512, "concurrency": 64 },
		"stun": { "servers": ["stun://stun.miwifi.com:3478"], "timeout": "3s" },
		"network": ["udp"]
	}`
	var opts option.BurrowOutboundOptions
	if err := json.Unmarshal([]byte(raw), &opts); err != nil {
		t.Fatalf("parse UDP burrow outbound: %v", err)
	}
	if len(opts.Network) != 1 || opts.Network[0] != "udp" {
		t.Fatalf("network not parsed: %v", opts.Network)
	}
	if opts.STUN == nil || len(opts.STUN.Servers) != 1 {
		t.Fatalf("stun not parsed: %+v", opts.STUN)
	}
	if opts.Predictive == nil || opts.Predictive.PortScanRange != 512 {
		t.Fatalf("predictive not parsed: %+v", opts.Predictive)
	}
}

// With UDP hole punching configured, DialContext(UDP) no longer returns
// os.ErrInvalid but enters the punch flow (which fails here because the
// signaling server is unreachable, but never with os.ErrInvalid). Without UDP it
// still returns os.ErrInvalid. The test builds the Outbound directly, skipping
// the NetworkManager dependency of NewOutbound, with burrow.NewPacketDialer.
func TestDialContextUDPNoLongerErrInvalid(t *testing.T) {
	packetDialer, err := burrow.NewPacketDialer(burrow.PacketConfig{
		SignalAddr: "ws://127.0.0.1:1/signal", // unreachable, so punching fails
		Room:       "t",
		Strategy:   burrow.Strategy("predictive"),
		Predictive: burrow.PredictiveOptions{PortScanRange: 16, Concurrency: 4},
		STUN:       burrow.STUNOptions{Servers: []string{"stun://127.0.0.1:1"}},
	})
	if err != nil {
		t.Fatalf("NewPacketDialer: %v", err)
	}
	defer packetDialer.Close()

	// Without UDP, packetDialer is nil and DialContext(UDP) returns os.ErrInvalid.
	tcpOnly := &Outbound{logger: log.NewNOPFactory().NewLogger("")}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := tcpOnly.DialContext(ctx, N.NetworkUDP, M.Socksaddr{}); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("without UDP, DialContext(UDP) must return os.ErrInvalid, got %v", err)
	}

	// With UDP, DialContext(UDP) punches and fails, but not with os.ErrInvalid.
	udpOut := &Outbound{logger: log.NewNOPFactory().NewLogger(""), packetDialer: packetDialer}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, err = udpOut.DialContext(ctx2, N.NetworkUDP, M.ParseSocksaddr("127.0.0.1:1"))
	if err == nil {
		t.Fatal("punching cannot succeed with an unreachable signaling server, expected an error")
	}
	if errors.Is(err, os.ErrInvalid) {
		t.Fatalf("with UDP, DialContext(UDP) must not return os.ErrInvalid, got %v", err)
	}
	t.Logf("DialContext(UDP) punched and failed as expected (not ErrInvalid): %v", err)
}
