package burrow

import (
	"fmt"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/getkiko/burrow"
)

func sdkDebugLog(logger log.ContextLogger) burrow.DebugLogFunc {
	return func(format string, args ...any) {
		logger.Debug("[burrow] ", fmt.Sprintf(format, args...))
	}
}

func sdkInfoLog(logger log.ContextLogger) burrow.LogFunc {
	return func(format string, args ...any) {
		logger.Info("[burrow] ", fmt.Sprintf(format, args...))
	}
}

func applySDKOptions(config *burrow.Config, options option.BurrowOptions) {
	config.Room = options.Room
	config.Mode = options.Mode
	config.BindInterface = options.BindInterface
	config.AddressFamily = options.AddressFamily
	config.PairTimeout = time.Duration(options.PairTimeout)
	config.PortScanRange = options.PortScanRange
	config.Strategy = burrow.Strategy(options.Strategy)
	config.StableSide = options.StableSide
	config.MaxConcurrentAttempts = options.MaxConcurrentAttempts

	if predictive := options.Predictive; predictive != nil {
		config.Predictive = burrow.PredictiveOptions{
			PortScanRange:  predictive.PortScanRange,
			Concurrency:    predictive.Concurrency,
			AttemptTimeout: time.Duration(predictive.AttemptTimeout),
		}
	}
	if birthday := options.Birthday; birthday != nil {
		config.Birthday = burrow.BirthdayOptions{
			Selection:            burrow.CandidateSelection(birthday.Selection),
			Candidates:           birthday.Candidates,
			MinPort:              birthday.MinPort,
			MaxPort:              birthday.MaxPort,
			Warmup:               time.Duration(birthday.Warmup),
			AttemptTimeout:       time.Duration(birthday.AttemptTimeout),
			SuccessGrace:         time.Duration(birthday.SuccessGrace),
			MaxSuccessCandidates: birthday.MaxSuccessCandidates,
		}
	}
	if natProbe := options.NATProbe; natProbe != nil {
		config.NATProbe = burrow.NATProbeOptions{
			Targets:        append([]string(nil), natProbe.Targets...),
			InitialSamples: natProbe.InitialSamples,
			MaxSamples:     natProbe.MaxSamples,
			Timeout:        time.Duration(natProbe.Timeout),
			CacheTTL:       time.Duration(natProbe.CacheTTL),
		}
	}
}

// applyPacketSDKOptions maps the common burrow options to the UDP hole punching
// burrow.PacketConfig. It mirrors applySDKOptions (TCP): the SDK does not share
// a sub-struct for the common fields, so both are filled separately. Only
// direct and predictive apply; the SDK rejects birthday and auto with an
// explicit error, so they are passed through unchanged here.
func applyPacketSDKOptions(config *burrow.PacketConfig, options option.BurrowOptions) {
	config.Room = options.Room
	config.Mode = options.Mode
	config.BindInterface = options.BindInterface
	config.PairTimeout = time.Duration(options.PairTimeout)
	config.Strategy = burrow.Strategy(options.Strategy)
	config.StableSide = options.StableSide
	config.MaxConcurrentAttempts = options.MaxConcurrentAttempts

	if predictive := options.Predictive; predictive != nil {
		config.Predictive = burrow.PredictiveOptions{
			PortScanRange:  predictive.PortScanRange,
			Concurrency:    predictive.Concurrency,
			AttemptTimeout: time.Duration(predictive.AttemptTimeout),
		}
	}
	if birthday := options.Birthday; birthday != nil {
		config.Birthday = burrow.BirthdayOptions{
			Selection:            burrow.CandidateSelection(birthday.Selection),
			Candidates:           birthday.Candidates,
			MinPort:              birthday.MinPort,
			MaxPort:              birthday.MaxPort,
			Warmup:               time.Duration(birthday.Warmup),
			AttemptTimeout:       time.Duration(birthday.AttemptTimeout),
			SuccessGrace:         time.Duration(birthday.SuccessGrace),
			MaxSuccessCandidates: birthday.MaxSuccessCandidates,
		}
	}
	if stun := options.STUN; stun != nil {
		config.STUN = burrow.STUNOptions{
			Servers:        append([]string(nil), stun.Servers...),
			InitialSamples: stun.InitialSamples,
			MaxSamples:     stun.MaxSamples,
			Timeout:        time.Duration(stun.Timeout),
			CacheTTL:       time.Duration(stun.CacheTTL),
		}
	}
	// UDP signaling proof: derive the sign and verify hooks from the shared
	// password. Without a password no hooks are set and the SDK sends no proof,
	// but the signaling server rejects a UDP DIAL without one, so UDP hole
	// punching requires a password.
	if options.Password != "" {
		config.SignProof = burrow.NewProofSigner(options.Password)
		config.VerifyProof = burrow.NewProofVerifier(options.Password)
	}
}

// networkList normalizes the network declaration of a burrow inbound or
// outbound. Empty means ["tcp"].
func networkList(configured []string) []string {
	if len(configured) == 0 {
		return []string{"tcp"}
	}
	return append([]string(nil), configured...)
}
