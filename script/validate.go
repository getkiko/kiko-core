package script

import (
	"regexp"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidTag reports whether tag is acceptable as a script tag.
func ValidTag(tag string) bool {
	return tag != "" && len(tag) <= MaxTagLength && tagPattern.MatchString(tag)
}

// validateConfig checks cfg and fills the defaults of MaxSize and Timeout.
func validateConfig(cfg *Config) error {
	if !ValidTag(cfg.Tag) {
		return E.New("tag must be 1-", MaxTagLength, " characters of A-Z a-z 0-9 . _ -")
	}
	switch cfg.Type {
	case PhaseRequest, PhaseResponse:
		if strings.TrimSpace(cfg.Pattern) == "" {
			return E.New("pattern is required")
		}
		if len(cfg.Pattern) > MaxPatternLength {
			return E.New("pattern too long")
		}
	case PhaseGeneric:
		if cfg.Pattern != "" {
			return E.New("generic scripts take no pattern")
		}
	case PhaseCron:
		if cfg.Pattern != "" {
			return E.New("cron scripts take no pattern")
		}
		if strings.TrimSpace(cfg.Cron) == "" {
			return E.New("cron is required")
		}
		if err := ValidCron(cfg.Cron); err != nil {
			return E.New("invalid cron: ", err.Error())
		}
	case PhaseRule, PhaseDNS:
		if cfg.Pattern != "" {
			return E.New(string(cfg.Type), " scripts take no pattern")
		}
		if cfg.RequiresBody || cfg.BinaryBody {
			return E.New(string(cfg.Type), " scripts take no body")
		}
	default:
		return E.New("unknown type: ", string(cfg.Type))
	}
	if cfg.Cron != "" && cfg.Type != PhaseCron {
		return E.New("cron is only for cron scripts")
	}
	if len(cfg.Source) > MaxSourceSize {
		return E.New("source larger than ", MaxSourceSize>>20, " MiB")
	}
	if err := CheckSource(cfg.Source, ScriptLimits); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Source) == "" {
		return E.New("source is empty")
	}
	if len(cfg.Argument) > MaxArgumentSize {
		return E.New("argument too long")
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.MaxSize < 0 || cfg.MaxSize > MaxMaxSize {
		return E.New("max_size must be between 1 and ", MaxMaxSize, " bytes")
	}
	def, limit := DefaultTimeout, MaxTimeout
	if cfg.Type == PhaseGeneric || cfg.Type == PhaseCron {
		def, limit = DefaultGenericTimeout, MaxGenericTimeout
	}
	if cfg.Type == PhaseRule || cfg.Type == PhaseDNS {
		def, limit = DefaultRuleTimeout, MaxRuleTimeout
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = def
	}
	if cfg.Timeout < 0 || cfg.Timeout > limit {
		return E.New("timeout must be positive and at most ", limit)
	}
	return nil
}

// MaxSourceDepth bounds the bracket nesting of a script.
const MaxSourceDepth = 2000

// MaxArrayLength is the longest array native methods accept (sparse or not): they walk or
// copy the whole length without an interrupt check.
const MaxArrayLength = AllocationLimit / 16
