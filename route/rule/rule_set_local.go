package rule

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/filemanager"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	ctx        context.Context
	logger     logger.Logger
	tag        string
	access     sync.RWMutex
	rules      []adapter.HeadlessRule
	metadata   adapter.RuleSetMetadata
	fileFormat string
	filePath   string
	watcher    *fswatch.Watcher
	// sourceAccess serializes loads of the source content and guards
	// inlineRules and overrides.
	sourceAccess sync.Mutex
	inlineRules  []option.HeadlessRule
	overrides    *option.RuleSetOverrides
	lastError    atomic.Pointer[string]
	callbacks    list.List[adapter.RuleSetUpdateCallback]
	refs         atomic.Int32
}

func NewLocalRuleSet(ctx context.Context, logger logger.Logger, tag string, options option.RuleSet) (*LocalRuleSet, error) {
	ruleSet := &LocalRuleSet{
		ctx:        ctx,
		logger:     logger,
		tag:        tag,
		fileFormat: options.Format,
		overrides:  options.Overrides,
	}
	if options.Type == C.RuleSetTypeInline {
		if len(options.InlineOptions.Rules) == 0 {
			return nil, E.New("empty inline rule-set")
		}
		ruleSet.inlineRules = options.InlineOptions.Rules
		err := ruleSet.reloadRules(options.InlineOptions.Rules)
		if err != nil {
			return nil, err
		}
	} else {
		filePath := filemanager.BasePath(ctx, strings.ReplaceAll(options.LocalOptions.Path, C.RuleSetTagPlaceholder, tag))
		filePath, _ = filepath.Abs(filePath)
		ruleSet.filePath = filePath
		err := ruleSet.reloadFile(filePath)
		if err != nil {
			return nil, err
		}
		watcher, err := fswatch.NewWatcher(fswatch.Options{
			Path: []string{filePath},
			Callback: func(path string) {
				ruleSet.sourceAccess.Lock()
				defer ruleSet.sourceAccess.Unlock()
				uErr := ruleSet.reloadFile(path)
				ruleSet.setLastError(uErr)
				if uErr != nil {
					logger.Error(E.Cause(uErr, "reload rule-set ", tag))
				}
			},
		})
		if err != nil {
			return nil, err
		}
		ruleSet.watcher = watcher
	}
	return ruleSet, nil
}

func (s *LocalRuleSet) Name() string {
	return s.tag
}

func (s *LocalRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	if s.watcher != nil {
		err := s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch rule-set file"))
		}
	}
	return nil
}

// IsInline reports whether the rule set holds inline rules.
func (s *LocalRuleSet) IsInline() bool {
	return s.filePath == ""
}

func (s *LocalRuleSet) reloadFile(path string) error {
	ruleSet, err := s.readFile(path, false)
	if err != nil {
		return err
	}
	return s.reloadRules(ruleSet.Options.Rules)
}

// readFile decodes the rule set file; recover keeps the domain and address
// lists of binary files, as the source content view needs them.
func (s *LocalRuleSet) readFile(path string, recover bool) (option.PlainRuleSetCompat, error) {
	var ruleSet option.PlainRuleSetCompat
	switch s.fileFormat {
	case C.RuleSetFormatSource, "":
		content, err := filemanager.ReadFile(s.ctx, path)
		if err != nil {
			return ruleSet, err
		}
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return ruleSet, err
		}
	case C.RuleSetFormatBinary:
		setFile, err := filemanager.Open(s.ctx, path)
		if err != nil {
			return ruleSet, err
		}
		defer setFile.Close()
		ruleSet, err = srs.Read(setFile, recover)
		if err != nil {
			return ruleSet, err
		}
	default:
		return ruleSet, E.New("unknown rule-set format: ", s.fileFormat)
	}
	_, err := ruleSet.Upgrade()
	return ruleSet, err
}

// reloadRules loads source rules with the current overrides; callers hold
// sourceAccess or own the rule set exclusively.
func (s *LocalRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
	rules, metadata, err := buildRuleSetRules(s.ctx, s.tag, headlessRules, s.overrides)
	if err != nil {
		return err
	}
	s.access.Lock()
	s.rules = rules
	s.metadata = metadata
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

// ReloadInline replaces the rules and overrides of an inline rule set, as a
// live apply changes them.
func (s *LocalRuleSet) ReloadInline(rules []option.HeadlessRule, overrides *option.RuleSetOverrides) error {
	if len(rules) == 0 {
		return E.New("empty inline rule-set")
	}
	if !s.IsInline() {
		return E.New("rule-set ", s.tag, " is not inline")
	}
	s.sourceAccess.Lock()
	defer s.sourceAccess.Unlock()
	return s.withOverrides(overrides, func() error {
		err := s.reloadRules(rules)
		if err == nil {
			s.inlineRules = rules
		}
		return err
	})
}

// ReloadOverrides applies new overrides to the current source content, as
// a live apply changes them.
func (s *LocalRuleSet) ReloadOverrides(overrides *option.RuleSetOverrides) error {
	s.sourceAccess.Lock()
	defer s.sourceAccess.Unlock()
	return s.withOverrides(overrides, func() error {
		if s.IsInline() {
			return s.reloadRules(s.inlineRules)
		}
		return s.reloadFile(s.filePath)
	})
}

// withOverrides runs load with overrides in effect, restoring the previous
// ones when it fails.
func (s *LocalRuleSet) withOverrides(overrides *option.RuleSetOverrides, load func() error) error {
	previous := s.overrides
	s.overrides = overrides
	err := load()
	if err != nil {
		s.overrides = previous
	}
	return err
}

// Update reads the rule set file again.
func (s *LocalRuleSet) Update(ctx context.Context) error {
	if s.IsInline() {
		return E.New("inline rule-set cannot be updated")
	}
	s.sourceAccess.Lock()
	defer s.sourceAccess.Unlock()
	err := s.reloadFile(s.filePath)
	s.setLastError(err)
	return err
}

// LastError is the error of the last failed read of the file, empty after
// a successful one.
func (s *LocalRuleSet) LastError() string {
	if value := s.lastError.Load(); value != nil {
		return *value
	}
	return ""
}

func (s *LocalRuleSet) setLastError(err error) {
	if err == nil {
		s.lastError.Store(nil)
		return
	}
	message := err.Error()
	s.lastError.Store(&message)
}

// SourceContent returns the rules before the overrides apply.
func (s *LocalRuleSet) SourceContent(ctx context.Context) (option.PlainRuleSetCompat, error) {
	if s.IsInline() {
		s.sourceAccess.Lock()
		rules := s.inlineRules
		s.sourceAccess.Unlock()
		return option.PlainRuleSetCompat{
			Version: C.RuleSetVersionCurrent,
			Options: option.PlainRuleSet{Rules: rules},
		}, nil
	}
	return s.readFile(s.filePath, true)
}

func (s *LocalRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *LocalRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *LocalRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *LocalRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *LocalRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *LocalRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *LocalRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *LocalRuleSet) Close() error {
	s.rules = nil
	return common.Close(common.PtrOrNil(s.watcher))
}

func (s *LocalRuleSet) Match(metadata *adapter.InboundContext) bool {
	return matchAnyHeadlessRule(s.rules, metadata)
}

func (s *LocalRuleSet) mergeableRule() *DefaultHeadlessRule {
	return mergeableRuleIn(s.rules)
}
