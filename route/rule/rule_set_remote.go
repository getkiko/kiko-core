package rule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	outbound       adapter.OutboundManager
	tag            string
	url            string
	urlHash        [32]byte
	initialPath    string
	options        option.RuleSet
	updateInterval time.Duration
	httpClient     *http.Client
	access         sync.RWMutex
	rules          []adapter.HeadlessRule
	metadata       adapter.RuleSetMetadata
	lastUpdated    time.Time
	lastUpdatedAt  atomic.Int64
	lastEtag       string
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
	callbacks      list.List[adapter.RuleSetUpdateCallback]
	refs           atomic.Int32
	// updateAccess (a semaphore, so waits can end with a context)
	// serializes downloads and loads of the source content, and guards
	// overrides, lastEtag and lastUpdated.
	updateAccess chan struct{}
	overrides    *option.RuleSetOverrides
	lastError    atomic.Pointer[string]
}

var (
	// remoteRuleSetUpdateTimeout bounds an update, waiting for a running
	// one included.
	remoteRuleSetUpdateTimeout = 60 * time.Second
	// remoteRuleSetReloadWait bounds the wait of a live apply for a running
	// update, within the client's live apply deadline.
	remoteRuleSetReloadWait = 10 * time.Second
)

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, tag string, options option.RuleSet) (*RemoteRuleSet, error) {
	ctx, cancel := context.WithCancel(ctx)
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	var initialPath string
	if options.RemoteOptions.InitialPath != "" {
		initialPath = filemanager.BasePath(ctx, strings.ReplaceAll(options.RemoteOptions.InitialPath, C.RuleSetTagPlaceholder, tag))
		initialPath, _ = filepath.Abs(initialPath)
	}
	url := strings.ReplaceAll(options.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
	return &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		tag:            tag,
		url:            url,
		urlHash:        sha256.Sum256([]byte(url)),
		initialPath:    initialPath,
		options:        options,
		overrides:      options.Overrides,
		updateAccess:   make(chan struct{}, 1),
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}, nil
}

func (s *RemoteRuleSet) Name() string {
	return s.tag
}

func (s *RemoteRuleSet) LastUpdatedAtMillis() int64 {
	return s.lastUpdatedAt.Load()
}

// LastError is the error of the last failed update, empty after a
// successful one.
func (s *RemoteRuleSet) LastError() string {
	if value := s.lastError.Load(); value != nil {
		return *value
	}
	return ""
}

func (s *RemoteRuleSet) setLastError(err error) {
	if err == nil {
		s.lastError.Store(nil)
		return
	}
	message := err.Error()
	s.lastError.Store(&message)
}

// lastUpdatedTime is lastUpdated without updateAccess.
func (s *RemoteRuleSet) lastUpdatedTime() time.Time {
	millis := s.lastUpdatedAt.Load()
	if millis == 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis)
}

func (s *RemoteRuleSet) setLastUpdated(value time.Time) {
	s.lastUpdated = value
	s.lastUpdatedAt.Store(value.UnixMilli())
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create rule-set http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if s.cacheFile != nil {
		savedSet := s.cacheFile.LoadRuleSet(s.tag)
		if savedSet != nil {
			if len(savedSet.URLHash) > 0 && !bytes.Equal(savedSet.URLHash, s.urlHash[:]) {
				s.logger.Info("cached rule-set was downloaded from another URL, will refetch")
			} else {
				err = s.loadBytes(savedSet.Content)
				if err != nil {
					s.logger.Warn(E.Cause(err, "restore cached rule-set, will refetch"))
				} else {
					s.setLastUpdated(savedSet.LastUpdated)
					s.lastEtag = savedSet.LastEtag
				}
			}
		}
	}
	var loadedFromInitialPath bool
	if s.lastUpdated.IsZero() && s.initialPath != "" {
		var content []byte
		content, err = filemanager.ReadFile(s.ctx, s.initialPath)
		if err == nil {
			err = s.loadBytes(content)
		}
		if err != nil {
			s.logger.Warn(E.Cause(err, "load initial rule-set from ", s.initialPath))
		} else {
			loadedFromInitialPath = true
		}
	}
	if s.lastUpdated.IsZero() && !loadedFromInitialPath {
		err = s.fetch(ctx, true)
		if err != nil {
			s.setLastError(err)
			return E.Cause(err, "initial rule-set: ", s.tag)
		}
	}
	return nil
}

func (s *RemoteRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *RemoteRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *RemoteRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *RemoteRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *RemoteRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) decodeContent(content []byte, recover bool) (option.PlainRuleSetCompat, error) {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.options.Format {
	case C.RuleSetFormatSource:
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(bytes.NewReader(content), recover)
	default:
		err = E.New("unknown rule-set format: ", s.options.Format)
	}
	if err != nil {
		return ruleSet, err
	}
	_, err = ruleSet.Upgrade()
	return ruleSet, err
}

// loadBytes loads downloaded or cached content with the current overrides;
// callers hold updateAccess.
func (s *RemoteRuleSet) loadBytes(content []byte) error {
	ruleSet, err := s.decodeContent(content, false)
	if err != nil {
		return err
	}
	rules, metadata, err := buildRuleSetRules(s.ctx, s.tag, ruleSet.Options.Rules, s.overrides)
	if err != nil {
		return err
	}
	s.access.Lock()
	s.metadata = metadata
	s.rules = rules
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

// savedContent is the content the rule set last loaded, from the cache
// file or the initial path; nil when neither holds it.
func (s *RemoteRuleSet) savedContent() []byte {
	if s.cacheFile != nil {
		savedSet := s.cacheFile.LoadRuleSet(s.tag)
		if savedSet != nil && len(savedSet.Content) > 0 && (len(savedSet.URLHash) == 0 || bytes.Equal(savedSet.URLHash, s.urlHash[:])) {
			return savedSet.Content
		}
	}
	if s.initialPath != "" {
		content, err := filemanager.ReadFile(s.ctx, s.initialPath)
		if err == nil {
			return content
		}
	}
	return nil
}

// lock takes updateAccess, giving up when ctx ends.
func (s *RemoteRuleSet) lock(ctx context.Context) error {
	select {
	case s.updateAccess <- struct{}{}:
		return nil
	case <-ctx.Done():
		return E.Cause(ctx.Err(), "rule-set ", s.tag, " is busy")
	}
}

func (s *RemoteRuleSet) tryLock() bool {
	select {
	case s.updateAccess <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *RemoteRuleSet) unlock() {
	<-s.updateAccess
}

// updateOnce runs a scheduled update; false when another operation holds
// the rule set and the update did not run.
func (s *RemoteRuleSet) updateOnce() bool {
	if !s.tryLock() {
		return false
	}
	defer s.unlock()
	ctx, cancel := context.WithTimeout(s.ctx, remoteRuleSetUpdateTimeout)
	defer cancel()
	err := s.fetch(ctx, false)
	s.setLastError(err)
	if err != nil {
		s.logger.Error("fetch rule-set ", s.tag, ": ", err)
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
	return true
}

// Update downloads the rule set now. Content the server reports unchanged
// counts as a successful update. Waiting for a running update counts
// towards the timeout.
func (s *RemoteRuleSet) Update(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, remoteRuleSetUpdateTimeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	if s.httpClient == nil {
		return E.New("rule-set ", s.tag, " is not started")
	}
	err = s.fetch(ctx, false)
	s.setLastError(err)
	if err != nil {
		s.logger.Error("fetch rule-set ", s.tag, ": ", err)
		return err
	}
	if s.refs.Load() == 0 {
		s.rules = nil
	}
	return nil
}

// HasSavedContent reports whether overrides can apply without a download.
// It reads the cache file and the initial path only, so it needs no lock.
func (s *RemoteRuleSet) HasSavedContent() bool {
	return s.savedContent() != nil
}

// ReloadOverrides applies new overrides to the saved content, as a live
// apply changes them. Without saved content it fails; the live apply asks
// for a restart instead (HasSavedContent).
func (s *RemoteRuleSet) ReloadOverrides(overrides *option.RuleSetOverrides) error {
	ctx, cancel := context.WithTimeout(s.ctx, remoteRuleSetReloadWait)
	defer cancel()
	err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer s.unlock()
	content := s.savedContent()
	if content == nil {
		return E.New("rule-set ", s.tag, " has no saved content")
	}
	previous := s.overrides
	s.overrides = overrides
	err = s.loadBytes(content)
	if err != nil {
		s.overrides = previous
	}
	return err
}

// SourceContent returns the saved content before the overrides apply.
func (s *RemoteRuleSet) SourceContent(ctx context.Context) (option.PlainRuleSetCompat, error) {
	err := s.lock(ctx)
	if err != nil {
		return option.PlainRuleSetCompat{}, err
	}
	content := s.savedContent()
	s.unlock()
	if content == nil {
		return option.PlainRuleSetCompat{}, ErrRuleSetNoContent
	}
	return s.decodeContent(content, true)
}

// fetch downloads the rule set; callers hold updateAccess.
func (s *RemoteRuleSet) fetch(ctx context.Context, isStart bool) error {
	s.logger.Debug("updating rule-set ", s.tag, " from URL: ", s.url)
	request, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	response, err := s.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.setLastUpdated(time.Now())
		if s.cacheFile != nil {
			savedRuleSet := s.cacheFile.LoadRuleSet(s.tag)
			if savedRuleSet != nil {
				savedRuleSet.LastUpdated = s.lastUpdated
				savedRuleSet.URLHash = s.urlHash[:]
				err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet)
				if err != nil {
					s.logger.Error("save rule-set updated time: ", err)
					return nil
				}
			}
		}
		s.logger.Info("update rule-set ", s.tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	err = s.loadBytes(content)
	if err != nil {
		return err
	}
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.setLastUpdated(time.Now())
	if s.cacheFile != nil {
		err = s.cacheFile.SaveRuleSet(s.tag, &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			Content:     content,
			LastEtag:    s.lastEtag,
			URLHash:     s.urlHash[:],
		})
		if err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.Info("updated rule-set ", s.tag)
	return nil
}

func (s *RemoteRuleSet) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.options.RemoteOptions.HTTPClient != nil && !s.options.RemoteOptions.HTTPClient.IsEmpty() {
		if s.options.RemoteOptions.DownloadDetour != "" { //nolint:staticcheck
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.options.RemoteOptions.HTTPClient)
	}
	if s.options.RemoteOptions.DownloadDetour != "" { //nolint:staticcheck
		deprecated.Report(s.ctx, deprecated.OptionLegacyRuleSetDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.options.RemoteOptions.DownloadDetour, //nolint:staticcheck
			},
			DisableEmptyDirectCheck: true,
		})
	}
	defaultTransport := httpClientManager.DefaultTransport()
	if defaultTransport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return defaultTransport, nil
}

func (s *RemoteRuleSet) Close() error {
	s.rules = nil
	s.cancel()
	return nil
}

func (s *RemoteRuleSet) Match(metadata *adapter.InboundContext) bool {
	return matchAnyHeadlessRule(s.rules, metadata)
}

func (s *RemoteRuleSet) mergeableRule() *DefaultHeadlessRule {
	return mergeableRuleIn(s.rules)
}
