package daemon

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/script"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	// scriptEvaluateSlots bounds the dry runs in progress; the runtime's own semaphore bounds
	// the scripts executing at once.
	scriptEvaluateSlots = 8
	scriptStreamSlots   = 16
	// scriptEvaluateBytes bounds the messages of one dry run (the server accepts 9 MiB).
	scriptEvaluateBytes = 8 << 20
	// scriptListValueBytes is how much of a value StoreList returns.
	scriptListValueBytes = 4 << 10
	scriptStoreEntries   = 100000
	// scriptStaleCheck is how often a stream checks that its hub is still the current one.
	scriptStaleCheck = 2 * time.Second
)

// ScriptProvider returns the script runtime of the running core, or nil while none is
// running.
type ScriptProvider interface {
	ScriptRuntime() (*script.Manager, *script.Hub)
}

// ScriptProviderFunc adapts a function to ScriptProvider.
type ScriptProviderFunc func() (*script.Manager, *script.Hub)

func (f ScriptProviderFunc) ScriptRuntime() (*script.Manager, *script.Hub) { return f() }

// ScriptRuntime returns the script manager and hub of the running core, or nils while the
// core is stopped.
func (s *StartedService) ScriptRuntime() (*script.Manager, *script.Hub) {
	s.serviceAccess.RLock()
	instance := s.instance
	s.serviceAccess.RUnlock()
	if instance == nil {
		return nil, nil
	}
	engine := service.FromContext[adapter.MITMEngine](instance.ctx)
	if engine == nil {
		return nil, nil
	}
	provider, ok := engine.(adapter.MITMScriptProvider)
	if !ok {
		return nil, nil
	}
	return provider.Scripts(), provider.ScriptHub()
}

type scriptServer struct {
	mitmapi.UnimplementedScriptServer
	provider ScriptProvider
	eval     chan struct{}
	streams  chan struct{}
}

// RegisterScript serves the Script service from the runtime the provider returns. Like the
// MITM service it belongs on the loopback API service; every method refuses a peer that is
// not loopback, a unix socket or TLS.
func RegisterScript(server *grpc.Server, provider ScriptProvider) {
	mitmapi.RegisterScriptServer(server, newScriptServer(provider))
}

func newScriptServer(provider ScriptProvider) *scriptServer {
	return &scriptServer{
		provider: provider,
		eval:     make(chan struct{}, scriptEvaluateSlots),
		streams:  make(chan struct{}, scriptStreamSlots),
	}
}

func (s *scriptServer) runtime(ctx context.Context) (*script.Manager, *script.Hub, error) {
	if !trustedAuthorityPeer(ctx) {
		return nil, nil, status.Error(codes.PermissionDenied, "scripts are served only to a loopback or unix socket peer, or over TLS")
	}
	manager, hub := s.provider.ScriptRuntime()
	if manager == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "core is stopped")
	}
	return manager, hub, nil
}

func scriptTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func toLogLines(lines []script.LogLine) []*mitmapi.ScriptLogLine {
	out := make([]*mitmapi.ScriptLogLine, len(lines))
	for i, line := range lines {
		out[i] = &mitmapi.ScriptLogLine{Level: line.Level, Message: line.Message, TimeMs: scriptTime(line.Time)}
	}
	return out
}

func toNotification(seq uint64, n script.Notification) *mitmapi.ScriptNotification {
	return &mitmapi.ScriptNotification{
		Seq: seq, Script: n.Script, Title: n.Title, Subtitle: n.Subtitle, Body: n.Body, Url: n.URL, TimeMs: scriptTime(n.Time),
	}
}

func scriptHeaders(headers []*mitmapi.ScriptHeader) []script.Header {
	out := make([]script.Header, len(headers))
	for i, h := range headers {
		out[i] = script.Header{Name: h.GetName(), Value: h.GetValue()}
	}
	return out
}

func protoHeaders(headers []script.Header) []*mitmapi.ScriptHeader {
	out := make([]*mitmapi.ScriptHeader, len(headers))
	for i, h := range headers {
		out[i] = &mitmapi.ScriptHeader{Name: h.Name, Value: h.Value}
	}
	return out
}

// storeTarget maps the key of $persistentStore of a script to its namespace and key.
func storeTarget(tag, key string) (string, string) {
	if strings.HasPrefix(key, script.SharedPrefix) {
		return script.SharedNamespace, key[len(script.SharedPrefix):]
	}
	return tag, key
}

func validNamespace(namespace string) bool {
	return namespace == script.SharedNamespace || script.ValidTag(namespace)
}

func (s *scriptServer) Evaluate(ctx context.Context, request *mitmapi.ScriptEvaluateRequest) (*mitmapi.ScriptEvaluateResponse, error) {
	manager, _, err := s.runtime(ctx)
	if err != nil {
		return nil, err
	}
	if len(request.Source) > script.MaxSourceSize {
		return nil, status.Error(codes.InvalidArgument, "source larger than 1 MiB")
	}
	if request.TimeoutMs < 0 || request.MaxSize < 0 {
		return nil, status.Error(codes.InvalidArgument, "timeout_ms and max_size must not be negative")
	}
	phase := script.Phase(request.Type)
	switch phase {
	case script.PhaseRequest, script.PhaseResponse, script.PhaseGeneric, script.PhaseCron, script.PhaseRule, script.PhaseDNS:
	default:
		return nil, status.Error(codes.InvalidArgument, "type must be http-request, http-response, generic, cron, rule or dns")
	}
	size := len(request.GetRequest().GetBody()) + len(request.GetResponse().GetBody())
	for _, entry := range request.Store {
		size += len(entry.Key) + len(entry.Value)
	}
	if size > scriptEvaluateBytes {
		return nil, status.Error(codes.InvalidArgument, "request larger than 8 MiB")
	}
	select {
	case s.eval <- struct{}{}:
		defer func() { <-s.eval }()
	default:
		return nil, status.Error(codes.ResourceExhausted, "too many dry runs in progress")
	}

	tag := request.Tag
	if tag == "" {
		tag = "eval"
	}
	cfg := script.Config{
		Tag:          tag,
		Type:         phase,
		Pattern:      request.Pattern,
		Source:       request.Source,
		RequiresBody: request.RequiresBody,
		BinaryBody:   request.BinaryBody,
		MaxSize:      request.MaxSize,
		Timeout:      time.Duration(request.TimeoutMs) * time.Millisecond,
		Argument:     request.Argument,
	}
	if cfg.BinaryBody && !cfg.RequiresBody {
		return nil, status.Error(codes.InvalidArgument, "binary_body needs requires_body")
	}
	if !script.ValidTag(tag) {
		return nil, status.Error(codes.InvalidArgument, "invalid tag")
	}
	maxSize := cfg.MaxSize
	if maxSize == 0 {
		maxSize = script.DefaultMaxSize
	}

	seed := script.NewMemoryStore()
	seeded := map[string]string{}
	for _, entry := range request.Store {
		ns, key := storeTarget(tag, entry.Key)
		if err := seed.Set(ns, key, entry.Value); err != nil {
			return nil, status.Error(codes.InvalidArgument, "store: "+err.Error())
		}
		seeded[ns+"\x00"+key] = entry.Value
	}

	in := &script.Input{}
	var original struct {
		url    string
		status int
		header []script.Header
		length int
	}
	ruleScript := phase == script.PhaseRule || phase == script.PhaseDNS
	if ruleScript {
		if cfg.RequiresBody || cfg.BinaryBody || cfg.Pattern != "" {
			return nil, status.Error(codes.InvalidArgument, "rule and dns scripts take no pattern and no body")
		}
		rule := request.GetRule()
		in.Rule = &script.RuleInput{
			Domain: rule.GetDomain(), IP: rule.GetIp(), Port: uint16(min(rule.GetPort(), 65535)), Network: rule.GetNetwork(),
			Protocol: rule.GetProtocol(), Inbound: rule.GetInbound(), InboundType: rule.GetInboundType(),
			SourceIP: rule.GetSourceIp(), ProcessName: rule.GetProcessName(), ProcessPath: rule.GetProcessPath(),
			User: rule.GetUser(), QueryType: rule.GetQueryType(),
		}
	} else if phase != script.PhaseGeneric && phase != script.PhaseCron {
		message := request.GetRequest()
		req := &script.Request{URL: message.GetUrl(), Method: message.GetMethod(), Headers: scriptHeaders(message.GetHeaders()), ID: "eval"}
		in.Request = req
		original.url = req.URL
		if phase == script.PhaseRequest {
			original.header = req.Headers
			if cfg.RequiresBody && message.GetHasBody() {
				if int64(len(message.Body)) > maxSize {
					return skippedEvaluation("size"), nil
				}
				req.Body, req.HasBody = message.Body, true
				original.length = len(req.Body)
			}
		} else {
			message := request.GetResponse()
			resp := &script.Response{Status: int(message.GetStatus()), Headers: scriptHeaders(message.GetHeaders())}
			if resp.Status == 0 {
				resp.Status = 200
			}
			if cfg.RequiresBody && message.GetHasBody() {
				if int64(len(message.Body)) > maxSize {
					return skippedEvaluation("size"), nil
				}
				resp.Body, resp.HasBody = message.Body, true
				original.length = len(resp.Body)
			}
			in.Response = resp
			original.status = resp.Status
			original.header = resp.Headers
		}
	}

	result, err := manager.Evaluate(ctx, cfg, in, seed)
	if err != nil {
		return &mitmapi.ScriptEvaluateResponse{Action: string(script.ActionError), Error: err.Error(), ErrorKind: "compile"}, nil
	}
	response := &mitmapi.ScriptEvaluateResponse{
		Action:         string(result.Action),
		Reason:         result.Reason,
		Error:          result.Error,
		DurationUs:     result.Duration.Microseconds(),
		Logs:           toLogLines(result.Logs),
		Url:            result.URL,
		HeadersChanged: result.HeadersChanged,
		BodyChanged:    result.BodyChanged,
		Status:         int32(result.Status),
		Output:         result.Output,
	}
	if result.HeadersChanged {
		response.Headers = protoHeaders(result.Headers)
	}
	if result.BodyChanged {
		response.Body = result.Body
	}
	if result.Response != nil {
		response.Response = &mitmapi.ScriptResponseMessage{
			Status: int32(result.Response.Status), Headers: protoHeaders(result.Response.Headers),
			Body: result.Response.Body, HasBody: result.Response.HasBody,
		}
	}
	for _, n := range result.Notifications {
		response.Notifications = append(response.Notifications, toNotification(0, n))
	}
	if ruleScript && result.Action == script.ActionNone {
		var decisionErr error
		response.Decision, decisionErr = ruleDecision(phase, result.Output)
		if decisionErr != nil {
			response.Error = decisionErr.Error()
		}
	}
	response.Changes = evaluateChanges(result, original.url, original.status, original.header, original.length, seed, seeded)
	return response, nil
}

// ruleDecision renders what the host makes of the output of a rule or dns script.
func ruleDecision(phase script.Phase, output string) (string, error) {
	if phase == script.PhaseRule {
		matched, err := script.ParseRuleOutput(output)
		if err != nil {
			return "", err
		}
		if matched {
			return "true", nil
		}
		return "false", nil
	}
	decision, err := script.ParseDNSOutput(output)
	if err != nil {
		return "", err
	}
	return decision.Summary(), nil
}

func skippedEvaluation(reason string) *mitmapi.ScriptEvaluateResponse {
	return &mitmapi.ScriptEvaluateResponse{Action: string(script.ActionSkipped), Reason: reason}
}

// evaluateChanges describes what a dry run changed: the URL, the status, the headers, the
// body (as byte lengths) and the $persistentStore entries.
func evaluateChanges(result *script.Result, url string, statusCode int, headers []script.Header, bodyLength int, store *script.MemoryStore, seeded map[string]string) []*mitmapi.ScriptChange {
	var changes []*mitmapi.ScriptChange
	if result.Action != script.ActionModify && result.Action != script.ActionNone && result.Action != script.ActionRespond {
		return nil
	}
	if result.Action != script.ActionRespond {
		if result.URL != "" && result.URL != url {
			changes = append(changes, &mitmapi.ScriptChange{Kind: "url", Op: "set", Name: "url", Before: url, HadBefore: url != "", After: result.URL, HasAfter: true})
		}
		if result.Status != 0 && result.Status != statusCode {
			changes = append(changes, &mitmapi.ScriptChange{Kind: "status", Op: "set", Name: "status", Before: strconv.Itoa(statusCode), HadBefore: statusCode != 0, After: strconv.Itoa(result.Status), HasAfter: true})
		}
		if result.HeadersChanged {
			changes = append(changes, headerDiff(headers, result.Headers)...)
		}
		if result.BodyChanged {
			changes = append(changes, &mitmapi.ScriptChange{Kind: "body", Op: "set", Name: "body", Before: strconv.Itoa(bodyLength), HadBefore: true, After: strconv.Itoa(len(result.Body)), HasAfter: true})
		}
	}
	return append(changes, storeDiff(store, seeded)...)
}

// headerDiff lists the header names whose value differs, case-insensitively; several values
// of a name are joined by ", " as scripts see them.
func headerDiff(before, after []script.Header) []*mitmapi.ScriptChange {
	join := func(list []script.Header) (map[string]string, []string) {
		values := map[string]string{}
		var order []string
		for _, h := range list {
			key := strings.ToLower(h.Name)
			if old, ok := values[key]; ok {
				values[key] = old + ", " + h.Value
			} else {
				values[key] = h.Value
				order = append(order, h.Name)
			}
		}
		return values, order
	}
	oldValues, oldOrder := join(before)
	newValues, newOrder := join(after)
	var changes []*mitmapi.ScriptChange
	for _, name := range oldOrder {
		key := strings.ToLower(name)
		if value, ok := newValues[key]; !ok {
			changes = append(changes, &mitmapi.ScriptChange{Kind: "header", Op: "remove", Name: name, Before: oldValues[key], HadBefore: true})
		} else if value != oldValues[key] {
			changes = append(changes, &mitmapi.ScriptChange{Kind: "header", Op: "set", Name: name, Before: oldValues[key], HadBefore: true, After: value, HasAfter: true})
		}
	}
	for _, name := range newOrder {
		key := strings.ToLower(name)
		if _, ok := oldValues[key]; !ok {
			changes = append(changes, &mitmapi.ScriptChange{Kind: "header", Op: "add", Name: name, After: newValues[key], HasAfter: true})
		}
	}
	return changes
}

func storeDiff(store *script.MemoryStore, seeded map[string]string) []*mitmapi.ScriptChange {
	namespaces, _ := store.Namespaces()
	final := map[string]string{}
	for _, ns := range namespaces {
		entries, _ := store.List(ns.Name)
		for _, entry := range entries {
			final[ns.Name+"\x00"+entry.Key] = entry.Value
		}
	}
	var names []string
	for k := range seeded {
		names = append(names, k)
	}
	for k := range final {
		if _, ok := seeded[k]; !ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	var changes []*mitmapi.ScriptChange
	for _, k := range names {
		ns, key, _ := strings.Cut(k, "\x00")
		name := key
		if ns == script.SharedNamespace {
			name = script.SharedPrefix + key
		}
		before, had := seeded[k]
		after, has := final[k]
		switch {
		case had && !has:
			changes = append(changes, &mitmapi.ScriptChange{Kind: "store", Op: "remove", Name: name, Before: before, HadBefore: true})
		case has && (!had || before != after):
			changes = append(changes, &mitmapi.ScriptChange{Kind: "store", Op: "set", Name: name, Before: before, HadBefore: had, After: after, HasAfter: true})
		}
	}
	return changes
}

func (s *scriptServer) Run(ctx context.Context, request *mitmapi.ScriptRunRequest) (*mitmapi.ScriptRunResponse, error) {
	manager, _, err := s.runtime(ctx)
	if err != nil {
		return nil, err
	}
	if len(request.Argument) > script.MaxArgumentSize {
		return nil, status.Error(codes.InvalidArgument, "argument too long")
	}
	sc := manager.Current().Lookup(request.Tag)
	if sc == nil {
		return nil, status.Error(codes.NotFound, "unknown script: "+request.Tag)
	}
	if sc.Phase() != script.PhaseGeneric && sc.Phase() != script.PhaseCron {
		return nil, status.Error(codes.FailedPrecondition, "script "+request.Tag+" is not a generic or cron script")
	}
	result, err := manager.RunGeneric(ctx, request.Tag, request.Argument)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &mitmapi.ScriptRunResponse{
		Action: string(result.Action), Error: result.Error, DurationUs: result.Duration.Microseconds(),
		Logs: toLogLines(result.Logs), Output: result.Output,
	}, nil
}

func (s *scriptServer) GetStatus(ctx context.Context, _ *emptypb.Empty) (*mitmapi.ScriptStatusList, error) {
	manager, _, err := s.runtime(ctx)
	if err != nil {
		return nil, err
	}
	list := &mitmapi.ScriptStatusList{StoreLimit: script.MaxStoreTotal}
	for _, st := range manager.Current().Status() {
		item := scriptStateMessage(st)
		list.Scripts = append(list.Scripts, item)
	}
	if info, ok := manager.Store().(script.StoreInfo); ok {
		list.StorePersistent = info.Persistent()
		list.StoreBytes = uint64(max(info.Usage(), 0))
	}
	return list, nil
}

func (s *scriptServer) acquireStream() (func(), error) {
	select {
	case s.streams <- struct{}{}:
		return func() { <-s.streams }, nil
	default:
		return nil, status.Error(codes.ResourceExhausted, "too many script subscribers")
	}
}

func (s *scriptServer) SubscribeLogs(request *mitmapi.ScriptSubscribeRequest, stream grpc.ServerStreamingServer[mitmapi.ScriptLogEntry]) error {
	ctx := stream.Context()
	_, hub, err := s.runtime(ctx)
	if err != nil {
		return err
	}
	release, err := s.acquireStream()
	if err != nil {
		return err
	}
	defer release()
	wake, cancel := hub.Subscribe()
	defer cancel()
	stale := time.NewTicker(scriptStaleCheck)
	defer stale.Stop()
	// A cursor beyond the newest entry belongs to an earlier core: start over.
	after := request.After
	if after > hub.LogSeq() {
		after = 0
	}
	for {
		for {
			records := hub.LogsAfter(after, 256)
			if len(records) == 0 {
				break
			}
			for _, rec := range records {
				after = rec.Seq
				if request.Tag != "" && rec.Script != request.Tag {
					continue
				}
				err = stream.Send(&mitmapi.ScriptLogEntry{
					Seq: rec.Seq, Script: rec.Script, Phase: string(rec.Phase), Level: rec.Level,
					Message: rec.Message, TimeMs: scriptTime(rec.Time),
				})
				if err != nil {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-stale.C:
			if _, current := s.provider.ScriptRuntime(); current != hub {
				return status.Error(codes.Unavailable, "scripts restarted")
			}
		}
	}
}

func (s *scriptServer) SubscribeNotifications(request *mitmapi.ScriptSubscribeRequest, stream grpc.ServerStreamingServer[mitmapi.ScriptNotification]) error {
	ctx := stream.Context()
	_, hub, err := s.runtime(ctx)
	if err != nil {
		return err
	}
	release, err := s.acquireStream()
	if err != nil {
		return err
	}
	defer release()
	wake, cancel := hub.Subscribe()
	defer cancel()
	stale := time.NewTicker(scriptStaleCheck)
	defer stale.Stop()
	after := request.After
	if after > hub.NotificationSeq() {
		after = 0
	}
	for {
		for {
			records := hub.NotificationsAfter(after, 256)
			if len(records) == 0 {
				break
			}
			for _, rec := range records {
				after = rec.Seq
				err = stream.Send(toNotification(rec.Seq, rec.Notification))
				if err != nil {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-stale.C:
			if _, current := s.provider.ScriptRuntime(); current != hub {
				return status.Error(codes.Unavailable, "scripts restarted")
			}
		}
	}
}

func (s *scriptServer) store(ctx context.Context) (script.Store, error) {
	manager, _, err := s.runtime(ctx)
	if err != nil {
		return nil, err
	}
	return manager.Store(), nil
}

func checkStoreKey(namespace, key string) error {
	if !validNamespace(namespace) {
		return status.Error(codes.InvalidArgument, "namespace must be a script tag or @shared")
	}
	if key == "" || len(key) > script.MaxStoreKey {
		return status.Error(codes.InvalidArgument, "key must be 1-256 bytes")
	}
	if namespace != script.SharedNamespace && strings.HasPrefix(key, script.SharedPrefix) {
		return status.Error(codes.InvalidArgument, "keys starting with @shared/ belong to the @shared namespace")
	}
	return nil
}

func storeStatus(err error) error {
	switch {
	case errors.Is(err, script.ErrStoreFull), errors.Is(err, script.ErrStoreTooMany):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, script.ErrStoreValueTooLarge), errors.Is(err, script.ErrStoreKey):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

func storeInfo(store script.Store) *mitmapi.ScriptStoreInfo {
	info := &mitmapi.ScriptStoreInfo{Limit: script.MaxStoreTotal}
	if i, ok := store.(script.StoreInfo); ok {
		info.Persistent = i.Persistent()
		info.Bytes = uint64(max(i.Usage(), 0))
	}
	return info
}

func (s *scriptServer) StoreList(ctx context.Context, request *mitmapi.ScriptStoreListRequest) (*mitmapi.ScriptStoreListResponse, error) {
	store, err := s.store(ctx)
	if err != nil {
		return nil, err
	}
	response := &mitmapi.ScriptStoreListResponse{Info: storeInfo(store)}
	if i, ok := store.(script.StoreInfo); ok {
		namespaces, err := i.Namespaces()
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		for _, ns := range namespaces {
			response.Namespaces = append(response.Namespaces, &mitmapi.ScriptStoreNamespace{Name: ns.Name, Entries: uint32(ns.Entries), Bytes: uint64(ns.Bytes)})
		}
	}
	if request.Namespace == "" {
		return response, nil
	}
	if !validNamespace(request.Namespace) {
		return nil, status.Error(codes.InvalidArgument, "namespace must be a script tag or @shared")
	}
	entries, err := store.List(request.Namespace)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if len(entries) > scriptStoreEntries {
		entries = entries[:scriptStoreEntries]
	}
	for _, entry := range entries {
		item := &mitmapi.ScriptStoreListEntry{Key: entry.Key, Value: entry.Value, Size: uint32(len(entry.Value))}
		if len(item.Value) > scriptListValueBytes {
			item.Value = truncateUTF8(item.Value, scriptListValueBytes)
			item.Truncated = true
		}
		response.Entries = append(response.Entries, item)
	}
	return response, nil
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func (s *scriptServer) StoreGet(ctx context.Context, request *mitmapi.ScriptStoreKey) (*mitmapi.ScriptStoreValue, error) {
	store, err := s.store(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkStoreKey(request.Namespace, request.Key); err != nil {
		return nil, err
	}
	value, found, err := store.Get(request.Namespace, request.Key)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &mitmapi.ScriptStoreValue{Value: value, Found: found}, nil
}

func (s *scriptServer) StoreSet(ctx context.Context, request *mitmapi.ScriptStoreSetRequest) (*mitmapi.ScriptStoreInfo, error) {
	store, err := s.store(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkStoreKey(request.Namespace, request.Key); err != nil {
		return nil, err
	}
	if len(request.Value) > script.MaxStoreValue {
		return nil, status.Error(codes.InvalidArgument, "value larger than 1 MiB")
	}
	if err := store.Set(request.Namespace, request.Key, request.Value); err != nil {
		return nil, storeStatus(err)
	}
	return storeInfo(store), nil
}

func (s *scriptServer) StoreDelete(ctx context.Context, request *mitmapi.ScriptStoreKey) (*mitmapi.ScriptStoreInfo, error) {
	store, err := s.store(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkStoreKey(request.Namespace, request.Key); err != nil {
		return nil, err
	}
	if err := store.Delete(request.Namespace, request.Key); err != nil {
		return nil, storeStatus(err)
	}
	return storeInfo(store), nil
}

// scriptStateMessage converts the run history of a script; next_run_ms is 0 for scripts that
// are not scheduled.
func scriptStateMessage(st script.Status) *mitmapi.ScriptState {
	item := &mitmapi.ScriptState{
		Tag: st.Tag, Type: string(st.Type), Runs: st.Runs, Errors: st.Errors, Timeouts: st.Timeouts,
		Limits: st.Limits, Skipped: st.Skipped, Paused: st.Paused, LastError: st.LastError,
		LastRunMs: scriptTime(st.LastRun), LastDurationUs: st.LastRunTime.Microseconds(),
		NextRunMs: scriptTime(st.NextRun),
	}
	if st.Paused {
		item.PausedUntil = st.PausedUntil.Unix()
	}
	return item
}
