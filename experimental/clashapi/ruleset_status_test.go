package clashapi

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

type statusTestRuleSet struct {
	tag       string
	updatedAt int64
}

func (s statusTestRuleSet) Name() string                                                { return s.tag }
func (statusTestRuleSet) StartContext(context.Context, *adapter.HTTPStartContext) error { return nil }
func (statusTestRuleSet) Metadata() adapter.RuleSetMetadata                             { return adapter.RuleSetMetadata{} }
func (statusTestRuleSet) ExtractIPSet() []*netipx.IPSet                                 { return nil }
func (statusTestRuleSet) IncRef()                                                       {}
func (statusTestRuleSet) DecRef()                                                       {}
func (statusTestRuleSet) Cleanup()                                                      {}
func (statusTestRuleSet) RegisterCallback(adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	return nil
}
func (statusTestRuleSet) UnregisterCallback(*list.Element[adapter.RuleSetUpdateCallback]) {}
func (statusTestRuleSet) Close() error                                                    { return nil }
func (statusTestRuleSet) Match(*adapter.InboundContext) bool                              { return false }
func (statusTestRuleSet) String() string                                                  { return "" }
func (s statusTestRuleSet) LastUpdatedAtMillis() int64                                    { return s.updatedAt }

func TestRuleSetStatusesIncludeLastUpdatedAtMillis(t *testing.T) {
	got := ruleSetStatuses([]adapter.RuleSet{
		statusTestRuleSet{tag: "geosite-cn", updatedAt: 1_792_720_440_000},
	})
	if len(got) != 1 || got[0].Tag != "geosite-cn" || got[0].LastUpdatedAt != 1_792_720_440_000 {
		t.Fatalf("unexpected rule-set statuses: %+v", got)
	}
}

type apiTestRuleSet struct {
	adapter.RuleSet
	tag       string
	updatedAt int64
	inline    *bool
	updateErr error
	lastError string
	updates   int
	source    *option.PlainRuleSetCompat
	sourceErr error
}

func (s *apiTestRuleSet) Name() string      { return s.tag }
func (s *apiTestRuleSet) LastError() string { return s.lastError }

func (s *apiTestRuleSet) Update(context.Context) error {
	s.updates++
	if s.updateErr != nil {
		s.lastError = s.updateErr.Error()
		return s.updateErr
	}
	s.lastError = ""
	s.updatedAt++
	return nil
}

func (s *apiTestRuleSet) SourceContent(context.Context) (option.PlainRuleSetCompat, error) {
	if s.sourceErr != nil {
		return option.PlainRuleSetCompat{}, s.sourceErr
	}
	return *s.source, nil
}

type apiTestLocalRuleSet struct {
	*apiTestRuleSet
}

func (s apiTestLocalRuleSet) IsInline() bool { return *s.inline }

// apiTestRemoteRuleSet reports a last update time, as remote rule sets do.
type apiTestRemoteRuleSet struct {
	*apiTestRuleSet
}

func (s apiTestRemoteRuleSet) LastUpdatedAtMillis() int64 { return s.updatedAt }

type apiTestRouter struct {
	adapter.Router
	ruleSets []adapter.RuleSet
}

func (r *apiTestRouter) RuleSets() []adapter.RuleSet { return r.ruleSets }

func (r *apiTestRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	for _, ruleSet := range r.ruleSets {
		if ruleSet.Name() == tag {
			return ruleSet, true
		}
	}
	return nil, false
}

func TestRuleSetAPI(t *testing.T) {
	inline, local := true, false
	source := &option.PlainRuleSetCompat{Version: 3, Options: option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{Domain: badoption.Listable[string]{"a.test", "b.test"}},
	}}}}
	remote := &apiTestRuleSet{tag: "geo site", updatedAt: 1000, source: source}
	localSet := &apiTestRuleSet{tag: "file", inline: &local, sourceErr: fs.ErrNotExist}
	inlineSet := &apiTestRuleSet{tag: "mine", inline: &inline, source: source}
	router := &apiTestRouter{ruleSets: []adapter.RuleSet{
		apiTestRemoteRuleSet{remote}, apiTestLocalRuleSet{localSet}, apiTestLocalRuleSet{inlineSet},
	}}
	server := httptest.NewServer(ruleSetRouter(router))
	defer server.Close()
	call := func(method, path string) (int, map[string]any) {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, nil)
		require.NoError(t, err)
		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		var body map[string]any
		require.NoError(t, stdjson.NewDecoder(response.Body).Decode(&body))
		return response.StatusCode, body
	}

	status, body := call(http.MethodGet, "/")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []any{
		map[string]any{"tag": "geo site", "lastUpdatedAt": float64(1000), "type": "remote"},
		map[string]any{"tag": "file", "lastUpdatedAt": float64(0), "type": "local"},
		map[string]any{"tag": "mine", "lastUpdatedAt": float64(0), "type": "inline"},
	}, body["ruleSets"])

	status, body = call(http.MethodPut, "/geo%20site")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, map[string]any{"tag": "geo site", "lastUpdatedAt": float64(1001), "type": "remote"}, body)
	require.Equal(t, 1, remote.updates)

	remote.updateErr = errors.New("unexpected status: 500")
	status, body = call(http.MethodPut, "/geo%20site")
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, "unexpected status: 500", body["message"])
	_, body = call(http.MethodGet, "/")
	require.Equal(t, "unexpected status: 500", body["ruleSets"].([]any)[0].(map[string]any)["lastError"])

	status, _ = call(http.MethodPut, "/file")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, localSet.updates)
	status, _ = call(http.MethodPut, "/mine")
	require.Equal(t, http.StatusBadRequest, status)
	require.Zero(t, inlineSet.updates)
	status, _ = call(http.MethodPut, "/missing")
	require.Equal(t, http.StatusNotFound, status)

	status, body = call(http.MethodGet, "/geo%20site/source")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, float64(3), body["version"])
	require.Equal(t, []any{map[string]any{"domain": []any{"a.test", "b.test"}}}, body["rules"])
	status, _ = call(http.MethodGet, "/mine/source")
	require.Equal(t, http.StatusOK, status)
	status, _ = call(http.MethodGet, "/file/source")
	require.Equal(t, http.StatusNotFound, status)
	status, _ = call(http.MethodGet, "/missing/source")
	require.Equal(t, http.StatusNotFound, status)
}
