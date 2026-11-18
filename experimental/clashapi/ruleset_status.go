package clashapi

import (
	"context"
	"errors"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

type ruleSetLister interface {
	RuleSets() []adapter.RuleSet
}

type ruleSetLastUpdated interface {
	LastUpdatedAtMillis() int64
}

type ruleSetLastError interface {
	LastError() string
}

type ruleSetInline interface {
	IsInline() bool
}

type ruleSetUpdater interface {
	Update(ctx context.Context) error
}

type ruleSetSource interface {
	SourceContent(ctx context.Context) (option.PlainRuleSetCompat, error)
}

type ruleSetStatus struct {
	Tag           string `json:"tag"`
	LastUpdatedAt int64  `json:"lastUpdatedAt"`
	Type          string `json:"type,omitempty"`
	LastError     string `json:"lastError,omitempty"`
}

func ruleSetType(ruleSet adapter.RuleSet) string {
	if _, isRemote := ruleSet.(ruleSetLastUpdated); isRemote {
		return C.RuleSetTypeRemote
	}
	if inline, ok := ruleSet.(ruleSetInline); ok {
		if inline.IsInline() {
			return C.RuleSetTypeInline
		}
		return C.RuleSetTypeLocal
	}
	return ""
}

func ruleSetStatusOf(ruleSet adapter.RuleSet) ruleSetStatus {
	status := ruleSetStatus{Tag: ruleSet.Name(), Type: ruleSetType(ruleSet)}
	if remote, ok := ruleSet.(ruleSetLastUpdated); ok {
		status.LastUpdatedAt = remote.LastUpdatedAtMillis()
	}
	if failed, ok := ruleSet.(ruleSetLastError); ok {
		status.LastError = failed.LastError()
	}
	return status
}

func ruleSetStatuses(ruleSets []adapter.RuleSet) []ruleSetStatus {
	result := make([]ruleSetStatus, 0, len(ruleSets))
	for _, ruleSet := range ruleSets {
		result = append(result, ruleSetStatusOf(ruleSet))
	}
	return result
}

func ruleSetRouter(router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleSetStatuses(router))
	r.Put("/{tag}", updateRuleSet(router))
	r.Get("/{tag}/source", getRuleSetSource(router))
	return r
}

func getRuleSetStatuses(router adapter.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var statuses []ruleSetStatus
		if lister, ok := router.(ruleSetLister); ok {
			statuses = ruleSetStatuses(lister.RuleSets())
		}
		if statuses == nil {
			statuses = []ruleSetStatus{}
		}
		render.JSON(w, r, render.M{"ruleSets": statuses})
	}
}

func findRuleSet(router adapter.Router, w http.ResponseWriter, r *http.Request) (adapter.RuleSet, bool) {
	ruleSet, loaded := router.RuleSet(getEscapeParam(r, "tag"))
	if !loaded {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return nil, false
	}
	return ruleSet, true
}

// updateRuleSet downloads a remote rule set or reads a local one again.
func updateRuleSet(router adapter.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleSet, found := findRuleSet(router, w, r)
		if !found {
			return
		}
		updater, canUpdate := ruleSet.(ruleSetUpdater)
		if !canUpdate || ruleSetType(ruleSet) == C.RuleSetTypeInline {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("inline rule-set cannot be updated"))
			return
		}
		err := updater.Update(r.Context())
		if err != nil {
			render.Status(r, http.StatusBadGateway)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, ruleSetStatusOf(ruleSet))
	}
}

// getRuleSetSource returns the rules of the source content, before the
// overrides apply, as a source rule set.
func getRuleSetSource(router adapter.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleSet, found := findRuleSet(router, w, r)
		if !found {
			return
		}
		source, canRead := ruleSet.(ruleSetSource)
		if !canRead {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		content, err := source.SourceContent(r.Context())
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, newError(err.Error()))
				return
			}
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		body, err := json.Marshal(content)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}
