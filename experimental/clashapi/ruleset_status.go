package clashapi

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
)

type ruleSetLister interface {
	RuleSets() []adapter.RuleSet
}

type ruleSetLastUpdated interface {
	LastUpdatedAtMillis() int64
}

type ruleSetStatus struct {
	Tag           string `json:"tag"`
	LastUpdatedAt int64  `json:"lastUpdatedAt"`
}

func ruleSetStatuses(ruleSets []adapter.RuleSet) []ruleSetStatus {
	result := make([]ruleSetStatus, 0, len(ruleSets))
	for _, ruleSet := range ruleSets {
		status := ruleSetStatus{Tag: ruleSet.Name()}
		if remote, ok := ruleSet.(ruleSetLastUpdated); ok {
			status.LastUpdatedAt = remote.LastUpdatedAtMillis()
		}
		result = append(result, status)
	}
	return result
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
