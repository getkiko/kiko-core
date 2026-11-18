package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

// ScriptOptions is one JavaScript script (top-level "scripts").
//
// http-request and http-response scripts run on decrypted and plain HTTP messages whose
// URL matches Pattern, after the URL, header and body rewrite rules. generic scripts run on
// demand. cron scripts run on a schedule. rule scripts are the `script` condition of route and
// DNS rules and dns scripts the `script` action of DNS rules: both run synchronously with a
// short timeout (default 100ms, at most 1s), take no pattern and no body, and their outcome
// is cached for 60 seconds per script and input.
type ScriptOptions struct {
	// Tag identifies the script: 1-64 characters of A-Z a-z 0-9 . _ -; unique.
	Tag  string `json:"tag"`
	Type string `json:"type" enum:"http-request,http-response,generic,cron,rule,dns"`
	// Enabled defaults to true. A disabled script is neither compiled nor run.
	Enabled *bool `json:"enabled,omitempty"`
	// Pattern is an RE2 expression matched against scheme://authority/path?query. Required
	// for http-request and http-response, not allowed for generic.
	Pattern string `json:"pattern,omitempty"`
	// SourcePath is the script file, relative to the working directory (no "..").
	SourcePath string `json:"source_path"`
	// RequiresBody passes the message body to the script ($request.body / $response.body).
	RequiresBody bool `json:"requires_body,omitempty"`
	// BinaryBody passes the body as a Uint8Array instead of a string; needs RequiresBody.
	BinaryBody bool `json:"binary_body,omitempty"`
	// MaxSize is the largest body the script gets (default http_rewrite.max_body_size, at
	// most 32 MiB). A larger body is not passed: the script is skipped with requires_body.
	MaxSize *byteformats.Bytes `json:"max_size,omitempty"`
	// Timeout is the run limit (default 10s, at most 30s; generic and cron scripts 60s; rule and
	// dns scripts 100ms, at most 1s).
	Timeout badoption.Duration `json:"timeout,omitempty"`
	// Cron is the schedule of a cron script: five fields (minute hour day-of-month month
	// day-of-week) in local time. Required for cron, not allowed for other types.
	Cron string `json:"cron,omitempty"`
	// Argument is the $argument string (at most 16 KiB).
	Argument string `json:"argument,omitempty"`
}

// Script types.
const (
	ScriptTypeHTTPRequest  = "http-request"
	ScriptTypeHTTPResponse = "http-response"
	ScriptTypeGeneric      = "generic"
	ScriptTypeCron         = "cron"
	ScriptTypeRule         = "rule"
	ScriptTypeDNS          = "dns"
)

// MaxScripts is the most scripts a configuration may hold.
const MaxScripts = 256
