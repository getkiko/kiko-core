// Package script runs JavaScript (Surge-style) scripts on decrypted HTTP messages. It embeds
// goja and knows nothing about the proxy engine: the HTTP hooks translate between messages
// and Input/Result, and the persistent store, notifications and logs reach the host through
// small interfaces.
package script

import (
	"time"
)

// Phase is the type of a script.
type Phase string

const (
	PhaseRequest  Phase = "http-request"
	PhaseResponse Phase = "http-response"
	PhaseGeneric  Phase = "generic"
	// PhaseCron scripts run like generic ones, on the schedule of Config.Cron.
	PhaseCron Phase = "cron"
	// PhaseRule scripts are the `script` condition of route and DNS rules: synchronous, short
	// and cached (see rulescript.go). PhaseDNS scripts are the `script` action of DNS rules.
	PhaseRule Phase = "rule"
	PhaseDNS  Phase = "dns"
)

// Action is the outcome of one script run, in the vocabulary of rewrite hits.
type Action string

const (
	ActionNone    Action = "none"
	ActionModify  Action = "modify"
	ActionRespond Action = "respond"
	ActionAbort   Action = "abort"
	ActionError   Action = "error"
	ActionTimeout Action = "timeout"
	ActionLimit   Action = "limit"
	ActionPaused  Action = "paused"
	ActionSkipped Action = "skipped"
)

// Skip reasons (Result.Reason for ActionSkipped).
const (
	SkipBusy = "busy"
	// ReasonCanceled is the Reason of a run that was ended because its message went away.
	ReasonCanceled = "canceled"
)

// Limits and defaults.
const (
	DefaultTimeout        = 10 * time.Second
	MaxTimeout            = 30 * time.Second
	DefaultGenericTimeout = 60 * time.Second
	MaxGenericTimeout     = 60 * time.Second
	// DefaultRuleTimeout is the run limit of rule and dns scripts; MaxRuleTimeout caps it.
	DefaultRuleTimeout = 100 * time.Millisecond
	MaxRuleTimeout     = time.Second
	DefaultMaxSize     = 2 << 20
	MaxMaxSize         = 32 << 20
	MaxSourceSize      = 1 << 20
	MaxArgumentSize    = 16 << 10
	MaxTagLength       = 64
	MaxScripts         = 256
	MaxPatternLength   = 4096

	// AllocationLimit is the most bytes one call may allocate (strings, arrays, buffers).
	AllocationLimit = 64 << 20
	// RegexInputLimit is the longest string a collecting regular expression operation (match
	// with the g flag, matchAll, split, replace with a function) accepts; regexMatchCost is
	// the allowance charged per input byte for the match objects.
	RegexInputLimit = 1 << 20
	regexMatchCost  = 16

	// CallStackLimit is the call stack depth of a script.
	CallStackLimit = 1024
	// WaitLimit is how long a call waits for a free slot before it is skipped.
	WaitLimit = 2 * time.Second

	// PoolSize is the most idle VMs kept per script; PoolIdle is how long they stay.
	PoolSize = 4
	PoolIdle = 60 * time.Second

	// PauseFailures failures within PauseWindow pause a script for PauseDuration.
	PauseFailures = 50
	PauseWindow   = time.Minute
	PauseDuration = 5 * time.Minute

	maxLogLines   = 200
	maxLogLine    = 4 << 10
	maxErrorText  = 512
	maxHeaders    = 512
	maxNotifyRate = 10 // notifications per script per minute
)

// Header is one header field.
type Header struct {
	Name  string
	Value string
}

// Config is one compiled script.
type Config struct {
	Tag      string
	Type     Phase
	Disabled bool
	// Pattern is an RE2 expression matched against scheme://authority/path?query (http-*).
	Pattern string
	Source  string
	// SourceName is shown in errors (the file path).
	SourceName   string
	RequiresBody bool
	BinaryBody   bool
	MaxSize      int64
	Timeout      time.Duration
	Argument     string
	// Cron is the schedule of a cron script: five fields (minute hour day-of-month month
	// day-of-week) in local time.
	Cron string
}

// Request is the $request object.
type Request struct {
	URL     string
	Method  string
	Headers []Header
	// Body is the message body; HasBody false leaves $request.body undefined.
	Body    []byte
	HasBody bool
	ID      string
}

// Response is the $response object, or the answer a script produces.
type Response struct {
	Status  int
	Headers []Header
	Body    []byte
	HasBody bool
}

// Input is what a script sees.
type Input struct {
	Request  *Request
	Response *Response // http-response only
	// Rule is the $request of rule and dns scripts.
	Rule *RuleInput
}

// Result is the outcome of a run. The modification fields are meaningful for
// ActionModify and ActionRespond only.
type Result struct {
	Tag      string
	Phase    Phase
	Action   Action
	Reason   string // skip reason
	Error    string // message of error, timeout and limit
	Duration time.Duration
	Logs     []LogLine

	// URL is the new request URL (http-request).
	URL string
	// Headers is the complete header list after the script, set when HeadersChanged.
	Headers        []Header
	HeadersChanged bool
	// Body is the new body (requires_body scripts); BodyChanged tells it differs.
	Body        []byte
	BodyChanged bool
	// Status is the new status code of an http-response script, 0 when unchanged.
	Status int
	// Response is the answer of $done({response}) (http-request), Action is ActionRespond.
	Response *Response
	// Output is the JSON text of the value a generic script passed to $done, "" for none.
	Output string
	// Notifications posted by the script during a dry run.
	Notifications []Notification
}

// LogLine is one console line.
type LogLine struct {
	Level   string // log, info, warn, error
	Message string
	Time    time.Time
}

// LogEntry is a console line with its script, for the host's log sink.
type LogEntry struct {
	Script string
	Phase  Phase
	LogLine
}

// Logger receives the console output of scripts as it happens.
type Logger interface {
	Log(entry LogEntry)
}

// Notification is a $notification.post call.
type Notification struct {
	Script   string
	Title    string
	Subtitle string
	Body     string
	URL      string
	Time     time.Time
}

// Notifier receives notifications posted by scripts. It must not block.
type Notifier interface {
	Notify(n Notification)
}

// StoreEntry is a key and value of a namespace.
type StoreEntry struct {
	Key   string
	Value string
}

// Store keeps the $persistentStore values. Namespaces isolate scripts: a script's own
// namespace is its tag; keys beginning with "@shared/" live in SharedNamespace. The
// implementation enforces the size limits (value 1 MiB, total 16 MiB) and returns an error
// when a write would exceed them.
type Store interface {
	Get(namespace, key string) (value string, ok bool, err error)
	Set(namespace, key, value string) error
	Delete(namespace, key string) error
	List(namespace string) ([]StoreEntry, error)
}

// SharedNamespace holds keys that start with SharedPrefix.
const (
	SharedNamespace = "@shared"
	SharedPrefix    = "@shared/"
)

// Store limits for implementations.
const (
	MaxStoreValue = 1 << 20
	MaxStoreTotal = 16 << 20
	MaxStoreKey   = 256
	// StoreEntryOverhead is counted against MaxStoreTotal for every entry, on top of the key
	// and value bytes.
	StoreEntryOverhead = 64
	// MaxStoreNamespaceEntries and MaxStoreEntries bound the entries of a namespace and of
	// the whole store.
	MaxStoreNamespaceEntries = 4096
	MaxStoreEntries          = 65536
)
