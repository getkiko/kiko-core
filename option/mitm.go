package option

import (
	"strings"
	"time"

	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// MITMOptions configures HTTPS decryption.
type MITMOptions struct {
	Enabled     bool                    `json:"enabled,omitempty"`
	Certificate *MITMCertificateOptions `json:"certificate,omitempty"`
	Hostnames   *MITMHostnamesOptions   `json:"hostnames,omitempty"`
	// Sources limits decryption to connections from these clients: "local"
	// (this machine, including the TUN interface) and IP addresses or CIDR
	// prefixes of devices routed through a gateway. Empty means ["local"].
	Sources  badoption.Listable[string] `json:"sources,omitempty"`
	Upstream *MITMUpstreamOptions       `json:"upstream,omitempty"`
	// QUIC is "block" (the default) or "allow". With block, QUIC to a
	// decrypted host is dropped so that the client falls back to TCP.
	QUIC string `json:"quic,omitempty" enum:"block,allow"`
	// PinningSkipDuration is how long a (process or source device, host)
	// pair that failed pinning twice in a row passes through (default 30m).
	PinningSkipDuration badoption.Duration `json:"pinning_skip_duration,omitempty"`
	// H2 offers HTTP/2 inside decrypted sessions (default true). false keeps
	// them HTTP/1.1: the upstream ALPN offers only http/1.1 and the client is
	// given only http/1.1. A change affects new connections only.
	H2 *bool `json:"h2,omitempty"`
	// Capture records decrypted exchanges for the HTTP request list.
	Capture *MITMCaptureOptions `json:"capture,omitempty"`
	// HTTPRewrite rewrites URLs, headers and responses of decrypted and
	// plain HTTP exchanges.
	HTTPRewrite *MITMHTTPRewriteOptions `json:"http_rewrite,omitempty"`
}

type MITMCertificateOptions struct {
	// Source is "managed" (the default: the authority is pushed over the
	// core API) or "file".
	Source          string `json:"source,omitempty" enum:"managed,file"`
	CertificatePath string `json:"certificate_path,omitempty"`
	KeyPath         string `json:"key_path,omitempty"`
}

type MITMHostnamesOptions struct {
	Include badoption.Listable[string] `json:"include,omitempty"`
	Exclude badoption.Listable[string] `json:"exclude,omitempty"`
	// BuiltinExclude keeps hosts that pin certificates or break under
	// decryption out of decryption (default true).
	BuiltinExclude *bool `json:"builtin_exclude,omitempty"`
	// DisabledBuiltin lists built-in entries (by id or pattern) that are
	// decrypted again.
	DisabledBuiltin badoption.Listable[string] `json:"disabled_builtin,omitempty"`
}

// MITMUpstreamOptions configures the TLS connection from the core to the
// destination of a decrypted connection.
type MITMUpstreamOptions struct {
	// Fingerprint is the upstream ClientHello: none (standard TLS), chrome
	// (the default), safari or firefox. Builds without uTLS always use
	// standard TLS. It applies to all hosts.
	Fingerprint string `json:"fingerprint,omitempty" enum:"none,chrome,safari,firefox"`
	// H2Profile is how the upstream HTTP/2 connection looks on the wire:
	// default (net/http's client) or chrome (Chrome's SETTINGS, window update,
	// pseudo-header and header order, request priority). It goes with the
	// chrome fingerprint but is independent of it.
	H2Profile string `json:"h2_profile,omitempty" enum:"default,chrome"`
	// MirrorClientHello builds the upstream ClientHello from the client's own
	// (cipher suites, extensions and their order) instead of the fixed
	// fingerprint. It needs a fingerprint other than none and a build with
	// uTLS; a hello that cannot be mirrored falls back to the fingerprint.
	MirrorClientHello bool `json:"mirror_client_hello,omitempty"`
	// SkipVerify lists hosts whose upstream certificate is not verified.
	SkipVerify badoption.Listable[string] `json:"skip_verify,omitempty"`
	// CustomRoots lists PEM files added to the roots that verify upstream
	// certificates.
	CustomRoots badoption.Listable[string] `json:"custom_roots,omitempty"`
}

const (
	MITMCaptureDefaultMaxBody    = 512 << 10
	MITMCaptureDefaultMaxMemory  = 64 << 20
	MITMCaptureDefaultMaxRecords = 5000

	MITMCaptureMaxBodyLimit    = 64 << 20
	MITMCaptureMinMemory       = 1 << 20
	MITMCaptureMaxMemoryLimit  = 4 << 30
	MITMCaptureMaxRecordsLimit = 200000
)

// MITMCaptureOptions configures the capture of decrypted HTTP exchanges.
type MITMCaptureOptions struct {
	// Enabled records request metadata (default true).
	Enabled *bool `json:"enabled,omitempty"`
	// Body also keeps request and response bodies (default false).
	Body bool `json:"body,omitempty"`
	// MaxBody is the most bytes kept per body (default 512KiB). Larger
	// bodies pass through in full and are marked truncated.
	MaxBody *byteformats.Bytes `json:"max_body,omitempty"`
	// MaxMemory is the budget of the capture store (default 64MiB).
	MaxMemory *byteformats.Bytes `json:"max_memory,omitempty"`
	// MaxRecords is the most records kept (default 5000).
	MaxRecords int `json:"max_records,omitempty"`
	// Persist writes finished exchanges to disk. It is off unless enabled.
	Persist *MITMCapturePersistOptions `json:"persist,omitempty"`
}

const (
	MITMCapturePersistDefaultMaxBytes   = 256 << 20
	MITMCapturePersistDefaultMaxRecords = 20000
	MITMCapturePersistDefaultRetention  = 7 * 24 * time.Hour

	MITMCapturePersistMinBytes      = 1 << 20
	MITMCapturePersistMaxBytesLimit = int64(64) << 30
	MITMCapturePersistMaxRecords    = 1000000
	MITMCapturePersistMinRetention  = time.Minute
	MITMCapturePersistMaxRetention  = 3650 * 24 * time.Hour
	MITMCapturePersistMaxRedact     = 64
)

// MITMCapturePersistOptions configures the on-disk copy of captured
// exchanges. Sensitive headers are masked before anything is written.
type MITMCapturePersistOptions struct {
	Enabled bool `json:"enabled,omitempty"`
	// Path is the directory of the files; it is created with mode 0700.
	Path string `json:"path,omitempty"`
	// MaxBytes bounds the files on disk (default 256MiB); the oldest records
	// are dropped first.
	MaxBytes *byteformats.Bytes `json:"max_bytes,omitempty"`
	// MaxRecords bounds the records on disk (default 20000).
	MaxRecords int `json:"max_records,omitempty"`
	// Retention is how long a record is kept (default 168h).
	Retention badoption.Duration `json:"retention,omitempty"`
	// Body also writes the bodies kept in memory (needs capture.body).
	Body bool `json:"body,omitempty"`
	// RedactHeaders names headers masked besides the built-in list.
	RedactHeaders badoption.Listable[string] `json:"redact_headers,omitempty"`
}

// MITMCapturePersistSettings is MITMCapturePersistOptions with defaults
// applied.
type MITMCapturePersistSettings struct {
	Enabled       bool
	Path          string
	MaxBytes      int64
	MaxRecords    int
	Retention     time.Duration
	Body          bool
	RedactHeaders []string
}

// Resolve applies defaults and checks value ranges. A nil receiver yields
// disabled settings.
func (o *MITMCapturePersistOptions) Resolve() (MITMCapturePersistSettings, error) {
	if o == nil {
		return MITMCapturePersistSettings{}, nil
	}
	settings := MITMCapturePersistSettings{
		Enabled:    o.Enabled,
		Path:       o.Path,
		MaxBytes:   MITMCapturePersistDefaultMaxBytes,
		MaxRecords: MITMCapturePersistDefaultMaxRecords,
		Retention:  MITMCapturePersistDefaultRetention,
		Body:       o.Body,
	}
	if o.Enabled && o.Path == "" {
		return settings, E.New("capture.persist.path is required")
	}
	if o.MaxBytes != nil {
		value := int64(o.MaxBytes.Value())
		if value < MITMCapturePersistMinBytes || value > MITMCapturePersistMaxBytesLimit {
			return settings, E.New("capture.persist.max_bytes must be between ", MITMCapturePersistMinBytes, " and ", MITMCapturePersistMaxBytesLimit, " bytes")
		}
		settings.MaxBytes = value
	}
	if o.MaxRecords != 0 {
		if o.MaxRecords < 0 || o.MaxRecords > MITMCapturePersistMaxRecords {
			return settings, E.New("capture.persist.max_records must be between 1 and ", MITMCapturePersistMaxRecords)
		}
		settings.MaxRecords = o.MaxRecords
	}
	if retention := time.Duration(o.Retention); retention != 0 {
		if retention < MITMCapturePersistMinRetention || retention > MITMCapturePersistMaxRetention {
			return settings, E.New("capture.persist.retention must be between ", MITMCapturePersistMinRetention, " and ", MITMCapturePersistMaxRetention)
		}
		settings.Retention = retention
	}
	if len(o.RedactHeaders) > MITMCapturePersistMaxRedact {
		return settings, E.New("capture.persist.redact_headers has at most ", MITMCapturePersistMaxRedact, " names")
	}
	for _, name := range o.RedactHeaders {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, " \t:\r\n") {
			return settings, E.New("capture.persist.redact_headers has an invalid header name")
		}
		settings.RedactHeaders = append(settings.RedactHeaders, name)
	}
	return settings, nil
}

// MITMCaptureSettings is MITMCaptureOptions with defaults applied.
type MITMCaptureSettings struct {
	Enabled    bool
	Body       bool
	MaxBody    int64
	MaxMemory  int64
	MaxRecords int
	Persist    MITMCapturePersistSettings
}

// Resolve applies defaults and checks value ranges. A nil receiver yields the
// defaults.
func (o *MITMCaptureOptions) Resolve() (MITMCaptureSettings, error) {
	settings := MITMCaptureSettings{
		Enabled:    true,
		MaxBody:    MITMCaptureDefaultMaxBody,
		MaxMemory:  MITMCaptureDefaultMaxMemory,
		MaxRecords: MITMCaptureDefaultMaxRecords,
	}
	if o == nil {
		return settings, nil
	}
	if o.Enabled != nil {
		settings.Enabled = *o.Enabled
	}
	settings.Body = o.Body
	if o.MaxBody != nil {
		value := int64(o.MaxBody.Value())
		if value <= 0 || value > MITMCaptureMaxBodyLimit {
			return settings, E.New("capture.max_body must be between 1 and ", MITMCaptureMaxBodyLimit, " bytes")
		}
		settings.MaxBody = value
	}
	if o.MaxMemory != nil {
		value := int64(o.MaxMemory.Value())
		if value < MITMCaptureMinMemory || value > MITMCaptureMaxMemoryLimit {
			return settings, E.New("capture.max_memory must be between ", MITMCaptureMinMemory, " and ", int64(MITMCaptureMaxMemoryLimit), " bytes")
		}
		settings.MaxMemory = value
	}
	if o.MaxRecords != 0 {
		if o.MaxRecords < 0 || o.MaxRecords > MITMCaptureMaxRecordsLimit {
			return settings, E.New("capture.max_records must be between 1 and ", MITMCaptureMaxRecordsLimit)
		}
		settings.MaxRecords = o.MaxRecords
	}
	persist, err := o.Persist.Resolve()
	if err != nil {
		return settings, err
	}
	settings.Persist = persist
	return settings, nil
}

// MITMHTTPRewriteOptions are the HTTP rewrite rules. Patterns are RE2
// expressions matched against scheme://authority/path?query.
type MITMHTTPRewriteOptions struct {
	URL      []MITMURLRewriteRule    `json:"url,omitempty"`
	Headers  []MITMHeaderRewriteRule `json:"headers,omitempty"`
	MapLocal []MITMMapLocalRule      `json:"map_local,omitempty"`
	// MaxBodySize bounds the message bodies buffered by body rules (default 2 MiB,
	// between 1 KiB and 32 MiB). Larger bodies pass through unmodified.
	MaxBodySize *byteformats.MemoryBytes `json:"max_body_size,omitempty"`
	Body        []MITMBodyRewriteRule    `json:"body,omitempty"`
	// ProtectedPorts are ports of listeners outside the core (the control application's
	// API) that internal rewrites must not reach on this machine, besides the ports of the
	// core's own inbounds, services and control APIs, which are protected without being
	// listed.
	ProtectedPorts badoption.Listable[uint16] `json:"protected_ports,omitempty"`
}

// MITMURLRewriteRule answers or redirects matching requests. Action is
// reject, reject-200, reject-img, reject-tinygif, reject-dict, reject-array,
// 302, 307 or header; Target is the redirect location, or for header the new
// URL (https://host[:port][/path]) the request is sent to without the client
// noticing.
type MITMURLRewriteRule struct {
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
}

// MITMHeaderRewriteRule edits the headers of matching requests or responses.
type MITMHeaderRewriteRule struct {
	ID         string                  `json:"id,omitempty"`
	Pattern    string                  `json:"pattern"`
	Scope      string                  `json:"scope" enum:"request,response"`
	Operations []MITMHeaderRewriteEdit `json:"operations,omitempty"`
}

// MITMHeaderRewriteEdit is one header operation.
type MITMHeaderRewriteEdit struct {
	Action string `json:"action" enum:"add,delete,replace,replace-regex"`
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Regex  string `json:"regex,omitempty"`
}

// MITMMapLocalRule answers matching requests locally. Exactly one of Body,
// BodyBase64 and BodyPath supplies the body.
type MITMMapLocalRule struct {
	ID         string                   `json:"id,omitempty"`
	Pattern    string                   `json:"pattern"`
	Status     int                      `json:"status,omitempty"`
	Headers    []MITMHeaderRewriteField `json:"headers,omitempty"`
	Body       string                   `json:"body,omitempty"`
	BodyBase64 string                   `json:"body_base64,omitempty"`
	BodyPath   string                   `json:"body_path,omitempty"`
}

// MITMHeaderRewriteField is one header field of a local response.
type MITMHeaderRewriteField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MITMBodyRewriteRule edits the bodies of matching requests or responses. Every
// matching rule applies, in list order; the edits of a rule apply in order, each
// to the result of the previous one.
type MITMBodyRewriteRule struct {
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern"`
	Scope   string `json:"scope" enum:"request,response"`
	// ContentTypes are case-insensitive substrings of the Content-Type. Empty
	// selects text, JSON, XML, JavaScript and form types for replace-regex and
	// application/json and +json types for the JSON edits.
	ContentTypes badoption.Listable[string] `json:"content_types,omitempty"`
	Edits        []MITMBodyRewriteEdit      `json:"edits,omitempty"`
}

// MITMBodyRewriteEdit is one body edit. replace-regex uses Regex and Value (a
// template with $1 or ${name}); the json-* edits use Path (a JSONPath subset) and,
// for json-set and json-append, Value (JSON text).
type MITMBodyRewriteEdit struct {
	Action string `json:"action" enum:"replace-regex,json-set,json-delete,json-append"`
	Regex  string `json:"regex,omitempty"`
	Path   string `json:"path,omitempty"`
	Value  string `json:"value,omitempty"`
}
