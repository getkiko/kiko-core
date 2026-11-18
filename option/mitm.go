package option

import (
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
}

// MITMCaptureSettings is MITMCaptureOptions with defaults applied.
type MITMCaptureSettings struct {
	Enabled    bool
	Body       bool
	MaxBody    int64
	MaxMemory  int64
	MaxRecords int
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
