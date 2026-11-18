package option

import (
	"encoding/json"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badjson"
)

type ShadowTLSInboundOptions struct {
	ListenOptions
	Version                int                                                  `json:"version,omitempty" enum:"1,2,3"`
	Password               string                                               `json:"password,omitempty"`
	Users                  []ShadowTLSUser                                      `json:"users,omitempty"`
	Handshake              ShadowTLSHandshakeOptions                            `json:"handshake,omitempty"`
	HandshakeForServerName *badjson.TypedMap[string, ShadowTLSHandshakeOptions] `json:"handshake_for_server_name,omitempty"`
	StrictMode             bool                                                 `json:"strict_mode,omitempty"`
	WildcardSNI            WildcardSNI                                          `json:"wildcard_sni,omitempty"`
}

type WildcardSNI int

const (
	ShadowTLSWildcardSNIOff WildcardSNI = iota
	ShadowTLSWildcardSNIAuthed
	ShadowTLSWildcardSNIAll
)

func (w WildcardSNI) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.String())
}

func (w WildcardSNI) String() string {
	switch w {
	case ShadowTLSWildcardSNIOff:
		return "off"
	case ShadowTLSWildcardSNIAuthed:
		return "authed"
	case ShadowTLSWildcardSNIAll:
		return "all"
	default:
		panic("unknown wildcard SNI value")
	}
}

func (w *WildcardSNI) UnmarshalJSON(bytes []byte) error {
	var valueString string
	err := json.Unmarshal(bytes, &valueString)
	if err != nil {
		return err
	}
	switch valueString {
	case "off", "":
		*w = ShadowTLSWildcardSNIOff
	case "authed":
		*w = ShadowTLSWildcardSNIAuthed
	case "all":
		*w = ShadowTLSWildcardSNIAll
	default:
		return E.New("unknown wildcard SNI value: ", valueString)
	}
	return nil
}

func (w WildcardSNI) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.StringEnum("", "off", "authed", "all"), nil
}

type ShadowTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type ShadowTLSHandshakeOptions struct {
	ServerOptions
	DialerOptions
}

type ShadowTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	Version  int    `json:"version,omitempty" enum:"1,2,3"`
	Password string `json:"password,omitempty"`
	// HandshakeRetries is the number of times to redial and retry the handshake
	// after a failed TLS handshake. The default 0 disables retries.
	//
	// It is meant for detours to burrow port scanning hole punching: a scan may
	// occasionally hit a half-dead connection on which the TLS handshake fails,
	// and a retry punches a new connection. A TLS handshake is a round trip in
	// both directions, so a successful one proves the connection works both
	// ways, and the burrow layer does not need its own probe bytes. A normal
	// detour succeeds on the first handshake and never retries.
	HandshakeRetries int `json:"handshake_retries,omitempty"`
	OutboundTLSOptionsContainer
}
