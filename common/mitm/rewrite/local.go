package rewrite

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

// Embedded bodies of the reject actions.
var (
	// TinyGIF is a 1x1 transparent GIF (43 bytes).
	TinyGIF = []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
		0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
	}
	EmptyDict  = []byte("{}")
	EmptyArray = []byte("[]")
)

// LocalResponse is an answer produced without asking the upstream. It is
// shared between requests: callers must not modify any field or slice.
type LocalResponse struct {
	// Abort means no response is sent: the connection is closed (h1) or the
	// stream is reset (h2).
	Abort   bool
	Status  int
	Headers []flow.Header // includes Content-Length
	Body    []byte
	// Hit is the record of the rule that produced the answer.
	Hit flow.RewriteHit
}

func newLocal(kind, id, action string, status int, headers []flow.Header, body []byte) *LocalResponse {
	h := make([]flow.Header, 0, len(headers)+1)
	h = append(h, headers...)
	h = append(h, flow.Header{Name: "Content-Length", Value: strconv.Itoa(len(body))})
	return &LocalResponse{
		Status:  status,
		Headers: h,
		Body:    body,
		Hit:     flow.RewriteHit{Kind: kind, Rule: id, Action: action, Status: status},
	}
}

func fixedAnswer(id, action string) *LocalResponse {
	switch action {
	case ActionReject:
		return &LocalResponse{Abort: true, Hit: flow.RewriteHit{Kind: KindURL, Rule: id, Action: action}}
	case ActionReject200:
		return newLocal(KindURL, id, action, 200, []flow.Header{{Name: "Content-Type", Value: "text/plain"}}, nil)
	case ActionRejectImg, ActionRejectGIF:
		return newLocal(KindURL, id, action, 200, []flow.Header{{Name: "Content-Type", Value: "image/gif"}}, TinyGIF)
	case ActionRejectDict:
		return newLocal(KindURL, id, action, 200, []flow.Header{{Name: "Content-Type", Value: "application/json"}}, EmptyDict)
	case ActionRejectArray:
		return newLocal(KindURL, id, action, 200, []flow.Header{{Name: "Content-Type", Value: "application/json"}}, EmptyArray)
	}
	return nil
}

// redirect answers a 302/307 rule for url. It returns nil when the expanded
// location is not an absolute http(s) URL free of control characters, so a
// capture group cannot inject headers or a foreign scheme.
func (r *urlRule) redirect(url []byte) *LocalResponse {
	match := r.re.FindSubmatchIndex(url)
	if match == nil {
		return nil
	}
	location := string(r.re.Expand(nil, []byte(r.target), url, match))
	if !validLocation(location) {
		return nil
	}
	status := 302
	if r.action == ActionTemporary {
		status = 307
	}
	local := newLocal(KindURL, r.id, r.action, status, []flow.Header{{Name: "Location", Value: location}}, nil)
	local.Hit.Target = location
	return local
}

func validLocation(s string) bool {
	if len(s) > maxValue {
		return false
	}
	lower := strings.ToLower(s[:min(len(s), 8)])
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// Local returns the answer that replaces the upstream exchange, or nil when
// the request goes upstream.
func (p *Plan) Local() *LocalResponse {
	if p == nil {
		return nil
	}
	return p.local
}

// HasRequestEdits reports whether header rules apply to the request.
func (p *Plan) HasRequestEdits() bool { return p != nil && len(p.request) > 0 }

// HasResponseEdits reports whether header rules apply to the response.
func (p *Plan) HasResponseEdits() bool { return p != nil && len(p.response) > 0 }
