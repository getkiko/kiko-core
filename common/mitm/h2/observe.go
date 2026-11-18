package h2

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

// observed reports one stream to Options.Observer. A nil *observed ignores
// everything, so the relay tests it only where it changes behavior.
type observed struct {
	ex   flow.Exchange
	req  flow.Body
	resp flow.Body
	done bool
}

// observe starts the Exchange of a request that passed the head checks.
func (s *session) observe(r *http.Request, header http.Header, scheme string) *observed {
	ex := s.opts.Observer.NewExchange(s.opts.Connection)
	ob := &observed{ex: ex, req: ex.RequestBody(), resp: ex.ResponseBody()}
	ex.RequestHead(flow.RequestHead{
		Method:    r.Method,
		Scheme:    scheme,
		Authority: r.Host,
		Path:      r.RequestURI,
		Proto:     "h2",
		Headers:   flowHeaders(header),
	})
	return ob
}

// finish ends the Exchange once; later calls are ignored.
func (o *observed) finish(err error) {
	if o == nil || o.done {
		return
	}
	o.done = true
	o.ex.Finish(err)
}

func (o *observed) mark(point flow.Point) {
	if o != nil {
		o.ex.Mark(point, time.Now())
	}
}

func (o *observed) markAt(point flow.Point, at time.Time) {
	if o != nil {
		o.ex.Mark(point, at)
	}
}

func (o *observed) informational(code int, header http.Header) {
	if o != nil {
		o.ex.Informational(code, flowHeaders(header))
	}
}

func (o *observed) responseHead(status int, header http.Header) {
	if o != nil {
		o.ex.ResponseHead(status, flowHeaders(header))
	}
}

func (o *observed) trailers(side flow.Side, header http.Header) {
	if o != nil && len(header) > 0 {
		o.ex.Trailers(side, flowHeaders(header))
	}
}

// flowHeaders lists header fields with lower-case names, as HTTP/2 sends them.
// net/http keeps no field order, so fields are sorted by name; values of one
// name keep their order.
func flowHeaders(header http.Header) []flow.Header {
	if len(header) == 0 {
		return nil
	}
	names := make([]string, 0, len(header))
	count := 0
	for name, values := range header {
		names = append(names, name)
		count += len(values)
	}
	sort.Strings(names)
	out := make([]flow.Header, 0, count)
	for _, name := range names {
		lower := strings.ToLower(name)
		for _, value := range header[name] {
			out = append(out, flow.Header{Name: lower, Value: value})
		}
	}
	return out
}
