package script

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// $httpClient runtime limits that are not part of the host contract.
const (
	// MaxHTTPConcurrent is the most requests in flight at once across all scripts of a
	// Manager; a request that cannot get a place within httpSlotWait fails.
	MaxHTTPConcurrent = 32
	// MaxHTTPMemory bounds the response bytes all in-flight requests of a Manager may hold at
	// once: every request reserves its response limit (at most MaxHTTPResponse) before it
	// starts, so the worst case stays near this value instead of slots x 8 MiB.
	MaxHTTPMemory     = 128 << 20
	maxHTTPURL        = 8 << 10
	maxHTTPHeaderSize = 64 << 10
	maxHTTPOutbound   = 256
	// maxHTTPCalls bounds the $httpClient calls of one script call, refused ones included: the
	// refusals are answered through callbacks, which a hostile loop must not pile up.
	maxHTTPCalls = 4 * MaxHTTPRequests
)

// httpItem is one $httpClient call of a script call.
type httpItem struct {
	cb      goja.Callable
	req     *HTTPRequest
	timeout time.Duration
	binary  bool
	reserve int64
	// resp and errText are the outcome; errText empty means success.
	resp    *HTTPResponse
	errText string
}

// httpState is the $httpClient state of one script call. Everything but done is touched by
// the VM goroutine only.
type httpState struct {
	ctx    context.Context
	cancel context.CancelFunc
	calls  int
	// inflight requests run in goroutines; pending counts those plus the queued ones, the
	// calls whose answer comes through done.
	inflight int
	pending  int
	reserved int64
	queue    []*httpItem
	// ready holds the calls that fail before reaching the host; their callbacks run from the
	// event loop like any other.
	ready []*httpItem
	// done receives the finished requests. It holds MaxHTTPRequests items, as many as can
	// ever be started, so a request goroutine never blocks on it.
	done chan *httpItem
}

func (cs *callState) httpState() *httpState {
	if cs.http == nil {
		ctx, cancel := context.WithCancel(cs.ctx)
		cs.http = &httpState{ctx: ctx, cancel: cancel, done: make(chan *httpItem, MaxHTTPRequests)}
	}
	return cs.http
}

// cancelHTTP cancels the requests still in flight.
func (cs *callState) cancelHTTP() {
	if cs.http != nil {
		cs.http.cancel()
	}
}

// httpWaiting reports whether the event loop has to wait for or deliver $httpClient answers.
func (hs *httpState) active() bool {
	return hs != nil && (hs.pending > 0 || len(hs.ready) > 0)
}

// timeLeft is how long the call may still run.
func (cs *callState) timeLeft() time.Duration {
	if cs.deadline.IsZero() {
		return cs.timeout()
	}
	return time.Until(cs.deadline)
}

func (e *vmEntry) installHTTPNatives(setNative func(string, func(goja.FunctionCall) goja.Value)) {
	rt := e.rt
	setNative("http", func(call goja.FunctionCall) goja.Value {
		cb, ok := goja.AssertFunction(call.Argument(2))
		cs := e.cs
		if cs != nil && (cs.cfg.Type == PhaseRule || cs.cfg.Type == PhaseDNS) {
			// A request of a rule script is routed itself, through the rules that call the
			// script: refused outright, so that no cycle can start.
			panic(rt.NewTypeError("$httpClient is not available in rule and dns scripts"))
		}
		if !ok {
			// Without a callback nothing can be answered asynchronously.
			if cs != nil && cs.m.httpClient() == nil {
				panic(rt.NewTypeError("$httpClient is not available"))
			}
			panic(rt.NewTypeError("$httpClient: the callback must be a function"))
		}
		if cs == nil {
			panic(rt.NewTypeError("$httpClient is not available"))
		}
		if cs.done {
			return goja.Undefined()
		}
		hs := cs.httpState()
		hs.calls++
		if hs.calls > maxHTTPCalls {
			panic(rt.NewTypeError("$httpClient: too many requests"))
		}
		item := &httpItem{cb: cb}
		switch {
		case hs.calls > MaxHTTPRequests:
			item.errText = "too many requests"
		case cs.m.httpClient() == nil:
			item.errText = "$httpClient is not available"
		default:
			e.parseHTTPRequest(cs, item, call.Argument(0).String(), call.Argument(1))
		}
		if item.errText != "" {
			hs.ready = append(hs.ready, item)
			return goja.Undefined()
		}
		hs.pending++
		hs.queue = append(hs.queue, item)
		cs.pumpHTTP()
		return goja.Undefined()
	})
}

// parseHTTPRequest validates the arguments of one call into item.req; a refusal is item.errText.
func (e *vmEntry) parseHTTPRequest(cs *callState, item *httpItem, method string, opts goja.Value) {
	fail := func(text string) { item.errText = text }
	req := &HTTPRequest{Script: cs.cfg.Tag, Phase: cs.cfg.Type, Method: method}
	obj, isObj := opts.(*goja.Object)
	var rawURL string
	if isObj {
		s, ok := plainString(obj.Get("url"))
		if !ok {
			fail("url is required")
			return
		}
		rawURL = s
	} else {
		s, ok := plainString(opts)
		if !ok {
			fail("url is required")
			return
		}
		rawURL = s
	}
	if err := checkHTTPURL(rawURL); err != nil {
		fail(err.Error())
		return
	}
	req.URL = rawURL
	item.timeout = DefaultHTTPTimeout
	if isObj {
		if v := obj.Get("headers"); isSet(v) {
			headers, err := e.httpHeaders(v)
			if err != nil {
				fail(err.Error())
				return
			}
			req.Headers = headers
		}
		body, errText := e.httpBody(cs, obj)
		if errText != "" {
			fail(errText)
			return
		}
		req.Body = body
		if v := obj.Get("timeout"); isSet(v) {
			if secs := v.ToFloat(); !math.IsNaN(secs) && secs > 0 {
				item.timeout = time.Duration(min(secs, MaxHTTPTimeout.Seconds()) * float64(time.Second))
			}
		}
		for _, key := range []string{"node", "policy"} {
			if v := obj.Get(key); isSet(v) {
				s, ok := plainString(v)
				if !ok || len(s) > maxHTTPOutbound || strings.ContainsAny(s, "\x00\r\n") {
					fail("invalid " + key)
					return
				}
				req.Outbound = s
				break
			}
		}
		if v := obj.Get("insecure"); isSet(v) {
			req.Insecure = v.ToBoolean()
		}
		if v := obj.Get("auto-redirect"); isSet(v) {
			req.NoRedirect = !v.ToBoolean()
		}
		if v := obj.Get("binary-mode"); isSet(v) {
			item.binary = v.ToBoolean()
		}
	}
	item.timeout = min(item.timeout, MaxHTTPTimeout)
	req.Timeout = item.timeout
	item.req = req
}

func checkHTTPURL(raw string) error {
	if len(raw) > maxHTTPURL {
		return errors.New("url too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("url must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("url has no host")
	}
	if u.User != nil {
		return errors.New("credentials in the url are not allowed")
	}
	return nil
}

// httpHeaders reads the headers option: an object of strings, numbers or arrays of them.
func (e *vmEntry) httpHeaders(v goja.Value) ([]Header, error) {
	if obj, ok := v.(*goja.Object); ok && obj.ClassName() == "Array" {
		return nil, errors.New("headers must be an object")
	}
	list, err := headersFromObject(v)
	if err != nil {
		return nil, err
	}
	out := list[:0]
	size := 0
	for _, h := range list {
		if !validHeaderName(h.Name) {
			return nil, errors.New("invalid header name " + clipText(h.Name, 64))
		}
		if !validHeaderValue(h.Value) {
			return nil, errors.New("invalid value of header " + h.Name)
		}
		if hopByHop(h.Name) {
			continue
		}
		size += len(h.Name) + len(h.Value)
		if size > maxHTTPHeaderSize {
			return nil, errors.New("headers too large")
		}
		out = append(out, h)
	}
	return out, nil
}

func hopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "content-length",
		"proxy-connection", "proxy-authorization", "proxy-authenticate":
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "proxy-")
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// httpBody reads the body or body-base64 option and charges it to the call.
func (e *vmEntry) httpBody(cs *callState, obj *goja.Object) ([]byte, string) {
	b64 := obj.Get("body-base64")
	plain := obj.Get("body")
	hasB64, hasPlain := isSet(b64), isSet(plain)
	if hasB64 && hasPlain {
		return nil, "body and body-base64 are exclusive"
	}
	var data []byte
	switch {
	case hasB64:
		text, ok := plainString(b64)
		if !ok {
			return nil, "body-base64 must be a string"
		}
		if base64.StdEncoding.DecodedLen(len(text)) > MaxHTTPRequestBody+3 {
			return nil, "request body too large"
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimRight(strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, text), "="))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(text, "="))
		}
		if err != nil {
			return nil, "body-base64 is not valid base64"
		}
		data = decoded
	case hasPlain:
		if s, ok := plainString(plain); ok {
			if len(s) > MaxHTTPRequestBody {
				return nil, "request body too large"
			}
			data = []byte(s)
		} else if b, ok := bytesOf(plain); ok {
			if len(b) > MaxHTTPRequestBody {
				return nil, "request body too large"
			}
			data = append([]byte(nil), b...)
		} else if _, nested := plain.(*goja.Object); nested {
			return nil, "body must be a string or a Uint8Array"
		} else {
			data = []byte(plain.String())
		}
	default:
		return nil, ""
	}
	if len(data) > MaxHTTPRequestBody {
		return nil, "request body too large"
	}
	if !cs.charge(int64(len(data))) {
		e.overLimit()
	}
	return data, ""
}

// pumpHTTP starts queued requests while the call has room for them.
func (cs *callState) pumpHTTP() {
	hs := cs.http
	for len(hs.queue) > 0 && hs.inflight < MaxHTTPInflight {
		item := hs.queue[0]
		hs.queue[0] = nil
		hs.queue = hs.queue[1:]
		client := cs.m.httpClient()
		budget := min(int64(MaxHTTPResponse), AllocationLimit-cs.charged-hs.reserved)
		switch {
		case client == nil:
			item.errText = "$httpClient is not available"
		case budget <= 0:
			item.errText = "allocation limit reached"
		}
		if item.errText != "" {
			hs.pending--
			hs.ready = append(hs.ready, item)
			continue
		}
		item.reserve = budget
		item.req.MaxResponse = budget
		item.req.Timeout = max(min(item.timeout, cs.timeLeft()), time.Millisecond)
		hs.reserved += budget
		hs.inflight++
		go cs.m.httpDo(hs.ctx, client, item, hs.done)
	}
}

// httpDo performs one request in its own goroutine and reports it on done.
func (m *Manager) httpDo(ctx context.Context, client HTTPClient, item *httpItem, done chan<- *httpItem) {
	defer func() {
		if r := recover(); r != nil {
			item.resp, item.errText = nil, "internal error"
		}
		done <- item
	}()
	wait := time.NewTimer(httpSlotWait)
	select {
	case m.httpSlots <- struct{}{}:
		wait.Stop()
		defer func() { <-m.httpSlots }()
	case <-wait.C:
		item.errText = "too many concurrent requests"
		return
	case <-ctx.Done():
		wait.Stop()
		item.errText = "canceled"
		return
	}
	if m.httpMemory != nil {
		acquire, stop := context.WithTimeout(ctx, httpSlotWait)
		err := m.httpMemory.Acquire(acquire, item.req.MaxResponse)
		stop()
		if err != nil {
			item.errText = "too many concurrent requests"
			if ctx.Err() != nil {
				item.errText = "canceled"
			}
			return
		}
		defer m.httpMemory.Release(item.req.MaxResponse)
	}
	rctx, cancel := context.WithTimeout(ctx, item.req.Timeout)
	defer cancel()
	resp, err := client.Do(rctx, item.req)
	switch {
	case err != nil:
		item.errText = httpErrorText(err)
	case resp == nil:
		item.errText = "empty response"
	case int64(len(resp.Body)) > item.req.MaxResponse:
		item.errText = "response too large"
	default:
		item.resp = resp
	}
}

func httpErrorText(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	text := strings.TrimSpace(err.Error())
	if text == "" {
		text = "request failed"
	}
	return clipText(text, maxErrorText)
}

// runHTTPCallback calls the callback of a finished (or refused) request. It returns the
// failure of the call, nil when the callback returned.
func (e *vmEntry) runHTTPCallback(cs *callState, item *httpItem, fromHost bool) error {
	hs := cs.http
	if fromHost {
		hs.pending--
		hs.inflight--
		hs.reserved -= item.reserve
		cs.pumpHTTP()
	}
	rt := e.rt
	// A call whose context is canceled is over: its answers are not delivered (a request
	// that ended because of the cancellation must not look like an ordinary failure).
	if cs.ctx.Err() != nil {
		cs.interrupt(rt, reasonCancel)
		return &goja.InterruptedError{}
	}
	args := []goja.Value{goja.Null(), goja.Undefined(), goja.Undefined()}
	if item.errText != "" {
		args[0] = rt.ToValue(item.errText)
	} else {
		resp := item.resp
		if !cs.charge(int64(len(resp.Body))) {
			cs.interrupt(rt, reasonLimit)
			return &goja.InterruptedError{}
		}
		headers := resp.Headers
		if len(headers) > maxHeaders {
			headers = headers[:maxHeaders]
		}
		obj := rt.NewObject()
		_ = obj.Set("status", resp.Status)
		_ = obj.Set("statusCode", resp.Status)
		_ = obj.Set("headers", e.headersObject(headers))
		args[1] = obj
		if item.binary {
			body := resp.Body
			if body == nil {
				body = []byte{}
			}
			args[2] = e.newUint8Array(body)
		} else {
			args[2] = rt.ToValue(string(resp.Body))
		}
	}
	item.resp = nil
	_, err := item.cb(goja.Undefined(), args...)
	return err
}

// httpSlotWait is how long a request waits for a place among the Manager's in-flight
// requests; a variable so that tests can shorten it.
var httpSlotWait = 5 * time.Second
