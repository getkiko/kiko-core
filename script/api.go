package script

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// Version is reported as $environment["kiko-version"]. The host may set it before
// scripts run.
var Version = "dev"

func (e *vmEntry) installAPI(m *Manager, sc *Script) {
	rt := e.rt
	global := rt.GlobalObject()
	store := rt.NewObject()
	nsKey := func(key string) (string, string) {
		if strings.HasPrefix(key, SharedPrefix) {
			return SharedNamespace, key[len(SharedPrefix):]
		}
		return sc.cfg.Tag, key
	}
	validKey := func(key string) bool { return key != "" && len(key) <= MaxStoreKey }
	_ = store.Set("read", func(call goja.FunctionCall) goja.Value {
		cs := e.cs
		key := call.Argument(0).String()
		if cs == nil || !validKey(key) {
			return goja.Null()
		}
		ns, k := nsKey(key)
		value, ok, err := cs.store.Get(ns, k)
		if err != nil {
			e.log("warn", "$persistentStore.read: "+err.Error())
			return goja.Null()
		}
		if !ok {
			return goja.Null()
		}
		return rt.ToValue(value)
	})
	_ = store.Set("write", func(call goja.FunctionCall) goja.Value {
		cs := e.cs
		key := call.Argument(1).String()
		if cs == nil || !validKey(key) || call.Argument(1) == nil || goja.IsUndefined(call.Argument(1)) {
			return rt.ToValue(false)
		}
		value := call.Argument(0)
		if goja.IsNull(value) || goja.IsUndefined(value) {
			return rt.ToValue(false)
		}
		text := value.String()
		if len(text) > MaxStoreValue {
			e.log("warn", "$persistentStore.write: value larger than 1 MiB")
			return rt.ToValue(false)
		}
		ns, k := nsKey(key)
		if err := cs.store.Set(ns, k, text); err != nil {
			e.log("warn", "$persistentStore.write: "+err.Error())
			return rt.ToValue(false)
		}
		return rt.ToValue(true)
	})
	_ = store.Set("remove", func(call goja.FunctionCall) goja.Value {
		cs := e.cs
		key := call.Argument(0).String()
		if cs == nil || !validKey(key) {
			return rt.ToValue(false)
		}
		ns, k := nsKey(key)
		if err := cs.store.Delete(ns, k); err != nil {
			e.log("warn", "$persistentStore.remove: "+err.Error())
			return rt.ToValue(false)
		}
		return rt.ToValue(true)
	})
	_ = global.Set("$persistentStore", store)

	notification := rt.NewObject()
	_ = notification.Set("post", func(call goja.FunctionCall) goja.Value {
		cs := e.cs
		if cs == nil {
			return goja.Undefined()
		}
		now := time.Now()
		if !cs.dry && !cs.sc.state.allowNotification(now) || cs.dry && cs.notified >= maxNotifyRate {
			e.log("warn", "$notification.post: rate limit reached")
			return goja.Undefined()
		}
		cs.notified++
		n := Notification{
			Script:   cs.cfg.Tag,
			Title:    clipText(argString(call, 0), 256),
			Subtitle: clipText(argString(call, 1), 256),
			Body:     clipText(argString(call, 2), 2048),
			Time:     now,
		}
		if opts, ok := call.Argument(3).(*goja.Object); ok {
			for _, key := range []string{"url", "open-url", "openUrl"} {
				if v := opts.Get(key); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
					n.URL = clipText(v.String(), 2048)
					break
				}
			}
		} else if s, ok := call.Argument(3).Export().(string); ok {
			n.URL = clipText(s, 2048)
		}
		if cs.dry {
			cs.res.Notifications = append(cs.res.Notifications, n)
		} else if notifier := cs.m.notifier(); notifier != nil {
			notifier.Notify(n)
		}
		return goja.Undefined()
	})
	_ = global.Set("$notification", notification)

	env := rt.NewObject()
	system := runtime.GOOS
	if system == "darwin" {
		system = "macOS"
	}
	_ = env.Set("system", system)
	_ = env.Set("language", "en")
	_ = env.Set("kiko-version", Version)
	_ = global.Set("$environment", env)

	_ = global.Set("$done", func(call goja.FunctionCall) goja.Value {
		cs := e.cs
		if cs == nil || cs.done {
			return goja.Undefined()
		}
		cs.done = true
		if err := e.parseDone(cs, call.Argument(0)); err != nil {
			if cs.interrupted() != "" {
				// The call was interrupted while the value was read: the failure is the
				// interrupt's (canceled, timeout, limit), not a bad $done value.
				cs.done = false
				cs.res.Action, cs.res.Error = ActionNone, ""
				return goja.Undefined()
			}
			cs.res.Action = ActionError
			cs.res.Error = clipText(err.Error(), maxErrorText)
		}
		return goja.Undefined()
	})
}

func argString(call goja.FunctionCall, i int) string {
	v := call.Argument(i)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	return v.String()
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !validUTF8Tail(s) {
		s = s[:len(s)-1]
	}
	return s
}

func validUTF8Tail(s string) bool {
	return strings.ToValidUTF8(s, "") == s
}

// callArgs builds the arguments of the script wrapper: $request, $response, $argument and
// $script are parameters of the per-call function, not globals, so nothing is left behind and
// a script that freezes the global object cannot break the next call.
func (e *vmEntry) callArgs(cs *callState) []goja.Value {
	rt := e.rt
	cfg := cs.cfg
	args := []goja.Value{goja.Undefined(), goja.Undefined(), rt.ToValue(cfg.Argument), nil}
	if cfg.Type == PhaseRule || cfg.Type == PhaseDNS {
		args = append(args, goja.Undefined())
	}
	script := rt.NewObject()
	_ = script.Set("name", cfg.Tag)
	_ = script.Set("type", string(cfg.Type))
	_ = script.Set("startTime", cs.start.UnixMilli())
	args[3] = script
	in := cs.in
	if in == nil {
		return args
	}
	if r := in.Rule; r != nil {
		args[0] = r.object(rt)
		args[4] = rt.ToValue(r.Domain)
	}
	if r := in.Request; r != nil {
		obj := rt.NewObject()
		_ = obj.Set("url", r.URL)
		_ = obj.Set("method", r.Method)
		_ = obj.Set("headers", e.headersObject(r.Headers))
		_ = obj.Set("id", r.ID)
		if r.HasBody && cfg.RequiresBody {
			_ = obj.Set("body", e.bodyValue(cs, r.Body))
		}
		args[0] = obj
	}
	if r := in.Response; r != nil {
		obj := rt.NewObject()
		_ = obj.Set("status", r.Status)
		_ = obj.Set("statusCode", r.Status)
		_ = obj.Set("headers", e.headersObject(r.Headers))
		if r.HasBody && cfg.RequiresBody {
			_ = obj.Set("body", e.bodyValue(cs, r.Body))
		}
		args[1] = obj
	}
	return args
}

// bodyValue converts a body for the script: a Uint8Array with binary_body, else a string.
// The bytes are copied, so a script cannot change the buffer the engine holds.
func (e *vmEntry) bodyValue(cs *callState, body []byte) goja.Value {
	if !cs.charge(int64(len(body))) {
		e.overLimit()
	}
	if cs.cfg.BinaryBody {
		return e.newUint8Array(bytes.Clone(body))
	}
	cs.inputStr = string(body)
	return e.rt.ToValue(cs.inputStr)
}

// headersObject builds the headers object: keys keep the case of their first field, values
// of repeated fields are joined by ", ".
func (e *vmEntry) headersObject(headers []Header) *goja.Object {
	obj := e.rt.NewObject()
	type entry struct {
		key   string
		value string
	}
	var order []string
	index := make(map[string]*entry, len(headers))
	for _, h := range headers {
		lower := strings.ToLower(h.Name)
		if cur, ok := index[lower]; ok {
			cur.value += ", " + h.Value
			continue
		}
		index[lower] = &entry{key: h.Name, value: h.Value}
		order = append(order, lower)
	}
	for _, lower := range order {
		cur := index[lower]
		_ = obj.Set(cur.key, cur.value)
	}
	return obj
}

var statusPattern = regexp.MustCompile(`(?:^|\s)([1-5][0-9][0-9])(?:\s|$)`)

func parseStatus(v goja.Value) (int, error) {
	if _, isObj := v.(*goja.Object); isObj {
		return 0, errors.New("invalid status")
	}
	switch x := v.Export().(type) {
	case int64:
		return checkStatus(int(x))
	case float64:
		return checkStatus(int(x))
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return checkStatus(n)
		}
		if m := statusPattern.FindStringSubmatch(x); m != nil {
			n, _ := strconv.Atoi(m[1])
			return checkStatus(n)
		}
	}
	return 0, errors.New("invalid status")
}

func checkStatus(n int) (int, error) {
	if n < 100 || n > 599 {
		return 0, fmt.Errorf("invalid status %d", n)
	}
	return n, nil
}

// plainString returns v when it is a primitive string. Objects are never exported: Export
// walks arrays and objects recursively, and a deeply nested one overflows the Go stack.
func plainString(v goja.Value) (string, bool) {
	if v == nil {
		return "", false
	}
	if _, isObj := v.(*goja.Object); isObj {
		return "", false
	}
	s, ok := v.Export().(string)
	return s, ok
}

func isSet(v goja.Value) bool {
	return v != nil && !goja.IsUndefined(v) && !goja.IsNull(v)
}

// valueBytes converts a body value written by a script.
func valueBytes(v goja.Value) ([]byte, error) {
	if s, ok := plainString(v); ok {
		return []byte(s), nil
	}
	if b, ok := bytesOf(v); ok {
		return bytes.Clone(b), nil
	}
	if _, isObj := v.(*goja.Object); !isObj {
		switch x := v.Export().(type) {
		case int64, float64, bool:
			return []byte(fmt.Sprint(x)), nil
		}
	}
	return nil, errors.New("body must be a string or a Uint8Array")
}

// headersFromObject reads a headers object into a list for a response a script creates.
func headersFromObject(v goja.Value) ([]Header, error) {
	obj, ok := v.(*goja.Object)
	if !ok {
		return nil, errors.New("headers must be an object")
	}
	var out []Header
	keys := obj.Keys()
	if len(keys) > maxHeaders {
		return nil, errors.New("too many headers")
	}
	for _, key := range keys {
		values, err := headerValues(obj.Get(key))
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", key, err)
		}
		for _, value := range values {
			out = append(out, Header{Name: key, Value: value})
		}
		if len(out) > maxHeaders {
			return nil, errors.New("too many headers")
		}
	}
	return out, nil
}

// headerValues returns the values of one header property: a string, a number, or an array of
// them (one field each). null and undefined mean no value.
func headerValues(v goja.Value) ([]string, error) {
	if !isSet(v) {
		return nil, nil
	}
	if obj, ok := v.(*goja.Object); ok {
		if obj.ClassName() != "Array" {
			return nil, errors.New("value must be a string")
		}
		n := obj.Get("length").ToInteger()
		if n > maxHeaders {
			return nil, errors.New("too many values")
		}
		out := make([]string, 0, n)
		for i := int64(0); i < n; i++ {
			item := obj.Get(strconv.FormatInt(i, 10))
			if _, nested := item.(*goja.Object); nested {
				return nil, errors.New("array items must be strings")
			}
			switch x := item.Export().(type) {
			case string:
				out = append(out, x)
			case int64, float64, bool:
				out = append(out, fmt.Sprint(x))
			default:
				return nil, errors.New("array items must be strings")
			}
		}
		return out, nil
	}
	switch x := v.Export().(type) {
	case string:
		return []string{x}, nil
	case int64, float64, bool:
		return []string{fmt.Sprint(x)}, nil
	}
	return nil, errors.New("value must be a string")
}

// mergeHeaders applies the headers object a script returned to orig. A string value that
// differs from the joined original replaces every field of that name (at the position of the
// first one); names the object lacks are removed; fields whose value is unchanged stay as
// they were, so repeated fields such as Set-Cookie survive.
func mergeHeaders(orig []Header, v goja.Value) ([]Header, bool, error) {
	obj, ok := v.(*goja.Object)
	if !ok {
		return nil, false, errors.New("headers must be an object")
	}
	type want struct {
		key    string
		values []string
	}
	wants := map[string]*want{}
	var order []string
	keys := obj.Keys()
	if len(keys) > maxHeaders {
		return nil, false, errors.New("too many headers")
	}
	for _, key := range keys {
		values, err := headerValues(obj.Get(key))
		if err != nil {
			return nil, false, fmt.Errorf("header %s: %w", key, err)
		}
		lower := strings.ToLower(key)
		if lower == "set-cookie" && len(values) == 1 {
			values = splitSetCookie(values[0])
		}
		if _, seen := wants[lower]; !seen {
			order = append(order, lower)
		}
		wants[lower] = &want{key: key, values: values}
	}
	if len(order) > maxHeaders {
		return nil, false, errors.New("too many headers")
	}
	joined := map[string]string{}
	count := map[string]int{}
	for _, h := range orig {
		lower := strings.ToLower(h.Name)
		if count[lower] > 0 {
			joined[lower] += ", " + h.Value
		} else {
			joined[lower] = h.Value
		}
		count[lower]++
	}
	out := make([]Header, 0, len(orig)+4)
	handled := map[string]bool{}
	changed := false
	for _, h := range orig {
		lower := strings.ToLower(h.Name)
		w, present := wants[lower]
		if !present {
			changed = true
			continue
		}
		if sameValues(w.values, joined[lower], lower) {
			out = append(out, h)
			continue
		}
		changed = true
		if handled[lower] {
			continue
		}
		handled[lower] = true
		for _, value := range w.values {
			out = append(out, Header{Name: w.key, Value: value})
		}
	}
	for _, lower := range order {
		if count[lower] > 0 {
			continue
		}
		w := wants[lower]
		for _, value := range w.values {
			out = append(out, Header{Name: w.key, Value: value})
			changed = true
		}
	}
	return out, changed, nil
}

// parseDone reads the value passed to $done into cs.res.
func (e *vmEntry) parseDone(cs *callState, v goja.Value) error {
	res := cs.res
	cfg := cs.cfg
	if cfg.Type == PhaseGeneric || cfg.Type == PhaseCron || cfg.Type == PhaseRule || cfg.Type == PhaseDNS {
		if !isSet(v) {
			return nil
		}
		out, err := e.stringify(goja.Undefined(), v)
		if err != nil {
			return fmt.Errorf("$done value is not JSON: %w", err)
		}
		text, ok := plainString(out)
		if !ok {
			return nil
		}
		if len(text) > 1<<20 {
			return errors.New("$done value larger than 1 MiB")
		}
		res.Output = text
		return nil
	}
	obj, ok := v.(*goja.Object)
	if !ok {
		return nil
	}
	if abort := obj.Get("abort"); isSet(abort) && abort.ToBoolean() {
		res.Action = ActionAbort
		return nil
	}
	in := cs.in
	if cfg.Type == PhaseRequest {
		src := obj
		explicit := false
		if r, ok := obj.Get("response").(*goja.Object); ok {
			src, explicit = r, true
		}
		if explicit || isSet(obj.Get("status")) || isSet(obj.Get("statusCode")) {
			resp, err := e.readResponse(src, 200)
			if err != nil {
				return err
			}
			res.Action = ActionRespond
			res.Response = resp
			return nil
		}
		if u := obj.Get("url"); isSet(u) {
			if s, ok := plainString(u); ok && s != in.Request.URL {
				res.URL = s
			}
		}
	} else if r, ok := obj.Get("response").(*goja.Object); ok && !isSet(obj.Get("status")) {
		obj = r
	}
	if h := obj.Get("headers"); isSet(h) {
		var orig []Header
		if cfg.Type == PhaseRequest {
			orig = in.Request.Headers
		} else if in.Response != nil {
			orig = in.Response.Headers
		}
		merged, changed, err := mergeHeaders(orig, h)
		if err != nil {
			return err
		}
		if changed {
			res.Headers, res.HeadersChanged = merged, true
		}
	}
	if cfg.Type == PhaseResponse {
		s := obj.Get("status")
		if !isSet(s) {
			s = obj.Get("statusCode")
		}
		if isSet(s) {
			n, err := parseStatus(s)
			if err != nil {
				return err
			}
			if in.Response != nil && n != in.Response.Status {
				res.Status = n
			}
		}
	}
	if b := obj.Get("body"); isSet(b) {
		data, err := valueBytes(b)
		if err != nil {
			return err
		}
		switch {
		case !cfg.RequiresBody:
			e.log("warn", "$done body ignored: the script has requires_body off")
		default:
			var orig []byte
			if cfg.Type == PhaseRequest {
				orig = in.Request.Body
			} else if in.Response != nil {
				orig = in.Response.Body
			}
			same := bytes.Equal(data, orig)
			if s, isString := plainString(b); isString && s == cs.inputStr && cs.inputStr != "" {
				same = true
			}
			if !same {
				res.Body, res.BodyChanged = data, true
			}
		}
	}
	if res.URL != "" || res.HeadersChanged || res.BodyChanged || res.Status != 0 {
		res.Action = ActionModify
	}
	return nil
}

func (e *vmEntry) readResponse(src *goja.Object, defaultStatus int) (*Response, error) {
	resp := &Response{Status: defaultStatus}
	s := src.Get("status")
	if !isSet(s) {
		s = src.Get("statusCode")
	}
	if isSet(s) {
		n, err := parseStatus(s)
		if err != nil {
			return nil, err
		}
		resp.Status = n
	}
	if h := src.Get("headers"); isSet(h) {
		headers, err := headersFromObject(h)
		if err != nil {
			return nil, err
		}
		resp.Headers = headers
	}
	if b := src.Get("body"); isSet(b) {
		data, err := valueBytes(b)
		if err != nil {
			return nil, err
		}
		resp.Body, resp.HasBody = data, true
	}
	return resp, nil
}

// sameValues reports whether the values a script returned for a header are the joined value
// it was given (so the original fields stay as they are).
func sameValues(values []string, joined, lower string) bool {
	if lower == "set-cookie" {
		return strings.Join(values, ", ") == joined
	}
	return len(values) == 1 && values[0] == joined
}

// splitSetCookie splits a Set-Cookie value that holds several cookies joined by ", " (the form
// scripts see) into one value per cookie. A comma starts a new cookie only when a name and
// "=" follow, so dates in Expires stay whole.
func splitSetCookie(value string) []string {
	var out []string
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(value) && (value[j] == ' ' || value[j] == '\t') {
			j++
		}
		k := j
		for k < len(value) && value[k] != '=' && value[k] != ';' && value[k] != ',' && value[k] != ' ' && value[k] != '\t' {
			k++
		}
		if k > j && k < len(value) && value[k] == '=' {
			out = append(out, value[start:i])
			start = j
			i = j - 1
		}
	}
	return append(out, value[start:])
}
