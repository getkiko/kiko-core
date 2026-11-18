// Package dnsmonitor implements optional, bounded DNS observability. It never
// participates in routing decisions and does not wrap the public DNS interfaces.
package dnsmonitor

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const SchemaVersion = 1

type Question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type Message struct {
	ID               uint16     `json:"id"`
	Rcode            string     `json:"rcode"`
	Opcode           int        `json:"opcode"`
	Flags            []string   `json:"flags,omitempty"`
	Questions        []Question `json:"questions,omitempty"`
	Answer           []Record   `json:"answer,omitempty"`
	Authority        []Record   `json:"authority,omitempty"`
	Additional       []Record   `json:"additional,omitempty"`
	Size             int        `json:"size"`
	TruncatedCapture bool       `json:"truncated_capture,omitempty"`
	Wire             []byte     `json:"wire,omitempty"`
}

type Failure struct {
	Kind    string `json:"kind"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type Source struct {
	Inbound     string `json:"inbound,omitempty"`
	Address     string `json:"address,omitempty"`
	Destination string `json:"destination,omitempty"`
	Network     string `json:"network,omitempty"`
	Process     string `json:"process,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	PID         uint32 `json:"pid,omitempty"`
	User        string `json:"user,omitempty"`
}

// Connection is frozen when a socket is acquired. A reused socket keeps the
// original chain even after a selector has changed its current node.
type Connection struct {
	owner            *Manager
	ID               string    `json:"id"`
	CreatedAt        time.Time `json:"created_at"`
	Protocol         string    `json:"protocol"`
	Configured       string    `json:"configured,omitempty"`
	Local            string    `json:"local,omitempty"`
	Peer             string    `json:"peer,omitempty"`
	PeerEvidence     string    `json:"peer_evidence"`
	Outbound         []string  `json:"outbound,omitempty"`
	OutboundEvidence string    `json:"outbound_evidence"`
	TLSVersion       string    `json:"tls_version,omitempty"`
	ServerName       string    `json:"server_name,omitempty"`
	ALPN             string    `json:"alpn,omitempty"`
}

type Attempt struct {
	ID          string      `json:"id"`
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  *time.Time  `json:"finished_at,omitempty"`
	Resolver    string      `json:"resolver"`
	Transport   string      `json:"transport"`
	Protocol    string      `json:"protocol"`
	Endpoint    string      `json:"endpoint,omitempty"`
	NetworkUsed bool        `json:"network_used"`
	Visibility  string      `json:"visibility"`
	Connection  *Connection `json:"connection,omitempty"`
	Reused      bool        `json:"reused"`
	WireID      uint16      `json:"wire_id"`
	SentAt      *time.Time  `json:"sent_at,omitempty"`
	FirstByteAt *time.Time  `json:"first_byte_at,omitempty"`
	HTTPVersion string      `json:"http_version,omitempty"`
	HTTPStatus  int         `json:"http_status,omitempty"`
	StreamID    string      `json:"stream_id,omitempty"`
	Response    *Message    `json:"response,omitempty"`
	Error       *Failure    `json:"error,omitempty"`
	Diagnostics []string    `json:"diagnostics,omitempty"`
}

type Query struct {
	ID                string     `json:"id"`
	ParentID          string     `json:"parent_id,omitempty"`
	OperationID       string     `json:"operation_id,omitempty"`
	Revision          uint64     `json:"revision,string"`
	Seq               uint64     `json:"seq,string"`
	StartedAt         time.Time  `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	DurationMS        float64    `json:"duration_ms"`
	Role              string     `json:"role"`
	Status            string     `json:"status"`
	Source            Source     `json:"source"`
	Questions         []Question `json:"questions"`
	ResolvedAddresses []string   `json:"resolved_addresses,omitempty"`
	Request           *Message   `json:"request,omitempty"`
	Response          *Message   `json:"response,omitempty"`
	Resolver          string     `json:"resolver,omitempty"`
	Transport         string     `json:"transport,omitempty"`
	// Candidates are the servers of a concurrent query; Resolver is the one
	// that answered.
	Candidates    []string  `json:"candidates,omitempty"`
	Cache         string    `json:"cache,omitempty"`
	SharedWith    string    `json:"shared_with,omitempty"`
	PolicyResult  string    `json:"policy_result,omitempty"`
	Policy        []string  `json:"policy,omitempty"`
	Attempts      []Attempt `json:"attempts,omitempty"`
	Error         *Failure  `json:"error,omitempty"`
	Delivery      string    `json:"delivery,omitempty"`
	DeliveryError *Failure  `json:"delivery_error,omitempty"`
	Incomplete    bool      `json:"incomplete,omitempty"`
	Rewritten     string    `json:"rewritten,omitempty"`
	// Scripts are the dns script actions that ran for the query, in order.
	Scripts []ScriptRun `json:"scripts,omitempty"`
}

// ScriptRun is the result of one dns script action.
type ScriptRun struct {
	Tag string `json:"tag"`
	// Outcome is answer, server, pass, reject (the script failed and on_error is reject),
	// error (the script failed and the query went on) or maybe (a policy test, script not run).
	Outcome string `json:"outcome"`
	// Detail is the answer, the server tag or the error text.
	Detail     string  `json:"detail,omitempty"`
	Cached     bool    `json:"cached,omitempty"`
	DurationMS float64 `json:"duration_ms"`
}

func failure(err error, stage string) *Failure {
	if err == nil {
		return nil
	}
	kind := "error"
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		kind = "timeout"
	case errors.Is(err, context.Canceled):
		kind = "canceled"
	}
	return &Failure{Kind: kind, Stage: stage, Message: clip(err.Error(), 2048)}
}

func clip(s string, limit int) string {
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

func snapshot(msg *dns.Msg, wire bool) *Message {
	if msg == nil {
		return nil
	}
	m := &Message{ID: msg.Id, Rcode: dns.RcodeToString[msg.Rcode], Opcode: msg.Opcode, Size: msg.Len()}
	if m.Rcode == "" {
		m.Rcode = strconv.Itoa(msg.Rcode)
	}
	for _, q := range msg.Question {
		if len(m.Questions) == 8 {
			m.TruncatedCapture = true
			break
		}
		m.Questions = append(m.Questions, Question{clip(q.Name, 255), dns.Type(q.Qtype).String(), dns.Class(q.Qclass).String()})
	}
	for _, f := range []struct {
		b bool
		s string
	}{{msg.Response, "qr"}, {msg.Authoritative, "aa"}, {msg.Truncated, "tc"}, {msg.RecursionDesired, "rd"}, {msg.RecursionAvailable, "ra"}, {msg.AuthenticatedData, "ad"}, {msg.CheckingDisabled, "cd"}} {
		if f.b {
			m.Flags = append(m.Flags, f.s)
		}
	}
	budget, count := 16*1024, 0
	copyRR := func(rrs []dns.RR) []Record {
		var records []Record
		for _, rr := range rrs {
			if count >= 128 || budget <= 0 {
				m.TruncatedCapture = true
				break
			}
			h := rr.Header()
			data := rr.String()
			if len(data) > 2048 {
				data = clip(data, 2048)
				m.TruncatedCapture = true
			}
			budget -= len(data) + len(h.Name) + 32
			count++
			records = append(records, Record{clip(h.Name, 255), dns.Type(h.Rrtype).String(), h.Ttl, data})
		}
		return records
	}
	m.Answer = copyRR(msg.Answer)
	m.Authority = copyRR(msg.Ns)
	m.Additional = copyRR(msg.Extra)
	if wire && m.Size <= 65535 {
		m.Wire, _ = msg.Pack()
	}
	return m
}

func responseAddresses(msg *dns.Msg) []string {
	var addresses []string
	// Match the RR capture limit so result summaries have bounded work and size.
	for _, rr := range msg.Answer[:min(len(msg.Answer), 128)] {
		var address net.IP
		switch rr := rr.(type) {
		case *dns.A:
			address = rr.A
		case *dns.AAAA:
			address = rr.AAAA
		}
		if address != nil {
			value := address.String()
			if !slices.Contains(addresses, value) {
				addresses = append(addresses, value)
			}
		}
	}
	return addresses
}

func summary(q Query) Query {
	q.Request = nil
	if q.Response != nil {
		r := *q.Response
		r.Answer = nil
		r.Authority = nil
		r.Additional = nil
		r.Wire = nil
		q.Response = &r
	}
	q.Attempts = append([]Attempt(nil), q.Attempts...)
	for i := range q.Attempts {
		q.Attempts[i].Response = nil
		q.Attempts[i].Diagnostics = nil
	}
	return q
}

func cloneMessage(m *Message) *Message {
	if m == nil {
		return nil
	}
	c := *m
	c.Flags = append([]string(nil), m.Flags...)
	c.Questions = append([]Question(nil), m.Questions...)
	c.Answer = append([]Record(nil), m.Answer...)
	c.Authority = append([]Record(nil), m.Authority...)
	c.Additional = append([]Record(nil), m.Additional...)
	c.Wire = append([]byte(nil), m.Wire...)
	return &c
}

func messageBytes(m *Message) int {
	if m == nil {
		return 0
	}
	size := 256 + len(m.Wire)
	for _, q := range m.Questions {
		size += len(q.Name) + 64
	}
	for _, section := range [][]Record{m.Answer, m.Authority, m.Additional} {
		for _, r := range section {
			size += len(r.Name) + len(r.Data) + 96
		}
	}
	return size
}

func matches(q Query, f Filter) bool {
	if f.Status != "" && q.Status != f.Status {
		return false
	}
	if f.Resolver != "" && q.Resolver != f.Resolver {
		return false
	}
	if f.Search == "" {
		return true
	}
	term := strings.ToLower(f.Search)
	for _, question := range q.Questions {
		if strings.Contains(strings.ToLower(question.Name), term) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(q.Source.Process+" "+q.Source.ProcessPath+" "+q.Resolver+" "+strings.Join(q.Candidates, " ")), term)
}

func (c *Connection) Release() {
	if c == nil || c.owner == nil {
		return
	}
	m := c.owner
	m.connMu.Lock()
	defer m.connMu.Unlock()
	for key, v := range m.connections {
		if v.ID == c.ID {
			delete(m.connections, key)
		}
	}
}
