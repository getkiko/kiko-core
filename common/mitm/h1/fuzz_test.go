package h1

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

// FuzzRelay sends a random client byte stream through Serve to an upstream answering every
// request with an empty 200 (405 for CONNECT, so no tunnel opens). Invariants: no panic, no
// hang, every forwarded request is whole and strictly framed (strict reader and net/http agree),
// every response the client gets is strictly framed, and each forwarded request is the one
// net/http reads at the same position of the client stream wherever net/http reads it.
func FuzzRelay(f *testing.F) {
	for _, tc := range smuggleCases {
		if len(tc.client) <= 4096 {
			f.Add([]byte(tc.client + tc.later))
		}
	}
	f.Add([]byte("GET /1 HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi" + endReq))
	f.Add([]byte("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" + endReq))
	f.Add([]byte("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n" + endReq))
	f.Add([]byte("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n" + endReq))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<10 {
			return
		}
		r := runRelay(t, relayConfig{client: string(data), pipe: true, closeClient: 3 * time.Millisecond, timeout: 3 * time.Second})
		checkRelayInvariants(t, r, false)
		checkForwardedAsSent(t, data, r)
	})
}

// checkForwardedAsSent compares every complete forwarded request with the request net/http
// reads at the same position of the client stream: same method, target, version and body.
func checkForwardedAsSent(t *testing.T, data []byte, r relayResult) {
	t.Helper()
	reader := bufio.NewReader(bytes.NewReader(data))
	for i, forwarded := range r.upstream {
		if !forwarded.complete || forwarded.invalid != "" {
			return
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return
		}
		sent := strictMsg{request: true, method: req.Method, target: req.RequestURI, proto: req.Proto, body: body, complete: true}
		got := *forwarded
		got.trailers = nil
		if got.String() != sent.String() {
			t.Fatalf("request %d forwarded as %q, net/http reads the client's as %q\nclient: %q\nupstream: %q", i, got.String(), sent.String(), data, r.upstreamRaw)
		}
	}
}

// relayScenario is a fixed client side for FuzzRelayResponse.
type relayScenario struct {
	client  string
	methods []string
}

var relayScenarios = []relayScenario{
	{"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n", []string{"GET"}},
	{"HEAD /1 HTTP/1.1\r\nHost: a\r\n\r\n", []string{"HEAD"}},
	{"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n", []string{"GET", "GET"}},
	{"POST /1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello", []string{"POST"}},
	{"HEAD /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n", []string{"HEAD", "GET"}},
}

// responseRelaySeeds are upstream byte streams answering the first request; "SMUGGLED" marks
// bytes that must never reach the client as a response.
var responseRelaySeeds = []string{
	"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	"HTTP/1.1 200 OK\r\n\r\nclose-delimited",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5, 6\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5, 6\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 13\r\n\r\nhelloSMUGGLED",
	"HTTP/1.1 200 OK\r\nContent-Length: 0, 0\r\n\r\n",
	"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	"HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	"HTTP/1.1 100 Continue\r\nContent-Length: 8\r\n\r\nSMUGGLEDHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
	"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nSMUGGLED",
	"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
	"HTTP/1.1 204 No Content\r\nContent-Length: 8\r\n\r\nSMUGGLED",
	"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
	"HTTP/1.1 304 Not Modified\r\nContent-Length: -1\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED",
	"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nSMUGGLED",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTrailer: X-T\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n\r\n",
	"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\nhello",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n folded\r\n\r\n",
	"HTTP/1.1 200 OK\r\nX: a\rContent-Length: 8\r\n\r\nSMUGGLED",
}

// FuzzRelayResponse feeds a random upstream byte stream, written in answer to the first request
// and followed by a close, through Serve for a fixed client side. Invariants: no panic, no hang,
// the client receives strictly framed responses (bodiless ones with at most one valid
// Content-Length, never with Transfer-Encoding and Content-Length together), no more responses
// than requests, only the first carries upstream bytes (later ones are bodiless 502s: the
// upstream sent nothing in answer to the later requests), and a first response the strict reader
// also accepts from the upstream bytes keeps its status and body.
func FuzzRelayResponse(f *testing.F) {
	for _, seed := range responseRelaySeeds {
		for i := range relayScenarios {
			f.Add([]byte(seed), uint8(i))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, scenarioIndex uint8) {
		if len(data) > 16<<10 {
			return
		}
		scenario := relayScenarios[int(scenarioIndex)%len(relayScenarios)]
		r := runRelay(t, relayConfig{
			client:      scenario.client,
			replies:     []upstreamReply{{raw: string(data), closeAfter: 5 * time.Millisecond}},
			methods:     scenario.methods,
			pipe:        true,
			closeClient: 200 * time.Millisecond,
			timeout:     3 * time.Second,
		})
		checkRelayInvariants(t, r, false)
		if len(r.client) > len(scenario.methods) {
			t.Fatalf("%d responses to %d requests\nupstream: %q\nclient: %q", len(r.client), len(scenario.methods), data, r.clientRaw)
		}
		for i, m := range r.client[min(1, len(r.client)):] {
			if m.status != 502 || len(m.body) > 0 {
				t.Fatalf("response %d is %s, but the upstream answered only the first request\nupstream: %q\nclient: %q", i+1, m, data, r.clientRaw)
			}
		}
		if len(r.client) == 0 || !r.client[0].complete || r.repliesWritten == 0 {
			return
		}
		// The first final response as the strict reader reads it from the upstream bytes.
		reader := strictReader{r: bufio.NewReader(bytes.NewReader(data))}
		for {
			m, err := reader.read(false, scenario.methods[0])
			if err != nil || m.invalid != "" || !m.complete {
				return
			}
			if m.status < 200 {
				continue
			}
			got := r.client[0]
			if got.status == m.status && !bytes.Equal(got.body, m.body) {
				t.Fatalf("body %q forwarded as %q\nupstream: %q\nclient: %q", m.body, got.body, data, r.clientRaw)
			}
			return
		}
	})
}
