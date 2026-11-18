package h1

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestStaleUpstreamAfterLocalReply: an upstream that was never asked (the exchange before was
// answered locally) and closes while idle is replaced (Redial) or ends the client connection,
// never answered with a 502.
func TestStaleUpstreamAfterLocalReply(t *testing.T) {
	for _, tc := range []struct {
		name   string
		redial bool
	}{
		{"redial", true},
		{"no redial", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "real "+r.URL.Path)
			}))
			upstreamServer.Config.ReadHeaderTimeout = 300 * time.Millisecond
			upstreamServer.Start()
			t.Cleanup(upstreamServer.Close)
			address := upstreamServer.Listener.Addr().String()
			dial := func() net.Conn {
				conn, err := net.Dial("tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				return conn
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			serverSide, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			options := rewriteOptions(nil, compileSet(t, urlRules(
				option.MITMURLRewriteRule{Pattern: `^https://a/blocked`, Action: "reject-dict"})))
			if tc.redial {
				options.Redial = func(context.Context) (net.Conn, error) { return dial(), nil }
			}
			done := make(chan error, 1)
			go func() { done <- Serve(context.Background(), serverSide, dial(), options) }()
			reader := bufio.NewReader(client)
			get := func(path string) (*http.Response, string, error) {
				_ = client.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := io.WriteString(client, "GET "+path+" HTTP/1.1\r\nHost: a\r\n\r\n"); err != nil {
					return nil, "", err
				}
				response, err := http.ReadResponse(reader, nil)
				if err != nil {
					return nil, "", err
				}
				body, err := io.ReadAll(response.Body)
				return response, string(body), err
			}
			if _, body, err := get("/blocked"); err != nil || body != "{}" {
				t.Fatalf("blocked %q %v", body, err)
			}
			time.Sleep(800 * time.Millisecond)
			response, body, err := get("/real")
			if tc.redial {
				if err != nil || response.StatusCode != 200 || body != "real /real" {
					t.Fatalf("real %v %q %v", response, body, err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected the client connection to close, got %d %q", response.StatusCode, body)
				}
				if response != nil && response.StatusCode == 502 || strings.Contains(body, "Bad Gateway") {
					t.Fatalf("502 for a stale idle upstream")
				}
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("serve did not return")
			}
		})
	}
}
