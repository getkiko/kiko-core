//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// An outbound proxy sends a browser's requests, plain and CONNECT, through
// the outbound it names although the rules block everything, and names a
// missing outbound instead of listening.
func TestOutboundProxyForcesOutbound(t *testing.T) {
	oldContext, oldPaths := globalCtx, configPaths
	defer func() { globalCtx, configPaths = oldContext, oldPaths }()
	preRun(nil, nil)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	config := fmt.Sprintf(`{
		"log": {"level": "error"},
		"services": [{"type": "api", "tag": "api", "listen": "127.0.0.1", "listen_port": %d}],
		"outbounds": [{"type": "block", "tag": "block"}, {"type": "direct", "tag": "out"}],
		"route": {"final": "block"}
	}`, apiPort)
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, cancel, err := create(options)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	defer cancel()

	conn, err := daemon.NewRemoteClient(daemon.RemoteClientOptions{ServerURL: fmt.Sprintf("http://127.0.0.1:%d", apiPort)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := daemon.NewStartedServiceClient(conn)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()

	missing, err := client.StartOutboundProxy(ctx, &daemon.OutboundProxyRequest{Outbound: "nowhere"})
	if err != nil {
		t.Fatal(err)
	}
	if event, err := missing.Recv(); err != nil || event.Address != "" || event.Error != "outbound not found: nowhere" {
		t.Fatalf("missing outbound: %+v %v", event, err)
	}

	stream, err := client.StartOutboundProxy(ctx, &daemon.OutboundProxyRequest{Outbound: "out"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Recv()
	if err != nil || event.Address == "" {
		t.Fatalf("proxy: %+v %v", event, err)
	}
	proxy, _ := url.Parse("http://" + event.Address)

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain") }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure") }))
	defer secure.Close()
	transport := secure.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxy)
	browser := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for target, want := range map[string]string{plain.URL: "plain", secure.URL: "secure"} {
		response, err := browser.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != want {
			t.Fatalf("%s: %q", target, body)
		}
	}
}
