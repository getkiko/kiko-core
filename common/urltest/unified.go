package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// UnifiedURLTest measures a "unified delay": the first request over a fresh
// connection only warms it up (dial, TLS handshake and any proxy handshake),
// and the second request over the same connection is the one timed, so the
// result is close to one round trip through the proxy. When the second
// request fails for another reason than the context ending, the result
// of the first one is returned.
func UnifiedURLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
			MaxIdleConns:    1,
			IdleConnTimeout: C.TCPTimeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()

	first, err := unifiedRequest(ctx, &client, link)
	if err != nil {
		return 0, err
	}
	t = elapsedMillis(start, first)
	secondStart := time.Now()
	second, err := unifiedRequest(ctx, &client, link)
	if err != nil {
		if ctx.Err() != nil {
			// Out of time: the caller sees a timeout, not a success.
			return 0, err
		}
		// Keep the first result: the connection was good enough once.
		return t, nil
	}
	return elapsedMillis(secondStart, second), nil
}

func unifiedRequest(ctx context.Context, client *http.Client, link string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, link, nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	done := time.Now()
	resp.Body.Close()
	return done, nil
}

func elapsedMillis(start, end time.Time) uint16 {
	ms := end.Sub(start) / time.Millisecond
	if ms < 1 {
		ms = 1
	}
	if ms > 65535 {
		ms = 65535
	}
	return uint16(ms)
}
