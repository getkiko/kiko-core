package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// h2Client sends requests over one MITM session whose client connection has negotiated h2.
func h2Client(t *testing.T, conn *tls.Conn) *http.Client {
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)
	used := false
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, io.ErrClosedPipe
			}
			used = true
			return conn, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func getBody(t *testing.T, client *http.Client, path string) (int, string) {
	response, err := client.Get("https://example.com" + path)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.ProtoMajor, string(body)
}

// Needs the h2 relay (package E1). When the origin closes the connection the session moves to a new one,
// and the redial offers only h2.
func TestH2RedialOffersOnlyH2(t *testing.T) {
	if !h2Supported {
		t.Skip("h2 relay needs Go 1.26")
	}
	origin := newALPNOrigin(t, []string{"h2", "http/1.1"}, nil)
	ctx := contextWithRoots(origin.server)
	ca := writeTestCA(t)
	engine := newTestEngine(t, ctx, h2Options(ca, nil))
	redial := &countingRedial{address: origin.address()}
	s, clientConn := startRedialSessionALPN(t, engine, ca, origin.address(), redial.redial, []string{"h2", "http/1.1"})
	client := h2Client(t, clientConn)

	major, body := getBody(t, client, "/1")
	require.Equal(t, 2, major)
	require.Equal(t, "HTTP/2.0 /1", body)
	// The origin closes the first connection; the next request goes through a redial.
	origin.closeConnections()
	major, body = getBody(t, client, "/2")
	require.Equal(t, 2, major)
	require.Equal(t, "HTTP/2.0 /2", body)
	require.Equal(t, int32(1), redial.calls.Load())
	offers := origin.offers()
	require.Equal(t, [][]string{{"h2", "http/1.1"}, {"h2"}}, offers)
	require.GreaterOrEqual(t, s.state.Requests(), int64(2))
}
