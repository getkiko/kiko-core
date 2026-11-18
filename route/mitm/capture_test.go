package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/capture"
	"github.com/sagernet/sing-box/common/mitm/flow"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func fetch(t *testing.T, s *session, ca testCA, protos []string, paths ...string) {
	t.Helper()
	clientConn := tls.Client(s.client, &tls.Config{ServerName: "example.com", RootCAs: caPool(t, ca), NextProtos: protos})
	require.NoError(t, clientConn.HandshakeContext(context.Background()))
	require.Eventually(t, func() bool { return s.state.Status() == adapter.MITMStatusDecrypted }, 5*time.Second, 10*time.Millisecond)
	if clientConn.ConnectionState().NegotiatedProtocol == "h2" {
		client := h2Client(t, clientConn)
		for _, path := range paths {
			getBody(t, client, path)
		}
	} else {
		reader := bufio.NewReader(clientConn)
		for _, path := range paths {
			_, err := io.WriteString(clientConn, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\nX-Probe: 1\r\n\r\n")
			require.NoError(t, err)
			response, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			response.Body.Close()
		}
	}
	clientConn.Close()
	s.wait(t)
}

func finishedRecords(t *testing.T, m *capture.Manager, n int) []capture.Record {
	t.Helper()
	var records []capture.Record
	require.Eventually(t, func() bool {
		records = m.List(capture.Filter{}).Records
		if len(records) != n {
			return false
		}
		for _, r := range records {
			if r.State == capture.StateInProgress {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	return records
}

func TestCaptureEndToEnd(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			if protocol == "h2" && !h2Supported {
				t.Skip("h2 relay needs Go 1.26")
			}
			protocols := []string{"h2", "http/1.1"}
			upstream := newALPNOrigin(t, protocols, nil)
			if protocol == "http/1.1" {
				protocols = []string{"http/1.1"}
				upstream = newALPNOrigin(t, protocols, nil)
			}
			ca := writeTestCA(t)
			options := fileOptions(ca, true, []string{"example.com"}, nil)
			options.Capture = &option.MITMCaptureOptions{Body: true}
			options.Upstream = &option.MITMUpstreamOptions{SkipVerify: []string{"example.com"}}
			engine := newTestEngine(t, contextWithRoots(upstream.server), options)
			s := startSessionFrom(t, context.Background(), engine, upstream.address(), "203.0.113.9:50000", func(metadata *adapter.InboundContext) {
				metadata.Inbound = "mixed-in"
				metadata.InboundType = "mixed"
				metadata.ProcessInfo = &adapter.ConnectionOwner{ProcessID: 42, ProcessPath: "/usr/bin/curl"}
			})
			s.state.SetConnection("conn-id", "#0 route")
			fetch(t, s, ca, protocols, "/first", "/second")
			records := finishedRecords(t, engine.Capture(), 2)
			for i, path := range []string{"/first", "/second"} {
				r := records[i]
				require.Equal(t, path, r.Path)
				require.Equal(t, "example.com", r.Authority)
				require.Equal(t, http.StatusOK, r.Status)
				require.Equal(t, capture.StateComplete, r.State)
				require.True(t, r.Unverified)
				require.Equal(t, "conn-id", r.ConnectionID)
				require.Equal(t, uint32(i+1), r.RequestIndex)
				require.Equal(t, r.Proto == "h2", protocol == "h2")
				require.Equal(t, map[bool]string{true: "HTTP/2.0 ", false: "HTTP/1.1 "}[protocol == "h2"]+path, bodyText(t, engine.Capture(), r.ID))
				require.False(t, r.Timing.RequestHeaders.IsZero())
				require.False(t, r.Timing.ResponseHeaders.IsZero())
				require.False(t, r.Timing.End.IsZero())
				connection := r.Connection
				require.NotNil(t, connection)
				require.Equal(t, "mixed-in", connection.Inbound)
				require.Equal(t, "curl", connection.ProcessName)
				require.Equal(t, "/usr/bin/curl", connection.ProcessPath)
				require.Equal(t, uint32(42), connection.ProcessID)
				require.Equal(t, "#0 route", connection.Rule)
				require.Equal(t, "example.com", connection.Host)
			}
			if protocol == "h2" {
				require.Equal(t, "h2", records[0].Proto)
			} else {
				require.Equal(t, "http/1.1", records[0].Proto)
			}
		})
	}
}

func bodyText(t *testing.T, m *capture.Manager, id string) string {
	t.Helper()
	result, err := m.GetBody(capture.BodyRequest{ID: id, Side: flow.Response})
	require.NoError(t, err)
	return string(result.Data)
}

func TestCaptureDisabledByOptions(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	off := false
	options := fileOptions(ca, true, []string{"example.com"}, nil)
	options.Capture = &option.MITMCaptureOptions{Enabled: &off}
	engine := newTestEngine(t, contextWithRoots(upstream), options)
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	fetch(t, s, ca, []string{"http/1.1"}, "/quiet")
	require.Empty(t, engine.Capture().List(capture.Filter{}).Records)
	require.Equal(t, int64(1), s.state.Requests())
}

func TestCaptureReloadKeepsStore(t *testing.T) {
	upstream := newUpstream(t)
	ca := writeTestCA(t)
	engine := newTestEngine(t, contextWithRoots(upstream), fileOptions(ca, true, []string{"example.com"}, nil))
	store := engine.Capture()
	instance := store.Instance()
	for i := 0; i < 3; i++ {
		s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
		fetch(t, s, ca, []string{"http/1.1"}, "/n")
	}
	finishedRecords(t, store, 3)

	// A smaller capacity evicts finished records and keeps the instance.
	smaller := fileOptions(ca, true, []string{"example.com"}, nil)
	smaller.Capture = &option.MITMCaptureOptions{MaxRecords: 2}
	commit, err := engine.Reload(smaller)
	require.NoError(t, err)
	commit()
	require.Same(t, store, engine.Capture())
	require.Equal(t, instance, store.Instance())
	require.Len(t, store.List(capture.Filter{}).Records, 2)

	// Capture off: new connections add nothing.
	off := false
	disabled := fileOptions(ca, true, []string{"example.com"}, nil)
	disabled.Capture = &option.MITMCaptureOptions{Enabled: &off}
	commit, err = engine.Reload(disabled)
	require.NoError(t, err)
	commit()
	s := startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	fetch(t, s, ca, []string{"http/1.1"}, "/n")
	require.Len(t, store.List(capture.Filter{}).Records, 2)

	// And on again.
	on := true
	enabled := fileOptions(ca, true, []string{"example.com"}, nil)
	enabled.Capture = &option.MITMCaptureOptions{Enabled: &on}
	commit, err = engine.Reload(enabled)
	require.NoError(t, err)
	commit()
	s = startSession(t, context.Background(), engine, upstream.Listener.Addr().String())
	fetch(t, s, ca, []string{"http/1.1"}, "/n")
	require.Len(t, store.List(capture.Filter{}).Records, 3)
}

func TestCaptureReloadRejectsInvalidOptions(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"example.com"}, nil))
	invalid := fileOptions(ca, true, []string{"example.com"}, nil)
	invalid.Capture = &option.MITMCaptureOptions{MaxRecords: -1}
	_, err := engine.Reload(invalid)
	require.Error(t, err)
}

func TestCaptureProviderNilWhenDisabled(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, false, nil, nil))
	var provider adapter.MITMCaptureProvider = engine
	require.Nil(t, provider.Capture())
	engine = newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"example.com"}, nil))
	provider = engine
	require.NotNil(t, provider.Capture())
}
