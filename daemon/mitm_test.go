package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing-box/common/mitm/authority"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/mitm"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

type testPush struct {
	chainPEM        []byte
	keyPKCS8        []byte
	rootFingerprint string
	notAfter        int64
	fingerprint     string
}

func newTestPush(t *testing.T) testPush {
	t.Helper()
	rootPEM, rootKeyPEM, err := authority.Generate("Kiko Daemon Root", 365*24*time.Hour)
	require.NoError(t, err)
	chainPEM, keyPKCS8, err := authority.IssueIntermediate(rootPEM, rootKeyPEM, "Kiko Daemon Intermediate", authority.IntermediateValidity)
	require.NoError(t, err)
	rootBlock, _ := pem.Decode(rootPEM)
	interBlock, _ := pem.Decode(chainPEM)
	intermediate, err := x509.ParseCertificate(interBlock.Bytes)
	require.NoError(t, err)
	rootSum := sha256.Sum256(rootBlock.Bytes)
	interSum := sha256.Sum256(interBlock.Bytes)
	return testPush{chainPEM, keyPKCS8, hex.EncodeToString(rootSum[:]), intermediate.NotAfter.Unix(), hex.EncodeToString(interSum[:])}
}

// request returns a fresh request: the server clears the key bytes it receives.
func (p testPush) request() *mitmapi.SetAuthorityRequest {
	return &mitmapi.SetAuthorityRequest{
		CertChainPem:    p.chainPEM,
		KeyPkcs8:        bytes.Clone(p.keyPKCS8),
		RootFingerprint: p.rootFingerprint,
		NotAfter:        p.notAfter,
	}
}

func newTestMITMServer(t *testing.T, output *bytes.Buffer) (*mitmServer, adapter.MITMEngine) {
	t.Helper()
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	require.NoError(t, factory.Start())
	t.Cleanup(func() { factory.Close() })
	engine, err := mitm.NewEngine(context.Background(), factory.NewLogger("mitm"), &option.MITMOptions{
		Enabled:   true,
		Hostnames: &option.MITMHostnamesOptions{Include: []string{"a.test"}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { engine.Close() })
	ctx := service.ContextWith[adapter.MITMEngine](context.Background(), engine)
	return &mitmServer{started: &StartedService{instance: &Instance{ctx: ctx}}}, engine
}

func peerContext(addr net.Addr, authInfo credentials.AuthInfo) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{Addr: addr, AuthInfo: authInfo})
}

func requireNoKeyMaterial(t *testing.T, content []byte, push testPush) {
	t.Helper()
	require.False(t, bytes.Contains(content, push.keyPKCS8), "contains the key")
	require.False(t, bytes.Contains(content, push.chainPEM), "contains the chain")
	require.NotContains(t, string(content), "PRIVATE KEY")
	require.NotContains(t, string(content), "BEGIN CERTIFICATE")
}

func TestMITMSetAuthorityPeers(t *testing.T) {
	accepted := []struct {
		name string
		ctx  context.Context
	}{
		{"loopback tcp", peerContext(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}, nil)},
		{"loopback tcp v6", peerContext(&net.TCPAddr{IP: net.IPv6loopback, Port: 4000}, nil)},
		{"loopback string", peerContext(stringAddr("127.0.0.1:4000"), nil)},
		{"loopback string v6", peerContext(stringAddr("[::1]:4000"), nil)},
		{"loopback string mapped", peerContext(stringAddr("[::ffff:127.0.0.1]:4000"), nil)},
		{"unix", peerContext(&net.UnixAddr{Name: "@", Net: "unix"}, nil)},
		{"tls", peerContext(&net.TCPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 4000}, credentials.TLSInfo{State: tls.ConnectionState{}})},
		{"tls string", peerContext(stringAddr("192.168.1.2:4000"), credentials.TLSInfo{})},
	}
	for _, testCase := range accepted {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			server, _ := newTestMITMServer(t, &output)
			push := newTestPush(t)
			request := push.request()
			response, err := server.SetAuthority(testCase.ctx, request)
			require.NoError(t, err)
			require.False(t, response.AuthorityPending)
			require.Equal(t, push.fingerprint, response.AuthorityFingerprint)
			require.Equal(t, push.rootFingerprint, response.RootFingerprint)
			require.Equal(t, push.notAfter, response.AuthorityNotAfter)
			require.Equal(t, "managed", response.CertificateSource)
			require.True(t, response.Enabled)
			// The received key is cleared.
			require.Equal(t, make([]byte, len(push.keyPKCS8)), request.KeyPkcs8)
			content, err := proto.Marshal(response)
			require.NoError(t, err)
			requireNoKeyMaterial(t, content, push)
			requireNoKeyMaterial(t, output.Bytes(), push)
			require.Contains(t, output.String(), push.fingerprint)
		})
	}
	denied := []struct {
		name string
		ctx  context.Context
	}{
		{"no peer", context.Background()},
		{"lan tcp", peerContext(&net.TCPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 4000}, nil)},
		{"lan string", peerContext(stringAddr("192.168.1.2:4000"), nil)},
		{"unspecified", peerContext(stringAddr("0.0.0.0:4000"), nil)},
		{"invalid string", peerContext(stringAddr("localhost:4000"), nil)},
		{"nil tcp", peerContext((*net.TCPAddr)(nil), nil)},
	}
	for _, testCase := range denied {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			server, engine := newTestMITMServer(t, &output)
			push := newTestPush(t)
			_, err := server.SetAuthority(testCase.ctx, push.request())
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.True(t, engine.Status().AuthorityPending)
		})
	}
}

func TestMITMSetAuthorityInvalid(t *testing.T) {
	var output bytes.Buffer
	server, engine := newTestMITMServer(t, &output)
	ctx := peerContext(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}, nil)
	push := newTestPush(t)
	other := newTestPush(t)
	invalid := []*mitmapi.SetAuthorityRequest{
		{CertChainPem: push.chainPEM, KeyPkcs8: bytes.Clone(other.keyPKCS8), RootFingerprint: push.rootFingerprint, NotAfter: push.notAfter},
		{CertChainPem: push.chainPEM, KeyPkcs8: bytes.Clone(push.keyPKCS8), RootFingerprint: other.rootFingerprint, NotAfter: push.notAfter},
		{CertChainPem: push.chainPEM, KeyPkcs8: bytes.Clone(push.keyPKCS8), RootFingerprint: push.rootFingerprint, NotAfter: push.notAfter + 1},
		{CertChainPem: push.chainPEM, KeyPkcs8: bytes.Clone(push.keyPKCS8[:len(push.keyPKCS8)-2]), RootFingerprint: push.rootFingerprint, NotAfter: push.notAfter},
		{CertChainPem: push.chainPEM, RootFingerprint: push.rootFingerprint, NotAfter: push.notAfter},
		{KeyPkcs8: bytes.Clone(push.keyPKCS8)},
		{CertChainPem: []byte("garbage"), KeyPkcs8: bytes.Clone(push.keyPKCS8)},
	}
	for _, request := range invalid {
		_, err := server.SetAuthority(ctx, request)
		require.Equal(t, codes.InvalidArgument, status.Code(err), err)
		requireNoKeyMaterial(t, []byte(err.Error()), push)
		requireNoKeyMaterial(t, []byte(err.Error()), other)
		require.True(t, engine.Status().AuthorityPending)
	}
	requireNoKeyMaterial(t, output.Bytes(), push)

	_, err := server.SetAuthority(ctx, push.request())
	require.NoError(t, err)
	response, err := server.SetAuthority(ctx, &mitmapi.SetAuthorityRequest{})
	require.NoError(t, err)
	require.True(t, response.AuthorityPending)
	require.Empty(t, response.AuthorityFingerprint)
	require.Zero(t, response.AuthorityNotAfter)
	requireNoKeyMaterial(t, output.Bytes(), push)
}

func TestMITMStatusAndCapabilities(t *testing.T) {
	var output bytes.Buffer
	server, _ := newTestMITMServer(t, &output)
	capabilities, err := server.GetCapabilities(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.Equal(t, uint32(1), capabilities.SchemaVersion)
	require.Equal(t, []string{"authority", "status", "skip"}, capabilities.Features)

	response, err := server.GetStatus(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.True(t, response.Enabled)
	require.True(t, response.AuthorityPending)
	require.Equal(t, "managed", response.CertificateSource)
	require.Empty(t, response.Skip)
	require.Empty(t, response.Failures)

	_, err = server.ClearSkip(context.Background(), &mitmapi.ClearSkipRequest{Host: "a.test"})
	require.NoError(t, err)

	stopped := &mitmServer{started: &StartedService{}}
	_, err = stopped.GetStatus(context.Background(), &emptypb.Empty{})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = stopped.SetAuthority(peerContext(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil), newTestPush(t).request())
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = stopped.GetCapabilities(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	_, err = stopped.ClearSkip(context.Background(), &mitmapi.ClearSkipRequest{})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// skipEngine reports fixed skip entries and failures, and records ClearSkip.
type skipEngine struct {
	adapter.MITMEngine
	cleared []string
}

func (e *skipEngine) Status() adapter.MITMEngineStatus {
	return adapter.MITMEngineStatus{
		Enabled: true,
		Skip: []adapter.MITMSkipEntry{
			{Host: "a.test", Source: "auto", Until: time.Unix(2000, 0), Reason: "pinned"},
		},
		Failures: []adapter.MITMFailure{
			{Host: "b.test", Count: 3, LastError: "bad certificate", At: time.Unix(1000, 0)},
		},
	}
}

func (e *skipEngine) ClearSkip(host string) bool {
	e.cleared = append(e.cleared, host)
	return true
}

func TestMITMSkipAndFailuresStatus(t *testing.T) {
	engine := &skipEngine{}
	ctx := service.ContextWith[adapter.MITMEngine](context.Background(), engine)
	server := &mitmServer{started: &StartedService{instance: &Instance{ctx: ctx}}}
	response, err := server.GetStatus(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, response.Skip, 1)
	require.Equal(t, "a.test", response.Skip[0].Host)
	require.Equal(t, "auto", response.Skip[0].Source)
	require.Equal(t, int64(2000), response.Skip[0].Until)
	require.Equal(t, "pinned", response.Skip[0].Reason)
	require.Len(t, response.Failures, 1)
	require.Equal(t, "b.test", response.Failures[0].Host)
	require.Equal(t, uint32(3), response.Failures[0].Count)
	require.Equal(t, "bad certificate", response.Failures[0].Reason)
	require.Equal(t, int64(1000), response.Failures[0].Time)

	response, err = server.ClearSkip(context.Background(), &mitmapi.ClearSkipRequest{Host: "a.test"})
	require.NoError(t, err)
	require.NotNil(t, response)
	_, err = server.ClearSkip(context.Background(), &mitmapi.ClearSkipRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"a.test", ""}, engine.cleared)
}

// TestMITMOverGRPC drives the registered service through NewServer with
// authentication, over a unix socket and loopback TCP.
func TestMITMOverGRPC(t *testing.T) {
	var output bytes.Buffer
	server, engine := newTestMITMServer(t, &output)
	grpcServer := NewServer(server.started, "secret")
	defer grpcServer.Stop()
	directory, err := os.MkdirTemp("", "mitm")
	require.NoError(t, err)
	defer os.RemoveAll(directory)
	unixListener, err := net.Listen("unix", filepath.Join(directory, "s"))
	require.NoError(t, err)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go grpcServer.Serve(unixListener)
	go grpcServer.Serve(tcpListener)
	var pushes []testPush
	for _, target := range []string{"unix://" + unixListener.Addr().String(), tcpListener.Addr().String()} {
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		client := mitmapi.NewMITMClient(conn)
		push := newTestPush(t)
		pushes = append(pushes, push)
		_, err = client.SetAuthority(context.Background(), push.request())
		require.Equal(t, codes.Unauthenticated, status.Code(err))
		ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer secret")
		response, err := client.SetAuthority(ctx, push.request())
		require.NoError(t, err, target)
		require.Equal(t, push.fingerprint, response.AuthorityFingerprint)
		response, err = client.GetStatus(ctx, &emptypb.Empty{})
		require.NoError(t, err)
		require.Equal(t, push.fingerprint, response.AuthorityFingerprint)
		require.Equal(t, push.fingerprint, engine.Status().AuthorityFingerprint)
		require.NoError(t, conn.Close())
	}
	for _, push := range pushes {
		requireNoKeyMaterial(t, output.Bytes(), push)
	}
}
