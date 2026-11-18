package daemon

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	mitmapi "github.com/sagernet/sing-box/common/mitm/api"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const mitmSchemaVersion = 1

type mitmServer struct {
	mitmapi.UnimplementedMITMServer
	started *StartedService
}

func RegisterMITM(server *grpc.Server, started *StartedService) {
	mitmapi.RegisterMITMServer(server, &mitmServer{started: started})
}

func (s *mitmServer) engine() (adapter.MITMEngine, error) {
	s.started.serviceAccess.RLock()
	defer s.started.serviceAccess.RUnlock()
	if s.started.instance == nil {
		return nil, status.Error(codes.FailedPrecondition, "core is stopped")
	}
	engine := service.FromContext[adapter.MITMEngine](s.started.instance.ctx)
	if engine == nil {
		return nil, status.Error(codes.FailedPrecondition, "core is stopped")
	}
	return engine, nil
}

func (s *mitmServer) GetCapabilities(context.Context, *emptypb.Empty) (*mitmapi.Capabilities, error) {
	return &mitmapi.Capabilities{SchemaVersion: mitmSchemaVersion, Features: []string{"authority", "status", "skip"}}, nil
}

func (s *mitmServer) SetAuthority(ctx context.Context, request *mitmapi.SetAuthorityRequest) (*mitmapi.Status, error) {
	defer clear(request.KeyPkcs8)
	if !trustedAuthorityPeer(ctx) {
		return nil, status.Error(codes.PermissionDenied, "certificate authority accepted only from a loopback or unix socket peer, or over TLS")
	}
	engine, err := s.engine()
	if err != nil {
		return nil, err
	}
	var notAfter time.Time
	if request.NotAfter != 0 {
		notAfter = time.Unix(request.NotAfter, 0)
	}
	err = engine.SetAuthority(request.CertChainPem, request.KeyPkcs8, request.RootFingerprint, notAfter)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return mitmStatus(engine.Status()), nil
}

func (s *mitmServer) GetStatus(context.Context, *emptypb.Empty) (*mitmapi.Status, error) {
	engine, err := s.engine()
	if err != nil {
		return nil, err
	}
	return mitmStatus(engine.Status()), nil
}

func (s *mitmServer) ClearSkip(_ context.Context, request *mitmapi.ClearSkipRequest) (*mitmapi.Status, error) {
	engine, err := s.engine()
	if err != nil {
		return nil, err
	}
	engine.ClearSkip(request.Host)
	return mitmStatus(engine.Status()), nil
}

func mitmStatus(engineStatus adapter.MITMEngineStatus) *mitmapi.Status {
	result := &mitmapi.Status{
		Enabled:              engineStatus.Enabled,
		AuthorityFingerprint: engineStatus.AuthorityFingerprint,
		AuthorityPending:     engineStatus.AuthorityPending,
		LeafCacheSize:        uint32(engineStatus.LeafCacheSize),
		RootFingerprint:      engineStatus.RootFingerprint,
		CertificateSource:    engineStatus.CertificateSource,
	}
	if !engineStatus.AuthorityNotAfter.IsZero() {
		result.AuthorityNotAfter = engineStatus.AuthorityNotAfter.Unix()
	}
	for _, entry := range engineStatus.Skip {
		result.Skip = append(result.Skip, &mitmapi.SkipEntry{
			Host:   entry.Host,
			Source: entry.Source,
			Until:  entry.Until.Unix(),
			Reason: entry.Reason,
		})
	}
	for _, failure := range engineStatus.Failures {
		result.Failures = append(result.Failures, &mitmapi.Failure{
			Host:   failure.Host,
			Reason: failure.LastError,
			Time:   failure.At.Unix(),
			Count:  uint32(failure.Count),
		})
	}
	return result
}

// trustedAuthorityPeer reports whether a request may load a certificate
// authority: the peer is loopback or a unix socket, or the request came
// over TLS. Requests served through net/http (the api service) carry the
// remote address as a string.
func trustedAuthorityPeer(ctx context.Context) bool {
	p, loaded := peer.FromContext(ctx)
	if !loaded {
		return false
	}
	switch p.AuthInfo.(type) {
	case credentials.TLSInfo, *credentials.TLSInfo:
		return true
	}
	switch addr := p.Addr.(type) {
	case nil:
		return false
	case *net.UnixAddr:
		return true
	case *net.TCPAddr:
		return addr != nil && addr.IP.IsLoopback()
	}
	if p.Addr.Network() == "unix" {
		return true
	}
	addrPort, err := netip.ParseAddrPort(p.Addr.String())
	if err != nil {
		return false
	}
	return addrPort.Addr().Unmap().IsLoopback()
}
