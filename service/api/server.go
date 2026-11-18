package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, NewService)
}

type Service struct {
	boxService.Adapter
	logger    log.ContextLogger
	options   option.APIServiceOptions
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	dashboard *dashboard
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.APIServiceOptions) (adapter.Service, error) {
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeAPI, tag),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tlsConfig
	}
	if options.Dashboard != nil && options.Dashboard.Enabled {
		s.dashboard = newDashboard(ctx, logger, *options.Dashboard)
	}
	return s, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	ctx := scope.Context()
	startedService := daemon.NewAttachedService(ctx)
	scope.Add(func() error {
		startedService.Close()
		return nil
	})
	grpcServer := daemon.NewServer(startedService, s.options.Secret)
	scope.Add(func() error {
		grpcServer.Stop()
		return nil
	})
	if s.dashboard != nil {
		err := s.dashboard.start(ctx)
		if err != nil {
			return E.Cause(err, "start dashboard")
		}
		scope.Add(s.dashboard.close)
	}
	httpServer := &http.Server{
		//nolint:staticcheck
		Handler: h2c.NewHandler(newHTTPHandler(s.logger, grpcServer, s.options, s.dashboard), new(http2.Server)),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	if s.tlsConfig != nil {
		err := s.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(s.tlsConfig.Close)
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
		}
		if !common.Contains(s.tlsConfig.NextProtos(), "http/1.1") {
			s.tlsConfig.SetNextProtos(append(s.tlsConfig.NextProtos(), "http/1.1"))
		}
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(func() error {
		err := s.listener.Close()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
	// h2c hijacks connections; http.Server.Close does not own those sockets.
	// Track accepts before TLS wrapping to preserve the TLS connection type.
	tracked := &connectionListener{Listener: tcpListener, connections: make(map[*apiConnection]struct{})}
	tcpListener = tracked
	if s.tlsConfig != nil {
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	scope.Add(func() error {
		err := httpServer.Close()
		tracked.closeConnections()
		return err
	})
	go func() {
		serveErr := httpServer.Serve(tcpListener)
		if serveErr != nil && ctx.Err() == nil {
			s.logger.Error("serve error: ", serveErr)
		}
	}()
	return nil
}

// connectionListener owns accepted transports including HTTP/2 h2c hijacks.
type connectionListener struct {
	net.Listener
	mu          sync.Mutex
	closed      bool
	connections map[*apiConnection]struct{}
}

func (l *connectionListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &apiConnection{Conn: conn, owner: l}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	l.connections[tracked] = struct{}{}
	l.mu.Unlock()
	return tracked, nil
}
func (l *connectionListener) closeConnections() {
	l.mu.Lock()
	l.closed = true
	connections := make([]*apiConnection, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
}

type apiConnection struct {
	net.Conn
	owner *connectionListener
}

func (c *apiConnection) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.connections, c)
	c.owner.mu.Unlock()
	return err
}
