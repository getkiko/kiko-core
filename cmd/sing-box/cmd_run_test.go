//go:build !windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
	"google.golang.org/protobuf/types/known/emptypb"
)

type slowStartupService struct {
	boxService.Adapter
	probe func() error
}

func (s *slowStartupService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	// The API service is listening while Box.Start still has work to do.
	if err := s.probe(); err != nil {
		return err
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		return err
	}
	select {
	case <-scope.Context().Done():
		return scope.Context().Err()
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func TestReloadSignalDuringStartupPreservesStartingInstance(t *testing.T) {
	// run owns this subscription and processes queued HUP once create returns.
	queued := make(chan os.Signal, 1)
	signal.Notify(queued, syscall.SIGHUP)
	defer signal.Stop(queued)
	oldContext, oldPaths := globalCtx, configPaths
	defer func() { globalCtx, configPaths = oldContext, oldPaths }()
	preRun(nil, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	conn, err := daemon.NewRemoteClient(daemon.RemoteClientOptions{ServerURL: fmt.Sprintf("http://127.0.0.1:%d", port)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := daemon.NewStartedServiceClient(conn)
	probe := func(wantReady bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		value, err := client.GetStartedAt(ctx, &emptypb.Empty{})
		if err != nil {
			return err
		}
		if value.Ready != wantReady || value.ConfigRevision != "test-revision" || value.InstanceId <= 0 || value.ReloadProtocol != 1 {
			return fmt.Errorf("readiness=%+v wantReady=%v", value, wantReady)
		}
		return nil
	}
	registry := service.FromContext[adapter.ServiceRegistry](globalCtx).(*boxService.Registry)
	boxService.Register[struct{}](registry, "test-slow-start", func(context.Context, log.ContextLogger, string, struct{}) (adapter.Service, error) {
		return &slowStartupService{Adapter: boxService.NewAdapter("test-slow-start", "slow"), probe: func() error { return probe(false) }}, nil
	})
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	instance, cancel, err := create(option.Options{
		Services: []option.Service{
			{Type: "api", Tag: "api", Options: &option.APIServiceOptions{ConfigRevision: "test-revision", ListenOptions: option.ListenOptions{ListenPort: uint16(port), Listen: &listen}}},
			{Type: "test-slow-start", Tag: "slow", Options: &struct{}{}},
		},
	})
	if err != nil {
		t.Fatalf("SIGHUP canceled first startup: %v", err)
	}
	defer instance.Close()
	defer cancel()
	if err := probe(true); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-queued:
		if got != syscall.SIGHUP {
			t.Fatalf("queued signal=%v", got)
		}
	default:
		t.Fatal("reload signal was lost during startup")
	}
}
