//go:build !windows

package main

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCoreRunFixture(t *testing.T) {
	config := os.Getenv("KIKO_CORE_RUN_FIXTURE")
	if config == "" {
		t.Skip("subprocess only")
	}
	preRun(nil, nil)
	configPaths = []string{config}
	registry := service.FromContext[adapter.ServiceRegistry](globalCtx).(*boxService.Registry)
	boxService.Register[struct{}](registry, "test-slow-close", func(context.Context, log.ContextLogger, string, struct{}) (adapter.Service, error) {
		return &slowCloseFixture{boxService.NewAdapter("test-slow-close", "slow")}, nil
	})
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

// Construction checks pass for a busy port. Only Start detects the conflict.
// Exercise the real CLI loop, OS signals, and cleanup in an isolated process.
func TestCoreReloadRestoresAfterStartupFailure(t *testing.T) {
	dir := t.TempDir()
	config, output := filepath.Join(dir, "config.json"), filepath.Join(dir, "core.log")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	spare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	oldPort := spare.Addr().(*net.TCPAddr).Port
	spare.Close()
	encode := func(port int) []byte {
		return []byte(fmt.Sprintf(`{"log":{"level":"trace","disabled":false},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"},"services":[{"type":"api","tag":"api","listen":"127.0.0.1"}]}`, port))
	}
	if err := os.WriteFile(config, encode(oldPort), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoreRunFixture$")
	cmd.Env = append(os.Environ(), "KIKO_CORE_RUN_FIXTURE="+config)
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}()
	waitFor := func(description string, match func(string) bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			data, _ := os.ReadFile(output)
			if match(string(data)) {
				return
			}
			select {
			case err := <-done:
				done <- err
				t.Fatalf("%s: core exited: %v\n%s", description, err, data)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		data, _ := os.ReadFile(output)
		t.Fatalf("%s: timed out\n%s", description, data)
	}
	waitFor("initial startup", func(log string) bool { return strings.Contains(log, "sing-box started") })
	if err := os.WriteFile(config, encode(busy.Addr().(*net.TCPAddr).Port), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor("startup failure restores last good instance", func(log string) bool { return strings.Count(log, "sing-box started") >= 2 })
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", oldPort), time.Second)
	if err != nil {
		t.Fatalf("restored listener: %v", err)
	}
	conn.Close()
	if err := os.WriteFile(config, encode(oldPort), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor("reload after recovery", func(log string) bool { return strings.Count(log, "sing-box started") >= 3 })
}

type slowCloseFixture struct{ boxService.Adapter }

func (s *slowCloseFixture) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStarted {
		scope.Add(func() error {
			fmt.Fprintln(os.Stderr, "fixture slow close")
			time.Sleep(400 * time.Millisecond)
			return nil
		})
	}
	return nil
}

func TestCoreTerminationWinsOverQueuedReload(t *testing.T) {
	dir := t.TempDir()
	path, output := filepath.Join(dir, "config.json"), filepath.Join(dir, "core.log")
	if err := os.WriteFile(path, []byte(`{"log":{"level":"info"},"services":[{"type":"test-slow-close","tag":"slow"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoreRunFixture$")
	cmd.Env = append(os.Environ(), "KIKO_CORE_RUN_FIXTURE="+path)
	cmd.Stdout, cmd.Stderr = file, file
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cmd.Process.Kill() }()
	waitLog := func(want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			data, _ := os.ReadFile(output)
			if strings.Contains(string(data), want) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		data, _ := os.ReadFile(output)
		t.Fatalf("waiting %q: %s", want, data)
	}
	waitLog("sing-box started")
	cmd.Process.Signal(syscall.SIGHUP)
	waitLog("fixture slow close")
	// Occupy the reload queue while the previous instance is still closing.
	cmd.Process.Signal(syscall.SIGHUP)
	time.Sleep(30 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			data, _ := os.ReadFile(output)
			t.Fatalf("termination: %v logs=%s", err, data)
		}
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		<-done
		data, _ := os.ReadFile(output)
		t.Fatalf("termination was lost behind queued reload: %s", data)
	}
}
