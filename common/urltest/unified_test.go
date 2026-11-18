package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type countingDialer struct {
	dials atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *countingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

var _ N.Dialer = (*countingDialer)(nil)

func TestUnifiedURLTestTimesSecondRequestOnSameConnection(t *testing.T) {
	var (
		mutex    sync.Mutex
		requests int
		conns    = map[string]int{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		requests++
		n := requests
		conns[r.RemoteAddr]++
		mutex.Unlock()
		if n == 1 {
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	dialer := &countingDialer{}
	delay, err := UnifiedURLTest(context.Background(), server.URL, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if delay >= 200 {
		t.Fatalf("delay %d ms includes the warm-up request", delay)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(conns) != 1 {
		t.Fatalf("requests used %d connections, want 1", len(conns))
	}
	if dialer.dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dialer.dials.Load())
	}
}

func TestUnifiedURLTestFallsBackToFirstResult(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Drop the connection on the second request.
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer server.Close()

	delay, err := UnifiedURLTest(context.Background(), server.URL, &countingDialer{})
	if err != nil {
		t.Fatalf("second failure must fall back to the first result: %v", err)
	}
	if delay < 50 {
		t.Fatalf("delay %d ms, want the first request's time (>= 50)", delay)
	}
}

func TestUnifiedURLTestHonoursContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := UnifiedURLTest(ctx, server.URL, &countingDialer{}); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestUnifiedURLTestSecondRequestTimeoutIsAnError(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	delay, err := UnifiedURLTest(ctx, server.URL, &countingDialer{})
	if err == nil || delay != 0 {
		t.Fatalf("second request out of time must fail, got %d ms, err %v", delay, err)
	}
}
