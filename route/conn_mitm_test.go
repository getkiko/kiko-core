package route

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// echoDialer answers every dial with an echoing pipe, or fails with err.
type echoDialer struct {
	err   error
	dials int
	last  net.Conn
}

func (d *echoDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	d.dials++
	if d.err != nil {
		return nil, d.err
	}
	client, server := net.Pipe()
	d.last = client
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func (d *echoDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func echoThrough(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	payload := make([]byte, size)
	written := make(chan struct{})
	go func() {
		_, _ = conn.Write(make([]byte, size))
		close(written)
	}()
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	// The meter counts a write once Write returns, which can be after the echo was read.
	<-written
}

// A redialed upstream of a decrypted connection is reported as a dial and metered into the
// session's single close report.
func TestMITMRedialMetersIntoSessionReport(t *testing.T) {
	node := &groupRouteNode{tag: "node"}
	learner := learningRouteGroup{&groupRouteGroup{tag: "smart", selected: node}}
	metadata := &adapter.InboundContext{
		Destination:   M.ParseSocksaddr("example.com:443"),
		OutboundChain: []adapter.Outbound{learner, node},
	}
	manager := &ConnectionManager{logger: logger.NOP(), urlTestHistory: urltest.NewHistoryStorage()}
	this := &echoDialer{}
	first, err := this.DialContext(context.Background(), N.NetworkTCP, metadata.Destination)
	if err != nil {
		t.Fatal(err)
	}
	var closes int
	meter, onClose := newGroupMeter(metadata, func(error) { closes++ })
	echoThrough(t, meter.wrap(first), 5)

	redial := manager.mitmRedial(this, metadata, meter)
	second, err := redial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	echoThrough(t, second, 7)
	second.Close()
	if len(learner.dials) != 1 || learner.members[0] != node || learner.dials[0].Err != nil {
		t.Fatalf("dial reports %+v", learner.dials)
	}
	if len(learner.closes) != 0 {
		t.Fatal("redialed connection reported a close of its own")
	}

	failure := errors.New("refused")
	this.err = failure
	if _, err = redial(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("redial error %v", err)
	}
	if len(learner.dials) != 2 || !errors.Is(learner.dials[1].Err, failure) {
		t.Fatalf("failed redial not reported: %+v", learner.dials)
	}

	onClose(nil)
	if closes != 1 || len(learner.closes) != 1 {
		t.Fatalf("closes %d, reports %d", closes, len(learner.closes))
	}
	report := learner.closes[0]
	if report.Upload != 12 || report.Download != 12 || report.Err != nil {
		t.Fatalf("report %+v", report)
	}
	if this.dials != 3 {
		t.Fatalf("dials %d", this.dials)
	}
}

// Without learning groups the redialed connection is returned as dialed.
func TestMITMRedialWithoutLearners(t *testing.T) {
	metadata := &adapter.InboundContext{Destination: M.ParseSocksaddr("example.com:443")}
	meter, _ := newGroupMeter(metadata, nil)
	if meter != nil {
		t.Fatal("meter without learning groups")
	}
	manager := &ConnectionManager{logger: logger.NOP()}
	this := &echoDialer{}
	conn, err := manager.mitmRedial(this, metadata, meter)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn != this.last {
		t.Fatal("wrapped")
	}
	echoThrough(t, conn, 3)
}
