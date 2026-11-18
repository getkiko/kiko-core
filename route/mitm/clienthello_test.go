package mitm

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// helloCapture keeps the first record the client sends and nothing after it.
func TestHelloCapture(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	capture := &helloCapture{Conn: serverSide}
	go func() {
		tls.Client(clientSide, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}).Handshake()
	}()
	server := tls.Server(capture, &tls.Config{})
	server.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.Handshake() // fails: no certificate; the hello was read
	record := capture.snapshot()
	require.NotNil(t, record)
	ids, ok := helloExtensionIDs(record)
	require.True(t, ok)
	require.Contains(t, ids, uint16(0))  // server_name
	require.Contains(t, ids, uint16(43)) // supported_versions
	require.Equal(t, 5+int(record[3])<<8+int(record[4]), len(record))
	require.Nil(t, (*helloCapture)(nil).snapshot())
}

func TestHelloCaptureNotHandshake(t *testing.T) {
	capture := &helloCapture{}
	capture.record([]byte("GET / HTTP/1.1\r\n"))
	require.Nil(t, capture.snapshot())
	_, ok := helloExtensionIDs([]byte{0x16, 3, 1, 0, 2, 9, 9})
	require.False(t, ok)
}
