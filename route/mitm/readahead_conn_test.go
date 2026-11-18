package mitm

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A deadline ends the waiting Read only: a read below that completes later is delivered by the
// next Read, and the timeout is not sticky.
func TestReadAheadDeadlineKeepsInFlightRead(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	conn := newReadAheadConn(noDeadlineConn{near})
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	start := time.Now()
	_, err := conn.Read(make([]byte, 8))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
	require.NoError(t, conn.SetReadDeadline(aLongTimeAgo))
	_, err = conn.Read(make([]byte, 8))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	go far.Write([]byte("hello"))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	buffer := make([]byte, 8)
	n, err := conn.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buffer[:n]))
}

// Data that arrived with an error is read first; the error then repeats.
func TestReadAheadDataBeforeError(t *testing.T) {
	near, far := net.Pipe()
	conn := newReadAheadConn(near)
	defer conn.Close()
	go func() {
		far.Write([]byte("abc"))
		far.Close()
	}()
	content, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, "abc", string(content))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

// Reads interrupted at random by deadlines lose, repeat and reorder nothing.
func TestReadAheadStreamUnderInterrupts(t *testing.T) {
	near, far := net.Pipe()
	conn := newReadAheadConn(near)
	defer conn.Close()
	payload := make([]byte, 4<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	go func() {
		for offset := 0; offset < len(payload); {
			n, err := far.Write(payload[offset:min(offset+1000+offset%9000, len(payload))])
			if err != nil {
				return
			}
			offset += n
		}
		far.Close()
	}()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Microsecond):
				_ = conn.SetReadDeadline(aLongTimeAgo)
			}
		}
	}()
	var received bytes.Buffer
	buffer := make([]byte, 3000)
	for {
		_ = conn.SetReadDeadline(time.Time{})
		n, err := conn.Read(buffer)
		received.Write(buffer[:n])
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	require.True(t, bytes.Equal(payload, received.Bytes()))
}

// Close ends a waiting Read and the goroutine reading ahead, also with a result unread.
func TestReadAheadCloseStopsReading(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 10 {
		near, far := net.Pipe()
		conn := newReadAheadConn(near)
		go far.Write([]byte("unread"))
		readErr := make(chan error, 1)
		go func() {
			time.Sleep(20 * time.Millisecond)
			_, err := conn.Read(make([]byte, 0))
			readErr <- err
		}()
		time.Sleep(50 * time.Millisecond)
		require.NoError(t, conn.Close())
		far.Close()
		<-readErr
	}
	near, far := net.Pipe()
	defer far.Close()
	conn := newReadAheadConn(near)
	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	select {
	case err := <-readErr:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("read not ended by close")
	}
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= before+1
	}, 3*time.Second, 20*time.Millisecond, "goroutines: before %d, now %d", before, runtime.NumGoroutine())
}

// A connection already behind the reader is not wrapped twice.
func TestWithDeadlineReaderOnce(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	conn := withDeadlineReader(near)
	defer conn.Close()
	require.Same(t, conn, withDeadlineReader(conn))
}
