package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestEstablishWithRetryUsesNextConnection(t *testing.T) {
	failedClient, failedServer := net.Pipe()
	defer failedServer.Close()
	failedConn := &trackedConn{Conn: failedClient}
	successClient, successServer := net.Pipe()
	defer successServer.Close()
	var attempts atomic.Int32

	establisher := NewRetryEstablisher(EstablishFunc(func(context.Context) (net.Conn, error) {
		if attempts.Add(1) == 1 {
			return failedConn, io.ErrUnexpectedEOF
		}
		return successClient, nil
	}), RetryOptions{Retries: 1})
	conn, err := establisher.Establish(context.Background())
	if err != nil {
		t.Fatalf("establish connection: %v", err)
	}
	defer conn.Close()
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	if !failedConn.closed.Load() {
		t.Fatal("failed connection was not closed")
	}
}

func TestEstablishWithRetryAppliesAttemptTimeout(t *testing.T) {
	var attempts atomic.Int32
	establisher := NewRetryEstablisher(EstablishFunc(func(ctx context.Context) (net.Conn, error) {
		attempts.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}), RetryOptions{
		Retries:        1,
		AttemptTimeout: 10 * time.Millisecond,
	})
	_, err := establisher.Establish(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

func TestEstablishWithRetryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	establisher := NewRetryEstablisher(EstablishFunc(func(context.Context) (net.Conn, error) {
		attempts++
		cancel()
		return nil, io.ErrUnexpectedEOF
	}), RetryOptions{Retries: 3})
	_, err := establisher.Establish(ctx)
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("error = %v, attempts = %d; want canceled after one attempt", err, attempts)
	}
}

func TestEstablishWithRetryStopsOnPermanentError(t *testing.T) {
	attempts := 0
	failure := &NonRetryableError{Err: io.ErrUnexpectedEOF}
	establisher := NewRetryEstablisher(EstablishFunc(func(context.Context) (net.Conn, error) {
		attempts++
		return nil, failure
	}), RetryOptions{Retries: 3})
	_, err := establisher.Establish(context.Background())
	if !errors.Is(err, failure) || attempts != 1 {
		t.Fatalf("error = %v, attempts = %d; want permanent error after one attempt", err, attempts)
	}
}
