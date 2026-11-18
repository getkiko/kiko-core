package dialer

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// NonRetryableError marks an error whose cause cannot be resolved by retrying.
// Establishers wrap such errors so the retry loop gives up immediately instead
// of burning every remaining attempt on a request that is certain to fail —
// and, worse, tripping server-side rate limits in the process.
type NonRetryableError struct {
	Err error
}

func (e *NonRetryableError) Error() string { return e.Err.Error() }

func (e *NonRetryableError) Unwrap() error { return e.Err }

// IsNonRetryable reports whether err is marked as non-retryable.
func IsNonRetryable(err error) bool {
	var nonRetryable *NonRetryableError
	return errors.As(err, &nonRetryable)
}

type EstablishFunc func(ctx context.Context) (net.Conn, error)

func (f EstablishFunc) Establish(ctx context.Context) (net.Conn, error) {
	return f(ctx)
}

type ConnectionEstablisher interface {
	Establish(ctx context.Context) (net.Conn, error)
}

type RetryOptions struct {
	Retries        int
	AttemptTimeout time.Duration
	Logger         logger.ContextLogger
	Name           string
}

const DefaultRetryAttemptTimeout = 10 * time.Second

type dialEstablisher struct {
	dialer      N.Dialer
	network     string
	destination M.Socksaddr
}

func NewDialEstablisher(dialer N.Dialer, network string, destination M.Socksaddr) ConnectionEstablisher {
	return &dialEstablisher{dialer: dialer, network: network, destination: destination}
}

func (e *dialEstablisher) Establish(ctx context.Context) (net.Conn, error) {
	return e.dialer.DialContext(ctx, e.network, e.destination)
}

type retryEstablisher struct {
	upstream ConnectionEstablisher
	options  RetryOptions
}

func NewRetryEstablisher(upstream ConnectionEstablisher, options RetryOptions) ConnectionEstablisher {
	if options.Retries <= 0 {
		return upstream
	}
	if options.AttemptTimeout <= 0 {
		options.AttemptTimeout = DefaultRetryAttemptTimeout
	}
	return &retryEstablisher{upstream: upstream, options: options}
}

// Establish retries a complete, verifiable connection establishment. The
// upstream Adapter owns intermediate connections and closes any it cannot
// return. A connection returned together with an error is closed here.
func (e *retryEstablisher) Establish(ctx context.Context) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt <= e.options.Retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx := ctx
		var cancel context.CancelFunc
		if e.options.AttemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, e.options.AttemptTimeout)
		}
		conn, err := e.upstream.Establish(attemptCtx)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		lastErr = err
		if e.options.Logger != nil {
			e.options.Logger.DebugContext(ctx, e.options.Name, " connection establishment attempt ", attempt+1, " failed: ", err)
		}
		// Retrying a non-retryable failure cannot succeed; it only multiplies
		// the request rate against a server that already refused us.
		if IsNonRetryable(err) {
			return nil, lastErr
		}
	}
	return nil, lastErr
}
