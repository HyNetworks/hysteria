package pppbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Bad credentials do not become good by waiting. Retrying an auth failure buries
// the cause under a restart loop, so it has to reach the caller, which reports it
// and stops.
func TestIsPermanentDialErrorTreatsAuthFailureAsPermanent(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"auth failure", coreErrs.AuthError{StatusCode: 401}, true},
		{"auth failure, wrapped", fmt.Errorf("dial: %w", coreErrs.AuthError{StatusCode: 403}), true},
		{"explicitly permanent", permanentDialError{errors.New("nope")}, true},
		{"client closed", coreErrs.ClosedError{}, true},

		{"connect failure is worth retrying", coreErrs.ConnectError{Err: errors.New("refused")}, false},
		{"plain error is worth retrying", errors.New("network unreachable"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPermanentDialError(tt.err))
		})
	}
}

// dialWithRetry hands a permanent failure straight back instead of backing off
// against it. The backoff starts at a second, so a retrying implementation could
// not return this quickly, and it must have tried exactly once.
func TestDialWithRetryReturnsImmediatelyOnAuthFailure(t *testing.T) {
	b := &Bridge{Logger: zap.NewNop()}
	attempts := 0
	dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		attempts++
		return nil, nil, nil, coreErrs.AuthError{StatusCode: 401}
	}

	start := time.Now()
	_, _, _, err := b.dialWithRetry(context.Background(), dialFn)
	elapsed := time.Since(start)

	require.Error(t, err)
	var authErr coreErrs.AuthError
	require.ErrorAs(t, err, &authErr, "the auth failure must reach the caller intact")
	assert.Equal(t, 1, attempts, "an auth failure must not be retried")
	assert.Less(t, elapsed, 500*time.Millisecond,
		"returned after %s, which means it backed off instead of giving up", elapsed)
}

// A retryable failure still retries, so making auth permanent has not turned
// every transient problem into a hard stop.
func TestDialWithRetryStillRetriesTransientFailures(t *testing.T) {
	b := &Bridge{Logger: zap.NewNop()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		attempts++
		if attempts >= 2 {
			// Cancelling is the only thing that stops the loop now: the child is
			// not watched here, because its one reader already took the first frame.
			cancel()
		}
		return nil, nil, nil, errors.New("connection refused")
	}

	_, _, _, err := b.dialWithRetry(ctx, dialFn)
	require.Error(t, err)
	assert.GreaterOrEqual(t, attempts, 2, "a transient failure must be retried")
}
