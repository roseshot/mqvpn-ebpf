package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/logging"
)

// errUnsafeReconnect marks a failed netlink cleanup that may leave a stale
// route or TUN lease behind. Never start another session in this state.
var errUnsafeReconnect = errors.New("previous VPN session did not clean up safely")

const (
	reconnectInitialDelay = time.Second
	reconnectMaximumDelay = 30 * time.Second
	// A sustained connection is evidence that the path was healthy.
	// Reset accumulated backoff so the next outage starts at 1 second.
	reconnectStableAfter = time.Minute
)

// runClientSupervisor retries initial connection errors and established
// session terminations. runClientSession completes all cleanup before it
// returns; the supervisor never overlaps two VPN tunnels.
func runClientSupervisor(ctx context.Context, enabled bool, logger *slog.Logger, attempt func(context.Context) error) error {
	return runClientSupervisorWithWait(ctx, enabled, logger, attempt, waitReconnect)
}

func runClientSupervisorWithWait(ctx context.Context, enabled bool, logger *slog.Logger, attempt func(context.Context) error, wait func(context.Context, time.Duration) error) error {
	logger = logging.Ensure(logger)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !enabled {
		return attempt(ctx)
	}
	delay := reconnectInitialDelay
	for attemptNumber := 1; ; attemptNumber++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		started := time.Now()
		err := attempt(ctx)
		if stop := ctx.Err(); stop != nil {
			return stop
		}
		if errors.Is(err, errUnsafeReconnect) {
			return err
		}
		if time.Since(started) >= reconnectStableAfter {
			delay = reconnectInitialDelay
		}
		if err == nil {
			logger.WarnContext(ctx,"VPN session closed; scheduling reconnect", "attempt", attemptNumber, "retry_in", delay)
		} else if errors.Is(err, context.Canceled) {
			// A cancellation from a nested session context (rather than the
			// daemon context) is still a disconnect that can be retried.
			logger.WarnContext(ctx,"VPN session interrupted; scheduling reconnect", "error", err, "attempt", attemptNumber, "retry_in", delay)
		} else {
			logger.WarnContext(ctx,"VPN connection failed; scheduling reconnect", "error", err, "attempt", attemptNumber, "retry_in", delay)
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
		delay = nextReconnectDelay(delay)
	}
}

func nextReconnectDelay(current time.Duration) time.Duration {
	if current >= reconnectMaximumDelay/2 {
		return reconnectMaximumDelay
	}
	if current < reconnectInitialDelay {
		return reconnectInitialDelay
	}
	return current * 2
}

func waitReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
