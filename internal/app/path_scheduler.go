package app

import (
	"fmt"

	quic "github.com/qoke/mp-quic-go"
)

// The policy is connection-wide. mp-quic-go v0.3.1's PathScheduler is
// called per QUIC packet and doesn't receive the inner TUN packet / DSCP.
// This must not be presented as RTP-only path steering.
const (
	pathSchedulerRoundRobin = "round_robin"
	pathSchedulerLowLatency = "low_latency"
)

// normalizePathScheduler ensures that a typo cannot silently disable the
// intended network policy. Empty retains the established Round Robin
// behavior for existing Client and Server installations.
func normalizePathScheduler(policy string) (string, error) {
	switch policy {
	case "", pathSchedulerRoundRobin:
		return pathSchedulerRoundRobin, nil
	case pathSchedulerLowLatency:
		return pathSchedulerLowLatency, nil
	default:
		return "", fmt.Errorf("invalid MPQUIC path_scheduler %q (round_robin|low_latency)", policy)
	}
}

// newPathScheduler creates an independent per-connection scheduler.
// In low_latency mode, the upstream algorithm prefers measured low-RTT
// paths that can send, and uses alternatives when the preferred path
// becomes unavailable / congestion-limited. No fixed WAN count is used.
func newPathScheduler(policy string) quic.PathScheduler {
	if policy == pathSchedulerLowLatency {
		return quic.NewLowLatencyScheduler()
	}
	return quic.NewRoundRobinScheduler()
}
