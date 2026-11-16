package session

import (
	"fmt"

	quic "github.com/qoke/mp-quic-go"
)

// The policy is connection-wide. mp-quic-go v0.3.1's PathScheduler is
// called per QUIC packet and doesn't receive the inner TUN packet / DSCP.
// This must not be presented as RTP-only path steering.
const (
	SchedulerRoundRobin = "round_robin"
	SchedulerLowLatency = "low_latency"
)

// NormalizePathScheduler ensures that a typo cannot silently disable the
// intended network policy. Empty selects the default Round Robin policy.
func NormalizePathScheduler(policy string) (string, error) {
	switch policy {
	case "", SchedulerRoundRobin:
		return SchedulerRoundRobin, nil
	case SchedulerLowLatency:
		return SchedulerLowLatency, nil
	default:
		return "", fmt.Errorf("invalid MPQUIC path_scheduler %q (round_robin|low_latency)", policy)
	}
}

// NewPathScheduler creates an independent per-connection scheduler.
// In low_latency mode, the upstream algorithm prefers measured low-RTT
// paths that can send, and uses alternatives when the preferred path
// becomes unavailable / congestion-limited. No fixed WAN count is used.
func NewPathScheduler(policy string) quic.PathScheduler {
	if policy == SchedulerLowLatency {
		return quic.NewLowLatencyScheduler()
	}
	return quic.NewRoundRobinScheduler()
}
