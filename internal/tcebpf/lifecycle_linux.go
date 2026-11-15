//go:build linux

package tcebpf

import (
	"context"
	"log/slog"

	"github.com/roseshot/mqvpn-ebpf/internal/logging"
)

// AttachConfigured fails open only in auto mode. Required remains strict.
func AttachConfigured(ctx context.Context, ifname string, policy Config, mtu int, logger *slog.Logger) (*Attachment, error) {
	logger = logging.Ensure(logger)
	norm, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	if !norm.Enabled() {
		return nil, nil
	}
	attached, err := Attach(ifname, norm, mtu)
	if err != nil {
		if norm.Mode == "auto" {
			logger.WarnContext(ctx, "TUN TC eBPF unavailable; using ordinary TUN forwarding", "tun", ifname, "object", norm.Object, "error", err)
			return nil, nil
		}
		return nil, err
	}
	logger.InfoContext(ctx, "TUN TC eBPF attached", "tun", ifname, "mode", norm.Mode, "mss_clamp", norm.MSSClamp, "stats", norm.Stats)
	return attached, nil
}

// ReportAndClose closes the live TCX links while the TUN still exists.
func ReportAndClose(ctx context.Context, tc *Attachment, logger *slog.Logger) error {
	if tc == nil {
		return nil
	}
	logger = logging.Ensure(logger)
	if counters, err := tc.Snapshot(); err == nil {
		logger.InfoContext(ctx, "TUN TC eBPF counters", "ingress", counters.Ingress, "egress", counters.Egress)
	} else {
		logger.WarnContext(ctx, "read TUN TC eBPF counters", "error", err)
	}
	err := tc.Close()
	if err != nil {
		logger.ErrorContext(ctx, "detach TUN TC eBPF", "error", err)
	}
	return err
}
