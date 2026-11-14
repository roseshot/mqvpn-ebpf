package app

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

// attachConfiguredTC fails open only in auto mode. Required remains strict.
func attachConfiguredTC(ifname string, policy tcebpf.Config, mtu int, logger *slog.Logger) (*tcebpf.Attachment, error) {
	if logger == nil {
		logger = slog.Default()
	}
	norm, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	if !norm.Enabled() {
		return nil, nil
	}
	attached, err := tcebpf.Attach(ifname, norm, mtu)
	if err != nil {
		if norm.Mode == "auto" {
			logger.Warn("TUN TC eBPF unavailable; using ordinary TUN forwarding", "tun", ifname, "object", norm.Object, "error", err)
			return nil, nil
		}
		return nil, err
	}
	logger.Info("TUN TC eBPF attached", "tun", ifname, "mode", norm.Mode, "mss_clamp", norm.MSSClamp, "stats", norm.Stats)
	return attached, nil
}

// reportAndCloseTC closes the live TCX links while the TUN still exists.
func reportAndCloseTC(tc *tcebpf.Attachment, logger *slog.Logger) error {
	if tc == nil {
		return nil
	}
	if counters, err := tc.Snapshot(); err == nil {
		logger.Info("TUN TC eBPF counters", "ingress", counters.Ingress, "egress", counters.Egress)
	} else {
		logger.Warn("read TUN TC eBPF counters", "error", err)
	}
	err := tc.Close()
	if err != nil {
		logger.Error("detach TUN TC eBPF", "error", err)
	}
	return err
}

// managedPumpDevice serializes resource teardown and makes it idempotent:
// restore DNS and detach TCX first, then release the TUN (and restore any prior interface
// configuration), then the app-level deferred route guard is closed.
// Unexpected cleanup errors are fatal to the reconnect supervisor.
type managedPumpDevice struct {
	io.ReadWriteCloser
	beforeClose func() error
	once        sync.Once
	closeErr    error
}

func (d *managedPumpDevice) Close() error {
	d.once.Do(func() {
		var prior error
		if d.beforeClose != nil {
			if err := d.beforeClose(); err != nil {
				prior = fmt.Errorf("%w: detach TUN TCX: %v", tun.ErrCleanup, err)
			}
		}
		d.closeErr = errors.Join(prior, d.ReadWriteCloser.Close())
	})
	return d.closeErr
}

func newManagedPumpDevice(device io.ReadWriteCloser, tc *tcebpf.Attachment, dns *dnspush.Lease, logger *slog.Logger) *managedPumpDevice {
	return &managedPumpDevice{ReadWriteCloser: device, beforeClose: func() error {
		// Release resolver state while the TUN is still alive, then detach
		// TCX before releasing the interface and its routes.
		var dnsErr error
		if dns != nil {
			dnsErr = dns.Close()
		}
		if dnsErr != nil {
			logger.Error("restore TUN DNS on disconnect", "error", dnsErr)
		}
		return errors.Join(dnsErr, reportAndCloseTC(tc, logger))
	}}
}
