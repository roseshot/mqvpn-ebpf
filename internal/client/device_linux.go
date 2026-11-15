//go:build linux

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

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

func newManagedPumpDevice(ctx context.Context, device io.ReadWriteCloser, tc *tcebpf.Attachment, dns *dnspush.Lease, logger *slog.Logger) *managedPumpDevice {
	return &managedPumpDevice{ReadWriteCloser: device, beforeClose: func() error {
		// Release resolver state while the TUN is still alive, then detach
		// TCX before releasing the interface and its routes.
		var dnsErr error
		if dns != nil {
			dnsErr = dns.Close()
		}
		if dnsErr != nil {
			logger.ErrorContext(ctx, "restore TUN DNS on disconnect", "error", dnsErr)
		}
		return errors.Join(dnsErr, tcebpf.ReportAndClose(ctx, tc, logger))
	}}
}
