package app

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

func TestAutoTCFailureFallsBackButRequiredFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	missing := filepath.Join(t.TempDir(), "missing-tun-tc.o")
	for _, mode := range []string{"auto", "required", "off"} {
		cfg := tcebpf.Config{Mode: mode, Object: missing, MSSClamp: "auto", Stats: true}
		// This missing-interface attach error exercises the same policy path
		// as a missing ELF or unsupported TCX kernel without requiring root.
		got, err := attachConfiguredTC("mqvpn-no-such-tun", cfg, 1400, logger)
		if got != nil {
			t.Fatalf("%s: unexpected attached TCX", mode)
		}
		if (err != nil) != (mode == "required") {
			t.Fatalf("%s: unexpected error %v", mode, err)
		}
	}
}

type testCleanupDevice struct {
	closed bool
	order  *[]string
	err    error
}

func (d *testCleanupDevice) Read([]byte) (int, error)    { return 0, io.EOF }
func (d *testCleanupDevice) Write(b []byte) (int, error) { return len(b), nil }
func (d *testCleanupDevice) Close() error {
	d.closed = true
	*d.order = append(*d.order, "tun")
	return d.err
}

func TestManagedClientSessionClosesTCBeforeTUN(t *testing.T) {
	var order []string
	base := &testCleanupDevice{order: &order}
	w := &managedPumpDevice{ReadWriteCloser: base, beforeClose: func() error {
		order = append(order, "tc")
		return nil
	}}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !base.closed || len(order) != 2 || order[0] != "tc" || order[1] != "tun" {
		t.Fatalf("cleanup order/once: %v", order)
	}
}

func TestManagedClientSessionFailsClosedOnTCDetachError(t *testing.T) {
	var order []string
	base := &testCleanupDevice{order: &order}
	w := &managedPumpDevice{ReadWriteCloser: base, beforeClose: func() error {
		order = append(order, "tc")
		return errors.New("tcx detach denied")
	}}
	err := w.Close()
	if !errors.Is(err, tun.ErrCleanup) || !base.closed {
		t.Fatalf("TCX detach error was swallowed: %v", err)
	}
}
