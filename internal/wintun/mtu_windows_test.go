//go:build windows

package wintun

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type fakeInterfaceMTUAPI struct {
	row    windows.MibIpInterfaceRow
	gets   int
	sets   int
	getErr error
	setErr error
}

func (f *fakeInterfaceMTUAPI) Get(row *windows.MibIpInterfaceRow) error {
	f.gets++
	if f.getErr != nil {
		return f.getErr
	}
	*row = f.row
	return nil
}

func (f *fakeInterfaceMTUAPI) Set(row *windows.MibIpInterfaceRow) error {
	f.sets++
	if f.setErr != nil {
		return f.setErr
	}
	f.row = *row
	return nil
}

func fakeMTUInterface(luid uint64, family uint16, mtu uint32) *fakeInterfaceMTUAPI {
	return &fakeInterfaceMTUAPI{row: windows.MibIpInterfaceRow{
		Family: family, InterfaceLuid: luid, NlMtu: mtu,
		Metric: 53, WeakHostSend: 1, UseAutomaticMetric: 1,
	}}
}

func TestWintunMTURejectsInvalidInputsWithoutMutation(t *testing.T) {
	cases := []struct {
		name   string
		luid   uint64
		family uint16
		mtu    uint32
	}{
		{"missing_luid", 0, windows.AF_INET, 1400},
		{"unknown_family", 8, windows.AF_UNSPEC, 1400},
		{"too_small_ipv4", 8, windows.AF_INET, 575},
		{"too_small_ipv6", 8, windows.AF_INET6, 1279},
		{"too_large_ipv4", 8, windows.AF_INET, 65536},
		{"too_large_ipv6", 8, windows.AF_INET6, 65536},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := fakeMTUInterface(8, windows.AF_INET, 1500)
			lease, err := setInterfaceMTU(f, test.luid, test.family, test.mtu)
			if err == nil || lease != nil || f.gets != 0 || f.sets != 0 {
				t.Fatalf("invalid request mutated interface: lease=%v err=%v reads=%d writes=%d", lease, err, f.gets, f.sets)
			}
		})
	}
}

func TestWintunMTULeaseOwnsIPv4AndIPv6Changes(t *testing.T) {
	for _, test := range []struct {
		name   string
		family uint16
		old    uint32
		new    uint32
	}{
		{"IPv4", windows.AF_INET, 1500, 1400},
		{"IPv6", windows.AF_INET6, 1500, 1380},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := fakeMTUInterface(42, test.family, test.old)
			lease, err := setInterfaceMTU(f, 42, test.family, test.new)
			if err != nil {
				t.Fatal(err)
			}
			if f.sets != 1 || f.row.NlMtu != test.new {
				t.Fatalf("MTU was not applied: count=%d value=%d", f.sets, f.row.NlMtu)
			}
			// Preserve unrelated OS properties, even if they change after setup.
			f.row.Metric = 27
			f.row.WeakHostSend = 0
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil || f.sets != 2 ||
				f.row.NlMtu != test.old || f.row.Metric != 27 ||
				f.row.WeakHostSend != 0 || f.row.UseAutomaticMetric != 1 {
				t.Fatalf("unsafe restoration or double change: %+v, writes=%d, err=%v", f.row, f.sets, err)
			}
		})
	}
}

func TestWintunMTUSameValueIsNotAdopted(t *testing.T) {
	f := fakeMTUInterface(7, windows.AF_INET, 1400)
	lease, err := setInterfaceMTU(f, 7, windows.AF_INET, 1400)
	if err != nil {
		t.Fatal(err)
	}
	f.row.NlMtu = 1450 // Other manager adjusts an already-owned setting.
	if err := lease.Close(); err != nil || f.sets != 0 || f.row.NlMtu != 1450 {
		t.Fatalf("unchanged MTU was incorrectly adopted: err=%v writes=%d", err, f.sets)
	}
}

func TestWintunMTUForeignChangesAreNotOverwritten(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*windows.MibIpInterfaceRow)
	}{
		{"mtu", func(r *windows.MibIpInterfaceRow) { r.NlMtu = 1300 }},
		{"luid", func(r *windows.MibIpInterfaceRow) { r.InterfaceLuid++ }},
		{"family", func(r *windows.MibIpInterfaceRow) { r.Family = windows.AF_INET6 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := fakeMTUInterface(8, windows.AF_INET, 1500)
			lease, err := setInterfaceMTU(f, 8, windows.AF_INET, 1400)
			if err != nil {
				t.Fatal(err)
			}
			test.change(&f.row)
			if err := lease.Close(); !errors.Is(err, ErrMTUChanged) || f.sets != 1 {
				t.Fatalf("foreign state was overwritten: err=%v writes=%d", err, f.sets)
			}
		})
	}
}

func TestWintunMTUFailureModes(t *testing.T) {
	t.Run("lookup_failure", func(t *testing.T) {
		f := fakeMTUInterface(8, windows.AF_INET, 1500)
		f.getErr = syscall.Errno(5)
		if lease, err := setInterfaceMTU(f, 8, windows.AF_INET, 1400); err == nil || lease != nil || f.sets != 0 {
			t.Fatalf("lookup error was ignored: %v", err)
		}
	})
	t.Run("apply_failure", func(t *testing.T) {
		f := fakeMTUInterface(8, windows.AF_INET, 1500)
		f.setErr = syscall.Errno(5)
		if lease, err := setInterfaceMTU(f, 8, windows.AF_INET, 1400); err == nil || lease != nil || f.row.NlMtu != 1500 {
			t.Fatalf("MTU set error was ignored: %v", err)
		}
	})
	t.Run("interface_removed", func(t *testing.T) {
		f := fakeMTUInterface(8, windows.AF_INET, 1500)
		lease, err := setInterfaceMTU(f, 8, windows.AF_INET, 1400)
		if err != nil {
			t.Fatal(err)
		}
		f.getErr = windows.ERROR_NOT_FOUND
		if err := lease.Close(); err != nil || f.sets != 1 {
			t.Fatalf("removed Wintun interface incorrectly restored: %v", err)
		}
	})
	t.Run("failed_cleanup_remains_failed", func(t *testing.T) {
		f := fakeMTUInterface(8, windows.AF_INET, 1500)
		lease, err := setInterfaceMTU(f, 8, windows.AF_INET, 1400)
		if err != nil {
			t.Fatal(err)
		}
		f.setErr = syscall.Errno(5)
		if err := lease.Close(); !errors.Is(err, syscall.Errno(5)) {
			t.Fatalf("cleanup failure hidden: %v", err)
		}
		if err := lease.Close(); !errors.Is(err, syscall.Errno(5)) || f.sets != 2 {
			t.Fatalf("cleanup failure was not retained: err=%v writes=%d", err, f.sets)
		}
	})
}

func TestWindowsMTUIPHelperSymbolsAvailableWithoutDriver(t *testing.T) {
	// Resolves system DLL entrypoints without installing a Wintun adapter.
	if _, err := newIPInterfaceAPI(); err != nil {
		t.Fatalf("Windows MTU IP Helper APIs unavailable: %v", err)
	}
}
