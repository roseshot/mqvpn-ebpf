//go:build windows

package wintun

import (
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fakeAddressAPI struct {
	existing  windows.MibUnicastIpAddressRow
	created   int
	deleted   int
	createErr error
	getErr    error
	deleteErr error
}

func (f *fakeAddressAPI) Initialize(row *windows.MibUnicastIpAddressRow) {
	row.ValidLifetime = ^uint32(0)
	row.PreferredLifetime = ^uint32(0)
}
func (f *fakeAddressAPI) Create(row *windows.MibUnicastIpAddressRow) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created++
	f.existing = *row
	return nil
}
func (f *fakeAddressAPI) Get(row *windows.MibUnicastIpAddressRow) error {
	if f.getErr != nil {
		return f.getErr
	}
	*row = f.existing
	return nil
}
func (f *fakeAddressAPI) Delete(row *windows.MibUnicastIpAddressRow) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted++
	return nil
}

func TestWindowsAddressRowPreservesIPv4IPv6HostBits(t *testing.T) {
	for _, test := range []struct {
		name   string
		cidr   string
		family uint16
	}{
		{"IPv4", "10.77.5.26/24", windows.AF_INET},
		{"IPv6", "2001:db8:100::12/64", windows.AF_INET6},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(test.cidr)
			row, err := addressRow(&fakeAddressAPI{}, 1101, prefix)
			if err != nil {
				t.Fatal(err)
			}
			if row.InterfaceLuid != 1101 || row.OnLinkPrefixLength != uint8(prefix.Bits()) ||
				row.PrefixOrigin != windows.IpPrefixOriginManual ||
				row.SuffixOrigin != windows.IpSuffixOriginManual ||
				row.Address.Family != test.family {
				t.Fatalf("incorrect IP Helper row: %+v", row)
			}
			if test.family == windows.AF_INET {
				sock := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
				if sock.Addr != prefix.Addr().As4() {
					t.Fatalf("Windows IPv4 sockaddr lost host bits: %v", sock.Addr)
				}
			} else {
				if row.Address.Addr != prefix.Addr().As16() {
					t.Fatalf("Windows IPv6 sockaddr lost host bits: %v", row.Address.Addr)
				}
			}
		})
	}
}

func TestWindowsAddressInvalidInputCannotMutateSystem(t *testing.T) {
	bad := []string{"0.0.0.0/0", "255.255.255.255/32", "127.0.0.1/8",
		"224.0.0.1/24", "fe80::1/64", "::/0", "2001:db8::1/0"}
	for _, raw := range bad {
		fake := &fakeAddressAPI{}
		if _, err := assignAddress(fake, 8, netip.MustParsePrefix(raw)); err == nil {
			t.Errorf("invalid prefix accepted: %s", raw)
		}
		if fake.created != 0 || fake.deleted != 0 {
			t.Fatalf("invalid prefix %s changed addresses", raw)
		}
	}
	if _, err := assignAddress(&fakeAddressAPI{}, 0, netip.MustParsePrefix("10.77.0.1/24")); err == nil {
		t.Fatal("missing adapter LUID accepted")
	}
}

func TestWindowsAddressLeaseOwnedRollbackAndConflict(t *testing.T) {
	t.Run("created_then_deleted_once", func(t *testing.T) {
		fake := &fakeAddressAPI{}
		lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24"))
		if err != nil {
			t.Fatal(err)
		}
		if fake.created != 1 {
			t.Fatalf("created %d addresses", fake.created)
		}
		// OS may update DAD state without changing the owned address.
		fake.existing.DadState = windows.IpDadStatePreferred
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil || fake.deleted != 1 {
			t.Fatalf("double delete of Wintun address: deleted=%d error=%v", fake.deleted, err)
		}
	})
	t.Run("foreign_prefix_change", func(t *testing.T) {
		fake := &fakeAddressAPI{}
		lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24"))
		if err != nil {
			t.Fatal(err)
		}
		fake.existing.OnLinkPrefixLength = 28
		if err := lease.Close(); !errors.Is(err, ErrAddressChanged) || fake.deleted != 0 {
			t.Fatalf("changed Windows address was incorrectly deleted: %v", err)
		}
	})
	t.Run("foreign_luid_change", func(t *testing.T) {
		fake := &fakeAddressAPI{}
		lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24"))
		if err != nil {
			t.Fatal(err)
		}
		fake.existing.InterfaceLuid = 45
		if err := lease.Close(); !errors.Is(err, ErrAddressChanged) || fake.deleted != 0 {
			t.Fatalf("foreign LUID was incorrectly deleted: %v", err)
		}
	})
	t.Run("missing_after_adapter_reset", func(t *testing.T) {
		fake := &fakeAddressAPI{getErr: windows.ERROR_NOT_FOUND}
		lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24"))
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil || fake.deleted != 0 {
			t.Fatalf("absent address not handled safely: %v", err)
		}
	})
	t.Run("failed_cleanup_stays_failed", func(t *testing.T) {
		fake := &fakeAddressAPI{deleteErr: syscall.Errno(5)}
		lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24"))
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); !errors.Is(err, syscall.Errno(5)) {
			t.Fatalf("unsafe cleanup failure hidden: %v", err)
		}
		if err := lease.Close(); !errors.Is(err, syscall.Errno(5)) {
			t.Fatalf("unsafe cleanup should stay failed: %v", err)
		}
	})
	t.Run("existing_ip_must_not_be_adopted", func(t *testing.T) {
		fake := &fakeAddressAPI{createErr: syscall.Errno(183)}
		if lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24")); err == nil || lease != nil || fake.deleted != 0 {
			t.Fatalf("another manager's address was incorrectly adopted: %v", err)
		}
	})
}

func TestWindowsIPHelperSymbolsAvailableWithoutAdministrator(t *testing.T) {
	// Resolve all four system DLL entrypoints without installing an
	// adapter, modifying any network state, or requiring elevation.
	if _, err := newIPAddressAPI(); err != nil {
		t.Fatalf("Windows unicast address APIs unavailable: %v", err)
	}
}

func TestWindowsAddressRemovedAdapterCleanup(t *testing.T) {
	fake := &fakeAddressAPI{getErr: windows.ERROR_FILE_NOT_FOUND}
	lease, err := assignAddress(fake, 44, netip.MustParsePrefix("10.77.0.26/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil || fake.deleted != 0 {
		t.Fatalf("removed original Wintun adapter should need no address cleanup: %v", err)
	}
}
