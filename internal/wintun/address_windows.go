//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AddressLease owns exactly one IP Helper unicast address added to the
// caller-created Wintun interface. It does not configure DNS, route selection,
// endpoint protection or a full VPN session.
type AddressLease struct {
	api  addressAPI
	row  windows.MibUnicastIpAddressRow
	once sync.Once
	err  error
}

var ErrAddressChanged = errors.New("Wintun address was changed by another manager; refusing to delete it")

type addressAPI interface {
	Initialize(*windows.MibUnicastIpAddressRow)
	Create(*windows.MibUnicastIpAddressRow) error
	Get(*windows.MibUnicastIpAddressRow) error
	Delete(*windows.MibUnicastIpAddressRow) error
}

type ipHelperAddressAPI struct {
	initialize *windows.LazyProc
	create     *windows.LazyProc
	get        *windows.LazyProc
	delete     *windows.LazyProc
}

func newIPAddressAPI() (*ipHelperAddressAPI, error) {
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	a := &ipHelperAddressAPI{
		initialize: dll.NewProc("InitializeUnicastIpAddressEntry"),
		create:     dll.NewProc("CreateUnicastIpAddressEntry"),
		get:        dll.NewProc("GetUnicastIpAddressEntry"),
		delete:     dll.NewProc("DeleteUnicastIpAddressEntry"),
	}
	for _, p := range []*windows.LazyProc{a.initialize, a.create, a.get, a.delete} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("Windows IP Helper API is unavailable: %w", err)
		}
	}
	return a, nil
}

func (a *ipHelperAddressAPI) Initialize(row *windows.MibUnicastIpAddressRow) {
	a.initialize.Call(uintptr(unsafe.Pointer(row)))
}

func ipHelperCall(p *windows.LazyProc, row *windows.MibUnicastIpAddressRow) error {
	code, _, _ := p.Call(uintptr(unsafe.Pointer(row)))
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func (a *ipHelperAddressAPI) Create(row *windows.MibUnicastIpAddressRow) error {
	return ipHelperCall(a.create, row)
}
func (a *ipHelperAddressAPI) Get(row *windows.MibUnicastIpAddressRow) error {
	return ipHelperCall(a.get, row)
}
func (a *ipHelperAddressAPI) Delete(row *windows.MibUnicastIpAddressRow) error {
	return ipHelperCall(a.delete, row)
}

func validateTunnelPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return errors.New("Wintun address must be a valid host CIDR")
	}
	ip := prefix.Addr()
	if ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() ||
		(ip.Is4() && ip == netip.MustParseAddr("255.255.255.255")) {
		return fmt.Errorf("invalid Wintun host address %q", prefix)
	}
	if prefix.Bits() < 1 {
		return fmt.Errorf("Wintun host address must use a nonzero prefix length: %s", prefix)
	}
	return nil
}

// addressRow constructs the exact SOCKADDR_INET union used by IP Helper.
// Setting the host IP rather than prefix.Masked() is deliberate: TUN
// addresses must not be converted into network addresses.
func addressRow(api addressAPI, luid uint64, prefix netip.Prefix) (windows.MibUnicastIpAddressRow, error) {
	if luid == 0 {
		return windows.MibUnicastIpAddressRow{}, errors.New("missing Wintun interface LUID")
	}
	if err := validateTunnelPrefix(prefix); err != nil {
		return windows.MibUnicastIpAddressRow{}, err
	}
	var row windows.MibUnicastIpAddressRow
	api.Initialize(&row)
	row.InterfaceLuid = luid
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	ip := prefix.Addr()
	if ip.Is4() {
		v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
		v4.Family = windows.AF_INET
		v4.Addr = ip.As4()
	} else {
		v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&row.Address))
		v6.Family = windows.AF_INET6
		v6.Addr = ip.As16()
	}
	return row, nil
}

func assignAddress(api addressAPI, luid uint64, prefix netip.Prefix) (*AddressLease, error) {
	row, err := addressRow(api, luid, prefix)
	if err != nil {
		return nil, err
	}
	if err := api.Create(&row); err != nil {
		// ERROR_OBJECT_ALREADY_EXISTS and all other failures remain errors:
		// never adopt or delete an address that we did not create.
		return nil, fmt.Errorf("create Windows Wintun address %s: %w", prefix, err)
	}
	return &AddressLease{api: api, row: row}, nil
}

// AssignAddress installs one session-owned host address using native IP
// Helper APIs. It cannot be called on an adapter already being closed.
// Call AddressLease.Close before closing the Wintun Device.
func (d *Device) AssignAddress(prefix netip.Prefix) (*AddressLease, error) {
	if err := validateTunnelPrefix(prefix); err != nil {
		return nil, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return nil, ErrClosed
	}
	var luid uint64
	d.api.adapterLUID.Call(d.adapter, uintptr(unsafe.Pointer(&luid)))
	if luid == 0 {
		return nil, errors.New("Windows Wintun adapter has no LUID")
	}
	api, err := newIPAddressAPI()
	if err != nil {
		return nil, err
	}
	return assignAddress(api, luid, prefix)
}

// Close deletes only the address originally installed by this lease.
// It checks that the prefix and interface are unchanged, and intentionally
// rejects external replacement instead of modifying someone else's state.
func (lease *AddressLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		check := lease.row
		if err := lease.api.Get(&check); err != nil {
			if errors.Is(err, windows.ERROR_NOT_FOUND) {
				return // Adapter was removed; the owned address is already gone.
			}
			lease.err = fmt.Errorf("inspect Wintun address before cleanup: %w", err)
			return
		}
		if check.InterfaceLuid != lease.row.InterfaceLuid ||
			check.OnLinkPrefixLength != lease.row.OnLinkPrefixLength ||
			!sameSockaddrIP(check.Address, lease.row.Address) {
			lease.err = ErrAddressChanged
			return
		}
		if err := lease.api.Delete(&lease.row); err != nil &&
			!errors.Is(err, windows.ERROR_NOT_FOUND) {
			lease.err = fmt.Errorf("remove session-owned Wintun address: %w", err)
		}
	})
	return lease.err
}

func sameSockaddrIP(a, b windows.RawSockaddrInet6) bool {
	if a.Family != b.Family {
		return false
	}
	switch a.Family {
	case windows.AF_INET:
		return (*windows.RawSockaddrInet4)(unsafe.Pointer(&a)).Addr ==
			(*windows.RawSockaddrInet4)(unsafe.Pointer(&b)).Addr
	case windows.AF_INET6:
		return a.Addr == b.Addr
	default:
		return false
	}
}
