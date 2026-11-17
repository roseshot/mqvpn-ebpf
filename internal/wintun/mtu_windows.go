//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MTULease owns a change to one Windows IP interface address family.
// A lease must be closed before its Wintun Device is closed. It does not
// install routes, DNS, or a complete VPN network session.
type MTULease struct {
	api      ipInterfaceAPI
	luid     uint64
	family   uint16
	previous uint32
	applied  uint32
	changed  bool

	once sync.Once
	err  error
}

// ErrMTUChanged means another manager modified the interface after mqvpn
// configured it. In that case cleanup must not overwrite the new value.
var ErrMTUChanged = errors.New("Wintun MTU was changed by another manager; refusing to restore it")

type ipInterfaceAPI interface {
	Get(*windows.MibIpInterfaceRow) error
	Set(*windows.MibIpInterfaceRow) error
}

type ipHelperInterfaceAPI struct {
	get *windows.LazyProc
	set *windows.LazyProc
}

func newIPInterfaceAPI() (*ipHelperInterfaceAPI, error) {
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	a := &ipHelperInterfaceAPI{
		get: dll.NewProc("GetIpInterfaceEntry"),
		set: dll.NewProc("SetIpInterfaceEntry"),
	}
	for _, proc := range []*windows.LazyProc{a.get, a.set} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("Windows IP interface API is unavailable: %w", err)
		}
	}
	return a, nil
}

func interfaceMTUCall(proc *windows.LazyProc, row *windows.MibIpInterfaceRow) error {
	code, _, _ := proc.Call(uintptr(unsafe.Pointer(row)))
	runtime.KeepAlive(row)
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func (a *ipHelperInterfaceAPI) Get(row *windows.MibIpInterfaceRow) error {
	return interfaceMTUCall(a.get, row)
}

func (a *ipHelperInterfaceAPI) Set(row *windows.MibIpInterfaceRow) error {
	return interfaceMTUCall(a.set, row)
}

func validateInterfaceMTU(family uint16, mtu uint32) error {
	switch family {
	case windows.AF_INET:
		if mtu >= 576 && mtu <= 65535 {
			return nil
		}
	case windows.AF_INET6:
		if mtu >= 1280 && mtu <= 65535 {
			return nil
		}
	default:
		return fmt.Errorf("unsupported Windows IP address family %d", family)
	}
	return fmt.Errorf("invalid Wintun MTU %d for address family %d", mtu, family)
}

// setInterfaceMTU uses the native IP Helper API and preserves unrelated
// settings by modifying a freshly read interface row. If the current value
// already equals mtu, the returned lease does not claim ownership.
func setInterfaceMTU(api ipInterfaceAPI, luid uint64, family uint16, mtu uint32) (*MTULease, error) {
	if err := validateInterfaceMTU(family, mtu); err != nil {
		return nil, err
	}
	if luid == 0 {
		return nil, errors.New("missing Wintun interface LUID")
	}
	row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: luid}
	if err := api.Get(&row); err != nil {
		return nil, fmt.Errorf("inspect Wintun IP interface MTU: %w", err)
	}
	if row.Family != family || row.InterfaceLuid != luid || row.NlMtu == 0 {
		return nil, errors.New("Windows IP Helper returned an inconsistent Wintun interface")
	}
	lease := &MTULease{
		api: api, luid: luid, family: family,
		previous: row.NlMtu, applied: mtu,
	}
	if row.NlMtu == mtu {
		// Do not adopt an existing MTU setting or restore it on Close.
		return lease, nil
	}
	row.NlMtu = mtu
	// Windows documents that this field must be zero when setting IPv4.
	if family == windows.AF_INET {
		row.SitePrefixLength = 0
	}
	if err := api.Set(&row); err != nil {
		return nil, fmt.Errorf("configure Wintun MTU %d: %w", mtu, err)
	}
	lease.changed = true
	return lease, nil
}

// SetMTU configures an IPv4 (AF_INET) or IPv6 (AF_INET6) MTU on this
// Wintun adapter. Call once for each family needed by a future network
// session, and close every returned lease before closing the Device.
// No native VPN session is enabled by this primitive alone.
func (d *Device) SetMTU(family uint16, mtu uint32) (*MTULease, error) {
	if err := validateInterfaceMTU(family, mtu); err != nil {
		return nil, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return nil, ErrClosed
	}
	var luid uint64
	d.api.adapterLUID.Call(d.adapter, uintptr(unsafe.Pointer(&luid)))
	runtime.KeepAlive(&luid)
	if luid == 0 {
		return nil, errors.New("Windows Wintun adapter has no LUID")
	}
	api, err := newIPInterfaceAPI()
	if err != nil {
		return nil, err
	}
	return setInterfaceMTU(api, luid, family, mtu)
}

// Close restores only the original MTU changed by this lease. A missing
// adapter needs no restoration; an externally changed MTU is never
// overwritten. Cleanup failures are retained and returned on later calls.
func (lease *MTULease) Close() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		if !lease.changed {
			return
		}
		current := windows.MibIpInterfaceRow{Family: lease.family, InterfaceLuid: lease.luid}
		if err := lease.api.Get(&current); err != nil {
			if errors.Is(err, windows.ERROR_NOT_FOUND) ||
				errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return // The session-owned Wintun adapter was already removed.
			}
			lease.err = fmt.Errorf("inspect Wintun MTU before restoration: %w", err)
			return
		}
		if current.Family != lease.family || current.InterfaceLuid != lease.luid ||
			current.NlMtu != lease.applied {
			lease.err = ErrMTUChanged
			return
		}
		current.NlMtu = lease.previous
		if lease.family == windows.AF_INET {
			current.SitePrefixLength = 0
		}
		if err := lease.api.Set(&current); err != nil {
			lease.err = fmt.Errorf("restore session-owned Wintun MTU: %w", err)
		}
	})
	return lease.err
}
