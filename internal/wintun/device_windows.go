//go:build windows

// Package wintun provides a native Windows L3 packet device using the
// official Wintun DLL, without embedding or redistributing the driver.
//
// This is a packet I/O component, NOT a complete mqvpn Windows network
// session: adapter IP/MTU, safe underlay routes, DNS and cleanup are separate
// OS-owned operations that must succeed before any VPN traffic is enabled.
package wintun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	ringCapacity	= 0x400000 // 4 MiB, a power of two and within Wintun's limits
	maxPacket	= 0xffff

	errorNoMoreItems	= syscall.Errno(259)
	errorHandleEOF	= syscall.Errno(38)
	waitObject0	= 0
	waitTimeout	= 0x102
)

var ErrClosed = errors.New("Wintun packet device is closed")

// Device implements io.ReadWriteCloser for L3 IPv4/IPv6 packet IO.
// It creates a private adapter and removes only that adapter on Close.
// One packet is consumed on each Read; a too-small buffer drops that packet
// and returns io.ErrShortBuffer instead of forwarding a partial IP packet.
type Device struct {
	api		*api
	adapter		uintptr
	session		uintptr
	readEvent	syscall.Handle
	closed		atomic.Bool
	mu		sync.RWMutex
	closeOnce	sync.Once
	closeError	error
}

type api struct {
	dll		*syscall.DLL
	create		*syscall.Proc
	close		*syscall.Proc
	start		*syscall.Proc
	end		*syscall.Proc
	readEvent	*syscall.Proc
	receive		*syscall.Proc
	release		*syscall.Proc
	allocate	*syscall.Proc
	send		*syscall.Proc
	adapterLUID	*syscall.Proc
}

// Open creates a Wintun adapter using wintun.dll next to this executable.
// Callers must provide the official, appropriately licensed and signed
// library themselves. No DLL from PATH or the current directory is used.
// Adapter creation ordinarily requires elevated Windows privileges.
func Open(name string) (*Device, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate mqvpn executable: %w", err)
	}
	return openLibrary(name, filepath.Join(filepath.Dir(executable), "wintun.dll"))
}

func validateName(name string) error {
	if name == "" || len(name) > 120 || strings.TrimSpace(name) != name ||
		strings.ContainsAny(name, "\x00/\\") {
		return fmt.Errorf("invalid Windows Wintun adapter name %q", name)
	}
	return nil
}

func openLibrary(name, dllPath string) (*Device, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	// Load an absolute path, never search working directories or PATH.
	if !filepath.IsAbs(dllPath) {
		return nil, errors.New("Wintun DLL path must be absolute")
	}
	lib, err := syscall.LoadDLL(dllPath)
	if err != nil {
		return nil, fmt.Errorf("load Wintun beside mqvpn-client executable: %w", err)
	}
	a := &api{dll: lib}
	for _, item := range []struct {
		name	string
		dst	**syscall.Proc
	}{
		{"WintunCreateAdapter", &a.create},
		{"WintunCloseAdapter", &a.close},
		{"WintunStartSession", &a.start},
		{"WintunEndSession", &a.end},
		{"WintunGetReadWaitEvent", &a.readEvent},
		{"WintunReceivePacket", &a.receive},
		{"WintunReleaseReceivePacket", &a.release},
		{"WintunAllocateSendPacket", &a.allocate},
		{"WintunSendPacket", &a.send},
		{"WintunGetAdapterLuid", &a.adapterLUID},
	} {
		*item.dst, err = lib.FindProc(item.name)
		if err != nil {
			_ = lib.Release()
			return nil, fmt.Errorf("Wintun DLL missing %s: %w", item.name, err)
		}
	}
	adapterName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		_ = lib.Release()
		return nil, err
	}
	tunnelType, _ := syscall.UTF16PtrFromString("mqvpn")
	adapter, _, callErr := a.create.Call(
		uintptr(unsafe.Pointer(adapterName)),
		uintptr(unsafe.Pointer(tunnelType)), 0,
	)
	runtime.KeepAlive(adapterName)
	runtime.KeepAlive(tunnelType)
	if adapter == 0 {
		_ = lib.Release()
		return nil, fmt.Errorf("create Wintun adapter %q: %w", name, callError(callErr))
	}
	session, _, callErr := a.start.Call(adapter, ringCapacity)
	if session == 0 {
		a.close.Call(adapter)
		_ = lib.Release()
		return nil, fmt.Errorf("start Wintun packet ring: %w", callError(callErr))
	}
	event, _, _ := a.readEvent.Call(session)
	if event == 0 {
		a.end.Call(session)
		a.close.Call(adapter)
		_ = lib.Release()
		return nil, errors.New("Wintun read event is unavailable")
	}
	return &Device{api: a, adapter: adapter, session: session, readEvent: syscall.Handle(event)}, nil
}

// LUID identifies this specific Wintun interface to native Windows route,
// DNS and IP-address configuration APIs. It is not a route itself.
func (d *Device) LUID() (uint64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return 0, ErrClosed
	}
	var luid uint64
	d.api.adapterLUID.Call(d.adapter, uintptr(unsafe.Pointer(&luid)))
	runtime.KeepAlive(&luid)
	return luid, nil
}

func (d *Device) Read(dst []byte) (int, error) {
	for {
		d.mu.RLock()
		if d.closed.Load() {
			d.mu.RUnlock()
			return 0, ErrClosed
		}
		var size uint32
		ptr, _, callErr := d.api.receive.Call(d.session, uintptr(unsafe.Pointer(&size)))
		if ptr != 0 {
			if size == 0 || size > maxPacket {
				d.api.release.Call(d.session, ptr)
				d.mu.RUnlock()
				return 0, fmt.Errorf("invalid Wintun incoming packet size %d", size)
			}
			if int(size) > len(dst) {
				d.api.release.Call(d.session, ptr)
				d.mu.RUnlock()
				return 0, io.ErrShortBuffer
			}
			n := copy(dst, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(size)))
			d.api.release.Call(d.session, ptr)
			d.mu.RUnlock()
			return n, nil
		}
		d.mu.RUnlock()
		if callErr != errorNoMoreItems {
			if callErr == errorHandleEOF || d.closed.Load() {
				return 0, ErrClosed
			}
			return 0, fmt.Errorf("read Wintun packet: %w", callError(callErr))
		}
		// Do not hold a lock while waiting: Close can terminate the ring
		// promptly. Check closed after waking; never close Wintun's event.
		wait, err := syscall.WaitForSingleObject(d.readEvent, 100)
		if d.closed.Load() {
			return 0, ErrClosed
		}
		if err != nil {
			return 0, fmt.Errorf("wait for Wintun packets: %w", err)
		}
		if wait != waitObject0 && wait != waitTimeout {
			return 0, fmt.Errorf("unexpected Wintun wait status %d", wait)
		}
	}
}

func (d *Device) Write(packet []byte) (int, error) {
	if len(packet) == 0 || len(packet) > maxPacket {
		return 0, fmt.Errorf("invalid Wintun outgoing IP packet size %d", len(packet))
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return 0, ErrClosed
	}
	ptr, _, callErr := d.api.allocate.Call(d.session, uintptr(uint32(len(packet))))
	if ptr == 0 {
		if callErr == errorHandleEOF {
			return 0, ErrClosed
		}
		return 0, fmt.Errorf("allocate Wintun outgoing packet: %w", callError(callErr))
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(packet)), packet)
	d.api.send.Call(d.session, ptr)
	return len(packet), nil
}

func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		// Wait for any active Wintun packet operation to finish before
		// closing the session, adapter, and DLL.
		d.mu.Lock()
		defer d.mu.Unlock()
		d.api.end.Call(d.session)
		d.api.close.Call(d.adapter) // removes the adapter created by Open
		d.closeError = d.api.dll.Release()
	})
	return d.closeError
}

func callError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return err
}

var _ io.ReadWriteCloser = (*Device)(nil)
