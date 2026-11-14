//go:build linux

package tun

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
)

type ifreq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [22]byte
}

// Open creates a Linux L3 TUN if missing, or attaches to the existing TUN.
// It assigns the explicitly requested IP/CIDR and MTU, then brings the
// device UP. Linux may create its standard connected and local address routes
// when the address is assigned. The daemon does not explicitly write routes,
// ip rules, VRFs, namespace changes, firewall or multicast routing.
// New nonpersistent TUNs exist while their file descriptor remains open.
func Open(name, cidr string, mtu int) (*os.File, error) {
	return open(name, cidr, mtu, false)
}

// OpenRouted uses a /32 or /128 local TUN address and a peer subnet route.
// Pool endpoints can then use the network/broadcast-numbered addresses as
// unicast destinations. Existing static configurations still use Open.
func OpenRouted(name, cidr string, mtu int) (*os.File, error) {
	return open(name, cidr, mtu, true)
}

func open(name, cidr string, mtu int, routed bool) (*os.File, error) {
	if err := Validate(name, cidr, mtu, 0); err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (requires TUN access and CAP_NET_ADMIN)", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("create/attach TUN %q: %w (requires CAP_NET_ADMIN and a TUN, not TAP)", name, errno)
	}
	setup := setupInterface
	if routed {
		setup = setupRoutedInterface
	}
	if err := setup(name, cidr, mtu, systemLinkOps{}); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("configure TUN %q: %w", name, err)
	}
	return f, nil
}
