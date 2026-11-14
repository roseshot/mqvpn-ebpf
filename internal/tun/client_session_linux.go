//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
)

// ErrCleanup is returned when session-owned network state could not be
// restored. The reconnect supervisor must not run another attempt.
var ErrCleanup = errors.New("VPN TUN session cleanup failed")

type sessionLinkOps interface {
	ByName(string) (netlink.Link, error)
	ListAddrs(netlink.Link) ([]netlink.Addr, error)
	ReplaceAddr(netlink.Link, *netlink.Addr) error
	DeleteAddr(netlink.Link, *netlink.Addr) error
	SetMTU(netlink.Link, int) error
	SetUp(netlink.Link) error
	SetDown(netlink.Link) error
	DeleteLink(netlink.Link) error
}

type linkSnapshot struct {
	existed   bool
	index     int
	mtu       int
	up        bool
	addresses []netlink.Addr
}

func captureLinkState(name string, ops sessionLinkOps) (linkSnapshot, error) {
	link, err := ops.ByName(name)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) {
			return linkSnapshot{}, nil
		}
		return linkSnapshot{}, fmt.Errorf("inspect TUN %s before VPN session: %w", name, err)
	}
	addrs, err := ops.ListAddrs(link)
	if err != nil {
		return linkSnapshot{}, fmt.Errorf("snapshot TUN %s addresses: %w", name, err)
	}
	return linkSnapshot{existed: true, index: link.Attrs().Index, mtu: link.Attrs().MTU,
		up: link.Attrs().Flags&net.FlagUp != 0, addresses: addrs}, nil
}

type ClientDevice struct {
	*os.File
	mu           sync.Once
	closeErr     error
	name, cidr   string
	routed       bool
	before       linkSnapshot
	createdIndex int
	ops          sessionLinkOps
}

// OpenClient restores the previous TUN state when a Client session ends,
// including static or dynamic lease address, MTU and administrative UP flag.
// Newly created interfaces are removed; pre-existing interfaces are never
// deleted. No /etc/resolv.conf, DNS or unrelated system routes are changed.
func OpenClient(name, cidr string, mtu int, routed bool) (*ClientDevice, error) {
	if err := Validate(name, cidr, mtu, 0); err != nil {
		return nil, err
	}
	ops := systemLinkOps{}
	before, err := captureLinkState(name, ops)
	if err != nil {
		return nil, err
	}
	f, err := open(name, cidr, mtu, routed)
	if err != nil {
		if before.existed {
			if restoreErr := restoreClientLink(name, cidr, routed, before, 0, ops); restoreErr != nil {
				return nil, errors.Join(err, fmt.Errorf("%w: %v", ErrCleanup, restoreErr))
			}
		}
		return nil, err
	}
	link, err := ops.ByName(name)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: inspect configured TUN: %v", ErrCleanup, err)
	}
	return &ClientDevice{File: f, name: name, cidr: cidr, before: before,
		createdIndex: link.Attrs().Index, routed: routed, ops: ops}, nil
}

func (d *ClientDevice) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Do(func() {
		// Stop the packet pump before touching the address and routes.
		err := d.File.Close()
		if err != nil {
			err = fmt.Errorf("%w: close TUN descriptor: %v", ErrCleanup, err)
		}
		cleanupErr := restoreClientLink(d.name, d.cidr, d.routed, d.before, d.createdIndex, d.ops)
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: %v", ErrCleanup, cleanupErr))
		}
		d.closeErr = err
	})
	return d.closeErr
}

func addressMatches(a, b netlink.Addr) bool {
	if a.IPNet == nil || b.IPNet == nil || a.IPNet.String() != b.IPNet.String() {
		return false
	}
	if (a.Peer == nil) != (b.Peer == nil) {
		return false
	}
	if a.Peer != nil && a.Peer.String() != b.Peer.String() {
		return false
	}
	return true
}

func restoreClientLink(name, cidr string, _ bool, before linkSnapshot, createdIndex int, ops sessionLinkOps) error {
	link, err := ops.ByName(name)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if !before.existed && errors.As(err, &missing) {
			return nil
		}
		return fmt.Errorf("find TUN %s for restore: %w", name, err)
	}
	if before.existed {
		if link.Attrs().Index != before.index {
			return fmt.Errorf("TUN %s changed link identity; refusing to edit unrelated interface", name)
		}
	} else {
		if createdIndex != 0 && link.Attrs().Index != createdIndex {
			return fmt.Errorf("new TUN %s changed identity; refusing deletion", name)
		}
		// An ordinary nonpersistent TUN disappears on descriptor Close.
		// If a newly created TUN was made persistent, it still belongs to
		// this VPN session and must not survive disconnect.
		return ops.DeleteLink(link)
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	local := net.ParseIP(prefix.Addr().String())
	current, err := ops.ListAddrs(link)
	if err != nil {
		return fmt.Errorf("inspect TUN %s before restore: %w", name, err)
	}
	var originally []netlink.Addr
	for _, a := range before.addresses {
		if a.IPNet != nil && a.IPNet.IP.Equal(local) {
			originally = append(originally, a)
		}
	}
	var failure error
	for _, a := range current {
		if a.IPNet == nil || !a.IPNet.IP.Equal(local) {
			continue
		}
		keep := false
		for _, saved := range originally {
			if addressMatches(a, saved) {
				keep = true
				break
			}
		}
		if keep {
			continue
		}
		if err := ops.DeleteAddr(link, &a); err != nil {
			failure = errors.Join(failure, fmt.Errorf("remove session address %s: %w", a.IPNet, err))
		}
	}
	// Reconcile all addresses present before the session, not just the
	// current lease's local IP: AddrReplace might have replaced an
	// administrator address using another prefix on some kernels.
	for _, saved := range before.addresses {
		if saved.IPNet == nil {
			continue
		}
		found := false
		for _, a := range current {
			if addressMatches(a, saved) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		v := saved
		if err := ops.ReplaceAddr(link, &v); err != nil {
			failure = errors.Join(failure, fmt.Errorf("restore original address %s: %w", saved.IPNet, err))
		}
	}
	if link.Attrs().MTU != before.mtu {
		if err := ops.SetMTU(link, before.mtu); err != nil {
			failure = errors.Join(failure, fmt.Errorf("restore TUN MTU %d: %w", before.mtu, err))
		}
	}
	if before.up != (link.Attrs().Flags&net.FlagUp != 0) {
		if before.up {
			err = ops.SetUp(link)
		} else {
			err = ops.SetDown(link)
		}
		if err != nil {
			failure = errors.Join(failure, fmt.Errorf("restore TUN link state: %w", err))
		}
	}
	return failure
}
