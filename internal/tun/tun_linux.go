//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	ifNameSize   = 16
	tunSetIFF    = 0x400454ca
	tunPersist   = 0x400454cb
	iffTUN       = 0x0001
	iffNoPI      = 0x1000
)

// Linux ifreq is 40 bytes on the supported linux/amd64 target.
type ifreq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [22]byte
}

// Open opens a single L3 TUN queue (IFF_TUN | IFF_NO_PI).
// The buffer contains an IP packet, never an Ethernet header.
func Open(name string) (*os.File, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil { return nil, fmt.Errorf("open /dev/net/tun: %w", err) }
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %w (existing device may be TAP, not TUN)", name, errno)
	}
	return f, nil
}

func validateName(name string) error {
	if name == "" || len(name) >= ifNameSize {
		return errors.New("TUN name must be 1..15 ASCII characters")
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("invalid TUN name %q", name)
		}
	}
	return nil
}

// Configure is called once on startup. A persistent TUN survives process
// termination. The administrator is responsible for deleting it if needed.
// The --tunnel-ip prefix adds a normal connected route in the main table,
// not an XFRM policy or packet-mark rule.
func Configure(name, cidr string, mtu, maxFrame int) error {
	if err := Validate(name, cidr, mtu, maxFrame); err != nil { return err }
	if _, err := os.Stat("/sys/class/net/" + name + "/master"); err == nil {
		return fmt.Errorf("TUN %s must not be a Linux bridge slave", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect TUN master: %w", err)
	}
	f, err := Open(name)
	if err != nil { return err }
	defer f.Close()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunPersist), 1)
	if errno != 0 { return fmt.Errorf("TUNSETPERSIST: %w", errno) }
	p, _ := netip.ParsePrefix(cidr)
	if err := runIP("link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil { return err }
	family := "-4"
	if p.Addr().Is6() { family = "-6" }
	if err := runIP(family, "address", "replace", cidr, "dev", name); err != nil { return err }
	return runIP("link", "set", "dev", name, "up")
}

func Validate(name, cidr string, mtu, maxFrame int) error {
	if err := validateName(name); err != nil { return err }
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.IsValid() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
		return fmt.Errorf("invalid --tunnel-ip CIDR %q", cidr)
	}
	if mtu < 576 || mtu > 65521 {
		return fmt.Errorf("--tunnel-mtu must be 576..65521, got %d", mtu)
	}
	if p.Addr().Is6() && mtu < 1280 {
		return errors.New("IPv6 tunnel MTU must be >=1280; check encapsulation PMTU")
	}
	if mtu+14 > maxFrame {
		return fmt.Errorf("IP MTU %d + Ethernet header exceeds --max-frame %d", mtu, maxFrame)
	}
	return nil
}

func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil { return fmt.Errorf("ip %v: %w: %s", args, err, out) }
	return nil
}
