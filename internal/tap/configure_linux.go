//go:build linux

package tap

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const tunSetPersist = 0x400454cb // TUNSETPERSIST

// Persist makes the TAP survive closing all file descriptors. Removing the
// interface is an explicit administrative operation: ip link delete dev <name>.
func Persist(f *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetPersist), 1)
	if errno != 0 { return fmt.Errorf("TUNSETPERSIST: %w", errno) }
	return nil
}

// Configure creates/attaches to a persistent TAP and assigns its own L3
// address and MTU. This is routed-over-Ethernet (no Linux Bridge required).
// Existing bridge-slave TAPs are rejected: IP belongs on a bridge instead.
func Configure(name, cidr string, mtu, maxFrame int) error {
	if err := validateName(name); err != nil { return err }
	if cidr == "" { return errors.New("--tunnel-ip CIDR is required (e.g. 10.77.0.1/30)") }
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
		return fmt.Errorf("invalid tunnel CIDR %q", cidr)
	}
	if mtu < 576 || mtu > 65521 { return fmt.Errorf("invalid tunnel MTU %d (576..65521)", mtu) }
	if prefix.Addr().Is6() && mtu < 1280 {
		return fmt.Errorf("IPv6 tunnel requires MTU >= 1280 (requested %d); check QUIC underlay PMTU", mtu)
	}
	if maxFrame < mtu+14 {
		return fmt.Errorf("--max-frame %d cannot carry --tunnel-mtu %d plus Ethernet header (14 bytes)", maxFrame, mtu)
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/master"); err == nil {
		return fmt.Errorf("tunnel TAP %q is enslaved to a bridge; use a standalone TAP to assign --tunnel-ip", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check TAP bridge master: %w", err)
	}
	f, err := Open(name)
	if err != nil { return err }
	defer f.Close()
	if err := Persist(f); err != nil { return err }

	// Pass arguments directly, never via shell. iproute2 is required.
	if err := ip("link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil { return err }
	family := "-4"
	if prefix.Addr().Is6() { family = "-6" }
	if err := ip(family, "address", "replace", cidr, "dev", name); err != nil { return err }
	if err := ip("link", "set", "dev", name, "up"); err != nil { return err }
	return nil
}

func ip(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("ip %v failed: %w: %s", args, err, out) }
	return nil
}
