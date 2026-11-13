//go:build linux

package tap

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	ifNameSize = 16
	tunSetIFF = 0x400454ca
	iffTAP   = 0x0002
	iffNoPI  = 0x1000
)

// The Linux ifreq union is 24 bytes on the supported amd64 Linux target.
type ifreq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [22]byte
}

// Open attaches to a TAP device or creates it. Pre-create a persistent TAP
// with "ip tuntap add dev mq0 mode tap" if it must survive process restarts.
// Requires CAP_NET_ADMIN or equivalent permissions.
func Open(name string) (*os.File, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTAP | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %q: %w", name, errno)
	}
	return f, nil
}

func validateName(name string) error {
	if name == "" || len(name) >= ifNameSize {
		return errors.New("TAP name must contain 1..15 ASCII characters")
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return fmt.Errorf("invalid TAP name %q", name)
		}
	}
	return nil
}
