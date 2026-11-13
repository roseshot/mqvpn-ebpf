//go:build linux

package wan

import (
	"fmt"
	"syscall"
)

// bindDeviceControl is shared by the UDP/QUIC and TCP/TLS underlays.
// Uses Linux SO_BINDTODEVICE directly; never launches ip(8), route(8),
// a shell, or any other subprocess.
func bindDeviceControl(iface string) func(string, string, syscall.RawConn) error {
	return func(_ string, _ string, raw syscall.RawConn) error {
		var setErr error
		if err := raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return fmt.Errorf("bind WAN interface %q: %w", iface, err)
		}
		if setErr != nil {
			return fmt.Errorf("SO_BINDTODEVICE %q: %w", iface, setErr)
		}
		return nil
	}
}
