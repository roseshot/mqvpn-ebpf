//go:build !linux

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
)

// The Client binary can cross-compile without importing Linux netlink or
// eBPF. A native platform MUST provide TUN, route protection, DNS rollback,
// and per-socket underlay exclusion before it may start a VPN session.
var errNativeClientUnavailable = errors.New("native VPN network session is not implemented for this platform")

type unavailableClientPlatform struct{}

var _ clientPlatform = unavailableClientPlatform{}

func defaultClientPlatform() clientPlatform { return unavailableClientPlatform{} }

func clientPlatformPreflight() error {
	return fmt.Errorf("%w; Windows requires Wintun plus native route/DNS protection, macOS requires a Packet Tunnel extension, and Android requires VpnService", errNativeClientUnavailable)
}

func (unavailableClientPlatform) ListenUDP(context.Context, string, string, *net.UDPAddr) (*net.UDPConn, net.IP, error) {
	return nil, nil, errNativeClientUnavailable
}

func (unavailableClientPlatform) ResolveSource(string, string, *net.UDPAddr) (net.IP, error) {
	return nil, errNativeClientUnavailable
}

func (unavailableClientPlatform) DialTCP(context.Context, string, string, *net.TCPAddr) (net.Conn, net.IP, error) {
	return nil, nil, errNativeClientUnavailable
}

func (unavailableClientPlatform) SourceUnderlay(net.IP, string) (mtu.Underlay, error) {
	return mtu.Underlay{}, errNativeClientUnavailable
}

func (unavailableClientPlatform) ProtectServer(net.IP, net.IP, string, string, []netip.Prefix, bool) (clientRouteGuard, error) {
	return nil, errNativeClientUnavailable
}

func (unavailableClientPlatform) OpenNetworkSession(context.Context, clientRouteGuard, clientTCPOptions, string, mtu.Result, []netip.Prefix, []netip.Addr, *slog.Logger) (io.ReadWriteCloser, error) {
	return nil, errNativeClientUnavailable
}

// classifyClientCleanup is unreachable while unsupported platforms fail in
// RunClient preflight. A future native adapter must classify unsafe partial
// route, DNS and packet-device cleanup as errUnsafeReconnect before enabling
// real connections, matching the Linux implementation.
func classifyClientCleanup(err error) error { return err }
