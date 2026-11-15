//go:build !linux

package client

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

type unavailablePlatform struct{}

var _ networkPlatform = unavailablePlatform{}

func defaultClientPlatform() networkPlatform { return unavailablePlatform{} }

func clientPlatformPreflight() error {
	return fmt.Errorf("%w; Windows requires Wintun plus native route/DNS protection, macOS requires a Packet Tunnel extension, and Android requires VpnService", errNativeClientUnavailable)
}

func (unavailablePlatform) ListenUDP(context.Context, string, string, *net.UDPAddr) (*net.UDPConn, net.IP, error) {
	return nil, nil, errNativeClientUnavailable
}

func (unavailablePlatform) ResolveSource(string, string, *net.UDPAddr) (net.IP, error) {
	return nil, errNativeClientUnavailable
}

func (unavailablePlatform) DialTCP(context.Context, string, string, *net.TCPAddr) (net.Conn, net.IP, error) {
	return nil, nil, errNativeClientUnavailable
}

func (unavailablePlatform) SourceUnderlay(net.IP, string) (mtu.Underlay, error) {
	return mtu.Underlay{}, errNativeClientUnavailable
}

func (unavailablePlatform) ProtectServer(net.IP, net.IP, string, string, []netip.Prefix, bool) (routeGuard, error) {
	return nil, errNativeClientUnavailable
}

func (unavailablePlatform) OpenNetworkSession(context.Context, routeGuard, tcpOptions, string, mtu.Result, []netip.Prefix, []netip.Addr, *slog.Logger) (io.ReadWriteCloser, error) {
	return nil, errNativeClientUnavailable
}

// classifyClientCleanup is unreachable while unsupported platforms fail in
// Run preflight. A future native adapter must classify unsafe partial
// route, DNS and packet-device cleanup as errUnsafeReconnect before enabling
// real connections, matching the Linux implementation.
func classifyClientCleanup(err error) error { return err }
