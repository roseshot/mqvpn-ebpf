package client

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
)

// routeGuard owns the protected physical path to the VPN Server as
// well as any authenticated routes installed for this session. Closing it
// must restore only session-owned state; cleanup failures stop reconnect.
type routeGuard interface {
	Install(deviceName string, routes []netip.Prefix) error
	Close() error
}

// networkPlatform is the narrow operating-system boundary of the Client.
// Transport negotiation, TLS identity, L3 packet processing and reconnect
// stay in the Client Core. The platform is responsible for source-bound
// sockets and an isolated, reversible VPN network session.
//
// The Linux implementation preserves SO_BINDTODEVICE, rtnetlink, TUN,
// resolver and optional TCX behavior. Native Windows/macOS/Android adapters
// are not implemented yet. In particular an Android implementation must
// protect *every* underlay socket before connecting to avoid VPN loops,
// including any sockets opened inside the MPQUIC multi-socket manager.
type networkPlatform interface {
	ListenUDP(ctx context.Context, sourceIP, interfaceName string, remote *net.UDPAddr) (*net.UDPConn, net.IP, error)
	ResolveSource(sourceIP, interfaceName string, remote *net.UDPAddr) (net.IP, error)
	DialTCP(ctx context.Context, sourceIP, interfaceName string, remote *net.TCPAddr) (net.Conn, net.IP, error)
	SourceUnderlay(sourceIP net.IP, interfaceName string) (mtu.Underlay, error)
	ProtectServer(remoteIP, sourceIP net.IP, interfaceName, deviceName string, routes []netip.Prefix, multipleWAN bool) (routeGuard, error)
	OpenNetworkSession(ctx context.Context, guard routeGuard, config tcpOptions, address string, budget mtu.Result, routes []netip.Prefix, dns []netip.Addr, logger *slog.Logger) (io.ReadWriteCloser, error)
}

// platformForClient preserves the Linux default for callers that construct
// session options directly in tests. A future native host will supply its
// own concrete platform instead of changing the protocol core.
func platformForClient(platform networkPlatform) networkPlatform {
	if platform != nil {
		return platform
	}
	return defaultClientPlatform()
}
