//go:build linux

package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

// linuxClientPlatform retains the existing production path. It does not
// acquire any cross-node state or introduce Linux services into Client Core.
type linuxClientPlatform struct{}

var _ clientPlatform = linuxClientPlatform{}
var _ clientRouteGuard = (*routepush.Guard)(nil)

func defaultClientPlatform() clientPlatform {
	return linuxClientPlatform{}
}

func (linuxClientPlatform) ListenUDP(ctx context.Context, sourceIP, interfaceName string, remote *net.UDPAddr) (*net.UDPConn, net.IP, error) {
	return wan.Listen(ctx, sourceIP, interfaceName, remote)
}

func (linuxClientPlatform) ResolveSource(sourceIP, interfaceName string, remote *net.UDPAddr) (net.IP, error) {
	return wan.ResolveSource(sourceIP, interfaceName, remote)
}

func (linuxClientPlatform) DialTCP(ctx context.Context, sourceIP, interfaceName string, remote *net.TCPAddr) (net.Conn, net.IP, error) {
	return wan.DialTCP(ctx, sourceIP, interfaceName, remote)
}

func (linuxClientPlatform) SourceUnderlay(sourceIP net.IP, interfaceName string) (mtu.Underlay, error) {
	return wan.SourceUnderlay(sourceIP, interfaceName)
}

func (linuxClientPlatform) ProtectServer(remoteIP, sourceIP net.IP, interfaceName, deviceName string, routes []netip.Prefix, multipleWAN bool) (clientRouteGuard, error) {
	return routepush.ProtectServer(remoteIP, sourceIP, interfaceName, deviceName, routes, multipleWAN)
}

func (linuxClientPlatform) OpenNetworkSession(ctx context.Context, guard clientRouteGuard, config clientTCPOptions, address string, budget mtu.Result, routes []netip.Prefix, dns []netip.Addr, logger *slog.Logger) (io.ReadWriteCloser, error) {
	return openClientNetworkSession(ctx, guard, config, address, budget, routes, dns, logger)
}
