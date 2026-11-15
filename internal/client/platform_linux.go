//go:build linux

package client

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

// linuxPlatform retains the existing production path. It does not
// acquire any cross-node state or introduce Linux services into Client Core.
type linuxPlatform struct{}

var _ networkPlatform = linuxPlatform{}
var _ routeGuard = (*routepush.Guard)(nil)

func defaultClientPlatform() networkPlatform {
	return linuxPlatform{}
}

func clientPlatformPreflight() error { return nil }

func (linuxPlatform) ListenUDP(ctx context.Context, sourceIP, interfaceName string, remote *net.UDPAddr) (*net.UDPConn, net.IP, error) {
	return wan.Listen(ctx, sourceIP, interfaceName, remote)
}

func (linuxPlatform) ResolveSource(sourceIP, interfaceName string, remote *net.UDPAddr) (net.IP, error) {
	return wan.ResolveSource(sourceIP, interfaceName, remote)
}

func (linuxPlatform) DialTCP(ctx context.Context, sourceIP, interfaceName string, remote *net.TCPAddr) (net.Conn, net.IP, error) {
	return wan.DialTCP(ctx, sourceIP, interfaceName, remote)
}

func (linuxPlatform) SourceUnderlay(sourceIP net.IP, interfaceName string) (mtu.Underlay, error) {
	return wan.SourceUnderlay(sourceIP, interfaceName)
}

func (linuxPlatform) ProtectServer(remoteIP, sourceIP net.IP, interfaceName, deviceName string, routes []netip.Prefix, multipleWAN bool) (routeGuard, error) {
	return routepush.ProtectServer(remoteIP, sourceIP, interfaceName, deviceName, routes, multipleWAN)
}

func (linuxPlatform) OpenNetworkSession(ctx context.Context, guard routeGuard, config tcpOptions, address string, budget mtu.Result, routes []netip.Prefix, dns []netip.Addr, logger *slog.Logger) (io.ReadWriteCloser, error) {
	return openClientNetworkSession(ctx, guard, config, address, budget, routes, dns, logger)
}
