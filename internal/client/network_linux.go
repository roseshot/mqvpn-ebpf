//go:build linux

package client

import (
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

// openClientNetworkSession is the single network-resource setup path for
// QUIC and TCP fallback. The calling session already owns the route guard
// and closes it *after* this device: DNS -> TCX -> TUN -> guarded routes.
// Setup failures close partially initialized resources in the same order.
func openClientNetworkSession(
	ctx context.Context,
	guard routeGuard,
	config tcpOptions,
	address string,
	budget mtu.Result,
	routes []netip.Prefix,
	dns []netip.Addr,
	logger *slog.Logger,
) (*managedPumpDevice, error) {
	logger = logging.Ensure(logger).With("subsystem", "network")
	device, err := tun.OpenClient(config.tunName, address, budget.TUNMTU, vpnwire.DynamicAddressRequested(config.tunAddress))
	if err != nil {
		return nil, classifyClientCleanup(err)
	}
	if err := guard.Install(config.tunName, routes); err != nil {
		return nil, classifyClientCleanup(errors.Join(fmt.Errorf("install authenticated routes: %w", err), device.Close()))
	}
	if len(routes) != 0 {
		logger.InfoContext(ctx, "authenticated VPN routes installed", "routes", routepush.Encode(routes))
	}

	tc, err := attachConfiguredTC(ctx, config.tunName, config.tcConfig, budget.TUNMTU, logger)
	if err != nil {
		return nil, classifyClientCleanup(errors.Join(fmt.Errorf("attach TUN TC eBPF: %w", err), device.Close()))
	}
	lease, err := dnspush.Apply(config.tunName, dns)
	if err != nil {
		tcErr := reportAndCloseTC(ctx, tc, logger)
		closeErr := device.Close()
		combined := errors.Join(fmt.Errorf("apply authenticated DNS: %w", err), tcErr, closeErr)
		if tcErr != nil {
			combined = errors.Join(combined, errUnsafeReconnect)
		}
		return nil, classifyClientCleanup(combined)
	}
	if lease != nil {
		logger.InfoContext(ctx, "authenticated DNS installed on TUN", "tun", config.tunName, "servers", dnspush.Encode(dns))
	}
	return newManagedPumpDevice(ctx, device, tc, lease, logger), nil
}

// Incomplete netlink/DNS cleanup is a fatal reconnect condition. Ordinary
// transport and configuration errors remain retryable by the supervisor.
func classifyClientCleanup(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, tun.ErrCleanup) || errors.Is(err, dnspush.ErrCleanup) {
		return errors.Join(err, errUnsafeReconnect)
	}
	return err
}
