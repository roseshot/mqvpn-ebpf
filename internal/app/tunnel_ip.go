package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
)

const tunnelAddressHeader = "Mqvpn-Tunnel-Address"

func dynamicAddressRequested(address string) bool {
	return address == "" || strings.EqualFold(address, "auto")
}

func wantsTunnelIP(header string) (bool, error) {
	if header == "" {
		return false, nil
	}
	if header != "auto" {
		return false, errors.New("invalid Mqvpn-Tunnel-Address request")
	}
	return true, nil
}

// Delay IP validation until the authenticated Server has supplied a lease.
// Still validate the interface name and explicit MTU/frame before dialing.
func validateClientAddressRequest(name, address string, mtuValue, frame int) error {
	if dynamicAddressRequested(address) {
		address = "192.0.2.2/24"
	}
	return mtu.ValidateRequest(name, address, mtuValue, frame)
}

// The client never trusts a non-requested assignment or an absent reply.
// The server's TLS SNI and mTLS identity were verified before this call.
func resolveClientTunnelAddress(requested, response string) (string, error) {
	if !dynamicAddressRequested(requested) {
		if response != "" {
			return "", errors.New("unexpected tunnel IP assignment for static client")
		}
		return requested, nil
	}
	if response == "" {
		return "", errors.New("server did not assign a tunnel IP (configure tunnel_pool and dynamic_tunnel_ip)")
	}
	prefix, err := netip.ParsePrefix(response)
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() ||
		prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() ||
		prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() ||
		prefix.Addr() == netip.MustParseAddr("255.255.255.255") {
		return "", fmt.Errorf("invalid assigned tunnel IP %q", response)
	}
	return prefix.String(), nil
}
