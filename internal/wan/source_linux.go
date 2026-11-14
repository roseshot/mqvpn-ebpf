//go:build linux

package wan

import (
	"fmt"
	"net"
)

// ResolveSource chooses exactly one unicast address on an explicit device
// or follows the kernel's route to the remote peer when no WAN selector is
// provided. This does not install or modify routes.
func ResolveSource(sourceIP, interfaceName string, peer *net.UDPAddr) (net.IP, error) {
	if peer == nil || peer.IP == nil {
		return nil, fmt.Errorf("resolved peer IP is required")
	}
	v4 := peer.IP.To4() != nil
	var explicit net.IP
	if sourceIP != "" {
		explicit = net.ParseIP(sourceIP)
		if explicit == nil || explicit.IsUnspecified() || explicit.IsMulticast() {
			return nil, fmt.Errorf("invalid WAN source IP %q", sourceIP)
		}
		if (explicit.To4() != nil) != v4 {
			return nil, fmt.Errorf("WAN source %s and gateway %s use different IP families", explicit, peer.IP)
		}
	}
	if interfaceName == "" {
		if explicit != nil {
			return explicit, nil
		}
		// Connected UDP sockets perform a route/source lookup without sending
		// a packet. Unlike a static default-route guess, this respects policy
		// routes and a pinned destination IP chosen by the client.
		probe, err := net.DialUDP("udp", nil, peer)
		if err != nil {
			return nil, fmt.Errorf("resolve WAN source via kernel route to %s: %w", peer.IP, err)
		}
		defer probe.Close()
		chosen := probe.LocalAddr().(*net.UDPAddr).IP
		if chosen == nil || chosen.IsUnspecified() || chosen.IsMulticast() {
			return nil, fmt.Errorf("kernel did not select a unicast WAN source for %s", peer.IP)
		}
		return chosen, nil
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("unknown WAN interface %q: %w", interfaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses of %s: %w", interfaceName, err)
	}
	var matches []net.IP
	for _, addr := range addrs {
		cidr, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := cidr.IP
		if (ip.To4() != nil) != v4 || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		if explicit != nil {
			if ip.Equal(explicit) {
				return explicit, nil
			}
			continue
		}
		if ip.IsLoopback() != peer.IP.IsLoopback() {
			continue
		}
		matches = append(matches, ip)
	}
	if explicit != nil {
		return nil, fmt.Errorf("source IP %s is not assigned to interface %s", explicit, interfaceName)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("interface %s has %d usable %s addresses; specify --source-ip", interfaceName, len(matches), networkName(v4))
	}
	return matches[0], nil
}

func networkName(v4 bool) string {
	if v4 {
		return "IPv4"
	}
	return "IPv6"
}
