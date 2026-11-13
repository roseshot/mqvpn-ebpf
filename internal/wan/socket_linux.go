//go:build linux

package wan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

// Listen binds the UDP socket to a source IP and, if supplied, a Linux interface.
// SO_BINDTODEVICE is set before bind / QUIC traffic, so a separate socket can
// remain on each WAN even if both gateways share the same destination address.
// A correct route through the chosen interface is still required.
func Listen(ctx context.Context, sourceIP, interfaceName string, peer *net.UDPAddr) (*net.UDPConn, net.IP, error) {
	ip, err := ResolveSource(sourceIP, interfaceName, peer)
	if err != nil {
		return nil, nil, err
	}
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	cfg := net.ListenConfig{}
	if interfaceName != "" {
		cfg.Control = func(network, address string, raw syscall.RawConn) error {
			var setErr error
			if err := raw.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
			}); err != nil {
				return err
			}
			if setErr != nil {
				return fmt.Errorf("SO_BINDTODEVICE %q: %w", interfaceName, setErr)
			}
			return nil
		}
	}
	pc, err := cfg.ListenPacket(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(0)))
	if err != nil {
		return nil, nil, fmt.Errorf("open UDP on source %s interface %q: %w", ip, interfaceName, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, nil, fmt.Errorf("unexpected packet socket %T", pc)
	}
	return conn, ip, nil
}

// ResolveSource chooses exactly one unicast address on the requested device,
// or validates that the explicitly supplied IP belongs to it. It never
// silently chooses an arbitrary interface if no source address is supplied.
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
		if explicit == nil {
			return nil, fmt.Errorf("specify --source-ip or --source-interface")
		}
		return explicit, nil
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
		if !ok { continue }
		ip := cidr.IP
		if (ip.To4() != nil) != v4 || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		if explicit != nil {
			if ip.Equal(explicit) { return explicit, nil }
			continue
		}
		if ip.IsLoopback() != peer.IP.IsLoopback() { continue }
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
	if v4 { return "IPv4" }
	return "IPv6"
}
