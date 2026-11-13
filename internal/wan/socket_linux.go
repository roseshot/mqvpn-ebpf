//go:build linux

package wan

import (
	"context"
	"fmt"
	"net"
	"strconv"
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
		cfg.Control = bindDeviceControl(interfaceName)
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
