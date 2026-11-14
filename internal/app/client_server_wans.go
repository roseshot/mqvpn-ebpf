package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	quic "github.com/qoke/mp-quic-go"
)

// selectServerTargets binds each local WAN path to a remote Server address.
// The first path remains the authenticated handshake destination. Explicit
// per-WAN server_ip overrides an advertised address; in discovery mode the
// remaining Client WANs are paired with the Server's authenticated
// ADD_ADDRESS announcements in sequence, cycling when N > M.
func selectServerTargets(primary *net.UDPAddr, wans []clientWAN, advertised []quic.AdvertisedAddress, discover bool) ([]*net.UDPAddr, error) {
	if primary == nil || primary.IP == nil {
		return nil, errors.New("primary authenticated QUIC Server address is required")
	}
	out := make([]*net.UDPAddr, len(wans))
	for i, link := range wans {
		out[i] = &net.UDPAddr{IP: append(net.IP(nil), primary.IP...), Port: primary.Port, Zone: primary.Zone}
		if link.ServerIP != "" {
			ip := net.ParseIP(link.ServerIP)
			if ip == nil || (ip.To4() != nil) != (primary.IP.To4() != nil) {
				return nil, fmt.Errorf("WAN %d Server IP family does not match QUIC handshake address", i+1)
			}
			out[i].IP = ip
		}
		if i == 0 && !out[i].IP.Equal(primary.IP) {
			return nil, fmt.Errorf("first WAN server_ip must match authenticated connect_ip %s", primary.IP)
		}
	}
	if !discover || len(wans) <= 1 {
		return out, nil
	}
	var serverAddrs []*net.UDPAddr
	for _, item := range advertised {
		remote := net.UDPAddrFromAddrPort(item.Addr)
		if (remote.IP.To4() != nil) != (primary.IP.To4() != nil) || remote.IP.Equal(primary.IP) {
			continue
		}
		serverAddrs = append(serverAddrs, remote)
	}
	if len(serverAddrs) == 0 {
		return nil, errors.New("Server did not advertise a usable secondary WAN address")
	}
	n := 0
	for i := 1; i < len(out); i++ {
		if wans[i].ServerIP != "" {
			continue
		}
		out[i] = serverAddrs[n%len(serverAddrs)]
		n++
	}
	return out, nil
}

func getServerTargets(ctx context.Context, conn *quic.Conn, primary *net.UDPAddr, wans []clientWAN, discover bool) ([]*net.UDPAddr, error) {
	if !discover {
		return selectServerTargets(primary, wans, nil, false)
	}
	if !conn.ConnectionState().SupportsAddressAdvertisement {
		return nil, errors.New("Server did not negotiate MPQUIC ADD_ADDRESS extension")
	}
	// ADD_ADDRESS is retransmittable, but may arrive after CONNECT 200.
	// Only wait if an unpinned secondary WAN needs a remote. For explicit
	// server_ip fields, the peer announcement is not a prerequisite.
	need := false
	for _, link := range wans[1:] {
		if link.ServerIP == "" {
			need = true
			break
		}
	}
	if !need {
		return selectServerTargets(primary, wans, nil, false)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	for {
		addrs := conn.PeerAdvertisedAddresses()
		if len(addrs) != 0 {
			remotes, err := selectServerTargets(primary, wans, addrs, true)
			if err == nil {
				return remotes, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("wait for authenticated Server WAN advertisement: %w", waitCtx.Err())
		case <-conn.Context().Done():
			return nil, fmt.Errorf("MPQUIC connection closed while waiting for Server WAN advertisement: %w", conn.Context().Err())
		case <-ticker.C:
		}
	}
}

// Configured remote Server addresses must be unicast and must not
// unexpectedly redirect the primary authenticated TLS handshake.
func parseServerWANIP(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid Server WAN address %q", ip)
	}
	return addr.Unmap(), nil
}
