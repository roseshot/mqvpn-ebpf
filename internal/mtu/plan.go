// Package mtu derives a conservative initial TUN packet budget from the
// locally selected WAN link MTUs. It does not claim to measure end-to-end
// Path MTU or QUIC's currently negotiated maximum DATAGRAM size.
package mtu

import (
	"fmt"
	"net/netip"

	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

const (
	// DefaultMaxTUNMTU caps automatic sizing on an otherwise large WAN.
	// Explicit MTU overrides remain possible when WAN PMTU is verified.
	DefaultMaxTUNMTU = tun.DefaultMTU
	// Reserved bytes include outer IP, UDP, QUIC short header + AEAD tag,
	// DATAGRAM frame, H3 quarter stream ID, MASQUE Context ID, synthetic
	// Ethernet and an extra safety margin for variable-length headers.
	// This is a startup heuristic, not a negotiated/verified PMTU.
	IPv4Reserve = 100
	IPv6Reserve = 120
)

type Underlay struct {
	Name string
	MTU  int
	// IPv6 means the *outer* WAN IP family (not the VPN TUN IP family).
	IPv6 bool
}

type Result struct {
	TUNMTU      int
	MaxFrame    int
	Auto        bool
	LimitingWAN string
}

// ValidateRequest checks inputs that are independent of the local WAN.
// Zero MTU / max_frame are allowed to represent runtime automatic sizing.
func ValidateRequest(name, address string, requestedMTU, requestedFrame int) error {
	if requestedMTU < 0 || requestedFrame < 0 || requestedFrame > 65535 {
		return fmt.Errorf("invalid TUN MTU %d or max_frame %d", requestedMTU, requestedFrame)
	}
	testMTU := requestedMTU
	if testMTU == 0 {
		testMTU = DefaultMaxTUNMTU
	}
	frame := requestedFrame
	if requestedMTU == 0 {
		// The selected WAN may constrain an automatic MTU below 1400;
		// final frame compatibility is checked by Plan at runtime.
		frame = 0
	}
	return tun.Validate(name, address, testMTU, frame)
}

// Plan selects the lowest usable WAN MTU after outer-family overhead, caps
// it at 1400 by default, and couples max_frame to the TUN's Ethernet shim.
// An explicit requested MTU overrides auto sizing; this is deliberate and
// does not imply that the WAN can actually carry that size.
func Plan(name, address string, requestedMTU, requestedFrame int, paths []Underlay) (Result, error) {
	if err := ValidateRequest(name, address, requestedMTU, requestedFrame); err != nil {
		return Result{}, err
	}
	result := Result{TUNMTU: requestedMTU, Auto: requestedMTU == 0}
	if result.Auto {
		if len(paths) == 0 {
			return Result{}, fmt.Errorf("auto TUN MTU needs at least one WAN interface; specify a WAN interface or explicit MTU")
		}
		result.TUNMTU = DefaultMaxTUNMTU
		for _, path := range paths {
			if path.MTU <= 0 {
				return Result{}, fmt.Errorf("invalid WAN MTU %d on %q", path.MTU, path.Name)
			}
			reserve := IPv4Reserve
			if path.IPv6 {
				reserve = IPv6Reserve
			}
			budget := path.MTU - reserve
			if budget < result.TUNMTU {
				result.TUNMTU = budget
				result.LimitingWAN = path.Name
			}
		}
	}
	result.MaxFrame = requestedFrame
	if result.MaxFrame == 0 {
		result.MaxFrame = result.TUNMTU + tun.EthernetOverhead
	}
	if result.MaxFrame > 65535 || result.TUNMTU+tun.EthernetOverhead > result.MaxFrame {
		return Result{}, fmt.Errorf("max_frame %d cannot carry TUN MTU %d + %d bytes Ethernet", result.MaxFrame, result.TUNMTU, tun.EthernetOverhead)
	}
	if err := tun.Validate(name, address, result.TUNMTU, result.MaxFrame); err != nil {
		return Result{}, fmt.Errorf("WAN-derived TUN MTU is not usable: %w", err)
	}
	prefix, _ := netip.ParsePrefix(address)
	if prefix.Addr().Is6() && result.TUNMTU < 1280 {
		return Result{}, fmt.Errorf("WAN links cannot support the IPv6 minimum TUN MTU 1280 under current encapsulation")
	}
	return result, nil
}
