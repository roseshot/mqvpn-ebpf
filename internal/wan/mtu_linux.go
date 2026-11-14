//go:build linux

package wan

import (
	"fmt"
	"net"
	"sort"

	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/vishvananda/netlink"
)

// SourceUnderlay returns the MTU of the exact local WAN interface owning the
// resolved source address. This is a local link MTU, NOT a measured PMTU.
func SourceUnderlay(source net.IP, interfaceName string) (mtu.Underlay, error) {
	if source == nil || source.IsUnspecified() {
		return mtu.Underlay{}, fmt.Errorf("WAN source IP is required for MTU discovery")
	}
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return mtu.Underlay{}, fmt.Errorf("WAN interface %q: %w", interfaceName, err)
		}
		if err := checkSourceOnInterface(source, iface); err != nil {
			return mtu.Underlay{}, err
		}
		return makeUnderlay(iface, source.To4() == nil)
	}
	all, err := net.Interfaces()
	if err != nil {
		return mtu.Underlay{}, fmt.Errorf("enumerate local WAN interfaces: %w", err)
	}
	var found *net.Interface
	for i := range all {
		if ifaceHasSource(source, &all[i]) {
			if found != nil {
				return mtu.Underlay{}, fmt.Errorf("WAN source IP %s is assigned to multiple interfaces; specify --source-interface", source)
			}
			found = &all[i]
		}
	}
	if found == nil {
		return mtu.Underlay{}, fmt.Errorf("WAN source IP %s has no matching local interface; specify --source-interface or configure a local WAN IP", source)
	}
	return makeUnderlay(found, source.To4() == nil)
}

func ifaceHasSource(source net.IP, iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if cidr, ok := a.(*net.IPNet); ok && cidr.IP.Equal(source) {
			return true
		}
	}
	return false
}
func checkSourceOnInterface(source net.IP, iface *net.Interface) error {
	if !ifaceHasSource(source, iface) {
		return fmt.Errorf("WAN source IP %s does not belong to interface %s", source, iface.Name)
	}
	return nil
}
func makeUnderlay(iface *net.Interface, ipv6 bool) (mtu.Underlay, error) {
	if iface.Flags&net.FlagUp == 0 {
		return mtu.Underlay{}, fmt.Errorf("WAN interface %s is DOWN", iface.Name)
	}
	if iface.MTU <= 0 {
		return mtu.Underlay{}, fmt.Errorf("WAN interface %s has invalid MTU %d", iface.Name, iface.MTU)
	}
	return mtu.Underlay{Name: iface.Name, MTU: iface.MTU, IPv6: ipv6}, nil
}

func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	return ones == 0
}

// ServerUnderlays selects WAN NICs based on explicit server wan_interfaces,
// the locally bound public listen IP, or the kernel's default routes.
// Wildcard listeners cannot reveal the *remote* peer path: on such servers,
// configure wan_interfaces to include every NIC that may carry VPN traffic.
// The smallest selected WAN packet budget wins.
func ServerUnderlays(listen string, names []string) ([]mtu.Underlay, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	bindIP := net.ParseIP(host)
	ipv4Only := bindIP != nil && bindIP.To4() != nil
	if len(names) > 0 {
		seen := make(map[string]bool, len(names))
		var result []mtu.Underlay
		for _, name := range names {
			if seen[name] {
				return nil, fmt.Errorf("duplicate WAN interface %q", name)
			}
			seen[name] = true
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return nil, fmt.Errorf("configured WAN interface %q: %w", name, err)
			}
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}
			hasV4, hasV6 := false, false
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsUnspecified() || ipnet.IP.IsMulticast() {
					continue
				}
				if ipnet.IP.To4() != nil {
					hasV4 = true
				} else if !ipnet.IP.IsLinkLocalUnicast() {
					hasV6 = true
				}
			}
			if !hasV4 && !hasV6 {
				return nil, fmt.Errorf("WAN interface %s has no usable IPv4/IPv6 source address", name)
			}
			if hasV4 {
				u, err := makeUnderlay(iface, false)
				if err != nil {
					return nil, err
				}
				result = append(result, u)
			}
			if hasV6 && !ipv4Only {
				u, err := makeUnderlay(iface, true)
				if err != nil {
					return nil, err
				}
				result = append(result, u)
			}
		}
		return result, nil
	}
	if bindIP != nil && !bindIP.IsUnspecified() {
		u, err := SourceUnderlay(bindIP, "")
		if err != nil {
			return nil, fmt.Errorf("resolve bound server WAN: %w", err)
		}
		return []mtu.Underlay{u}, nil
	}
	return defaultRouteUnderlays(ipv4Only)
}

func defaultRouteUnderlays(ipv4Only bool) ([]mtu.Underlay, error) {
	var out []mtu.Underlay
	seen := make(map[string]bool)
	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	if ipv4Only {
		families = families[:1]
	}
	for _, family := range families {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			return nil, fmt.Errorf("list default WAN routes (family %d): %w", family, err)
		}
		for _, route := range routes {
			// The normal main routing table identifies outbound Internet
			// WAN interfaces, not tenant VRF routes or directly connected LANs.
			if (route.Table != 0 && route.Table != 254) || !isDefaultRoute(route) {
				continue
			}
			indices := []int{route.LinkIndex}
			for _, hop := range route.MultiPath {
				indices = append(indices, hop.LinkIndex)
			}
			for _, index := range indices {
				if index <= 0 {
					continue
				}
				iface, err := net.InterfaceByIndex(index)
				if err != nil {
					return nil, err
				}
				if iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				key := fmt.Sprintf("%s/%d", iface.Name, family)
				if seen[key] {
					continue
				}
				u, err := makeUnderlay(iface, family == netlink.FAMILY_V6)
				if err != nil {
					return nil, err
				}
				out = append(out, u)
				seen[key] = true
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable main-table default WAN route: set server wan_interfaces explicitly or configure an explicit TUN mtu")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return !out[i].IPv6 && out[j].IPv6
	})
	return out, nil
}
