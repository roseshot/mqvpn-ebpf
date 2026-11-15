package client

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// wanPath describes one physical underlay path. Its position in the
// list determines the initial handshake path; remaining entries are
// validated as MPQUIC paths. No mqvpn-specific path-count ceiling is
// imposed. The underlying mp-quic-go library independently limits
// concurrently active paths (64 in v0.3.1).
type wanPath struct {
	SourceIP  string `yaml:"source_ip,omitempty"`
	Interface string `yaml:"interface,omitempty"`
	ServerIP  string `yaml:"server_ip,omitempty"`
}

// wanFlags accepts repeated --wan=source_ip@interface arguments.
// The list replaces YAML wans rather than appending a different set.
type wanFlags []wanPath

func (w *wanFlags) String() string {
	parts := make([]string, 0, len(*w))
	for _, item := range *w {
		spec := item.SourceIP + "@" + item.Interface
		if item.ServerIP != "" {
			spec += "=" + item.ServerIP
		}
		parts = append(parts, spec)
	}
	return strings.Join(parts, ",")
}

func (w *wanFlags) Set(value string) error {
	source, remainder, ok := strings.Cut(value, "@")
	if !ok || source == "" || remainder == "" {
		return errors.New("--wan expects SOURCE_IP@INTERFACE[=SERVER_IP] (repeat for each WAN)")
	}
	iface, server, specified := strings.Cut(remainder, "=")
	if iface == "" || (specified && server == "") {
		return errors.New("--wan expects SOURCE_IP@INTERFACE[=SERVER_IP]")
	}
	*w = append(*w, wanPath{SourceIP: source, Interface: iface, ServerIP: server})
	return nil
}

// planClientWANs chooses a single ordered representation. Repeated --wan
// arguments override the YAML list; if both are absent, the kernel selects
// the source address and interface for the only initial path.
func planClientWANs(list, cli []wanPath) ([]wanPath, error) {
	var selected []wanPath
	switch {
	case len(cli) != 0:
		selected = append(selected, cli...)
	case len(list) != 0:
		selected = append(selected, list...)
	default:
		selected = []wanPath{{}}
	}
	seenIPs := make(map[netip.Addr]bool, len(selected))
	seenInterfaces := make(map[string]bool, len(selected))
	for i, item := range selected {
		if item.SourceIP == "" && item.Interface == "" && len(selected) > 1 {
			return nil, fmt.Errorf("WAN %d requires an explicit source_ip or interface", i+1)
		}
		if item.SourceIP != "" {
			ip, err := netip.ParseAddr(item.SourceIP)
			if err != nil || ip.Zone() != "" {
				return nil, fmt.Errorf("WAN %d invalid source IP %q", i+1, item.SourceIP)
			}
			// Treat IPv4-mapped IPv6 literals as IPv4 for validation and
			// duplicate detection, matching the socket layer's net.ParseIP.
			ip = ip.Unmap()
			if ip.IsUnspecified() || ip.IsMulticast() {
				return nil, fmt.Errorf("WAN %d invalid source IP %q", i+1, item.SourceIP)
			}
			if seenIPs[ip] {
				return nil, fmt.Errorf("WAN %d reuses source IP %s", i+1, item.SourceIP)
			}
			seenIPs[ip] = true
		}
		if item.ServerIP != "" {
			server, err := netip.ParseAddr(item.ServerIP)
			if err != nil || server.Zone() != "" {
				return nil, fmt.Errorf("WAN %d invalid server_ip %q", i+1, item.ServerIP)
			}
			server = server.Unmap()
			if server.IsUnspecified() || server.IsMulticast() {
				return nil, fmt.Errorf("WAN %d invalid server_ip %q", i+1, item.ServerIP)
			}
			if item.SourceIP != "" {
				source, _ := netip.ParseAddr(item.SourceIP)
				if source.Unmap().Is4() != server.Is4() {
					return nil, fmt.Errorf("WAN %d source and server IP families differ", i+1)
				}
			}
		}
		if item.Interface != "" {
			if len(item.Interface) >= 16 || strings.TrimSpace(item.Interface) != item.Interface || strings.ContainsRune(item.Interface, '\x00') {
				return nil, fmt.Errorf("WAN %d invalid interface %q", i+1, item.Interface)
			}
			if seenInterfaces[item.Interface] {
				return nil, fmt.Errorf("WAN %d reuses interface %s", i+1, item.Interface)
			}
			seenInterfaces[item.Interface] = true
		}
	}
	return selected, nil
}
