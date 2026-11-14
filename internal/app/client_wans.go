package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// clientWAN describes one physical underlay path. Its position in the
// list determines the initial handshake path; remaining entries are
// validated as MPQUIC paths. No mqvpn-specific path-count ceiling is
// imposed. The underlying mp-quic-go library independently limits
// concurrently active paths (64 in v0.3.1).
type clientWAN struct {
	SourceIP  string `yaml:"source_ip,omitempty"`
	Interface string `yaml:"interface,omitempty"`
	ServerIP  string `yaml:"server_ip,omitempty"`
}

// clientWANFlags accepts repeated --wan=source_ip@interface arguments.
// The list replaces YAML wans rather than appending a different set.
type clientWANFlags []clientWAN

func (w *clientWANFlags) String() string {
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

func (w *clientWANFlags) Set(value string) error {
	source, remainder, ok := strings.Cut(value, "@")
	if !ok || source == "" || remainder == "" {
		return errors.New("--wan expects SOURCE_IP@INTERFACE[=SERVER_IP] (repeat for each WAN)")
	}
	iface, server, specified := strings.Cut(remainder, "=")
	if iface == "" || (specified && server == "") {
		return errors.New("--wan expects SOURCE_IP@INTERFACE[=SERVER_IP]")
	}
	*w = append(*w, clientWAN{SourceIP: source, Interface: iface, ServerIP: server})
	return nil
}

// planClientWANs converts both the new ordered list and the historical
// two-WAN flags to one representation. Do not silently merge the two
// configuration models: it makes the handshake path ambiguous.
func planClientWANs(list, cli []clientWAN, primaryIP, primaryInterface, secondIP, secondInterface string, explicitLegacy bool) ([]clientWAN, error) {
	if len(cli) != 0 && explicitLegacy {
		return nil, errors.New("--wan cannot be combined with legacy --source-* or --wan2-* flags")
	}
	if len(list) != 0 && explicitLegacy && len(cli) == 0 {
		return nil, errors.New("YAML wans cannot be combined with legacy WAN CLI flags; override with repeated --wan")
	}
	var selected []clientWAN
	switch {
	case len(cli) != 0:
		selected = append(selected, cli...)
	case len(list) != 0:
		selected = append(selected, list...)
	default:
		selected = append(selected, clientWAN{SourceIP: primaryIP, Interface: primaryInterface})
		if secondIP != "" || secondInterface != "" {
			selected = append(selected, clientWAN{SourceIP: secondIP, Interface: secondInterface})
		}
	}
	seenIPs := make(map[netip.Addr]bool, len(selected))
	seenInterfaces := make(map[string]bool, len(selected))
	for i, item := range selected {
		if item.SourceIP == "" && item.Interface == "" && len(selected) > 1 {
			return nil, fmt.Errorf("WAN %d requires an explicit source_ip or interface", i+1)
		}
		if item.SourceIP != "" {
			ip, err := netip.ParseAddr(item.SourceIP)
			if err != nil || ip.IsUnspecified() || ip.Zone() != "" {
				return nil, fmt.Errorf("WAN %d invalid source IP %q", i+1, item.SourceIP)
			}
			if seenIPs[ip.Unmap()] {
				return nil, fmt.Errorf("WAN %d reuses source IP %s", i+1, item.SourceIP)
			}
			seenIPs[ip.Unmap()] = true
		}
		if item.ServerIP != "" {
			server, err := netip.ParseAddr(item.ServerIP)
			if err != nil || server.IsUnspecified() || server.IsMulticast() || server.Zone() != "" {
				return nil, fmt.Errorf("WAN %d invalid server_ip %q", i+1, item.ServerIP)
			}
			if item.SourceIP != "" {
				source, _ := netip.ParseAddr(item.SourceIP)
				if source.Is4() != server.Is4() {
					return nil, fmt.Errorf("WAN %d source and server IP families differ", i+1)
				}
			}
		}
		if item.Interface != "" {
			if seenInterfaces[item.Interface] {
				return nil, fmt.Errorf("WAN %d reuses interface %s", i+1, item.Interface)
			}
			seenInterfaces[item.Interface] = true
		}
	}
	return selected, nil
}
