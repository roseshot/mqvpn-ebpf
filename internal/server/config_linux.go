//go:build linux

package server

import (
	"errors"
	"fmt"
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/xdp"
)

// defaultServerListen is the shared QUIC/UDP bind when YAML omits listen.
// Optional TCP fallback uses TCP/443 independently.
const defaultServerListen = "0.0.0.0:443"

// wanPath identifies a reachable Server QUIC/UDP address on an underlay
// interface. The shared wildcard socket accepts UDP on every listed IP;
// MPQUIC ADD_ADDRESS advertises them to authenticated Clients.
type wanPath struct {
	Interface string `yaml:"interface"`
	IP        string `yaml:"ip"`
}

// Instance owns an isolated L3 P2MP forwarding domain and mTLS identity.
// All instances share Config.Listen and one HTTP/3 QUIC listener.
type Instance struct {
	Name             string            `yaml:"name"`
	ServerName       string            `yaml:"server_name"`
	TUN              string            `yaml:"tun"`
	Address          string            `yaml:"address"`
	TunnelPool       string            `yaml:"tunnel_pool,omitempty"`
	PushRoutes       []string          `yaml:"push_routes,omitempty"`
	PushDNS          []string          `yaml:"push_dns,omitempty"`
	MTU              int               `yaml:"mtu,omitempty"`
	Peers            string            `yaml:"peers"`
	Path             string            `yaml:"path,omitempty"`
	Cert             string            `yaml:"cert"`
	Key              string            `yaml:"key"`
	ClientCA         string            `yaml:"client_ca"`
	ClientRevocation *RevocationConfig `yaml:"client_revocation,omitempty"`
	MaxFrame         int               `yaml:"max_frame,omitempty"`
	TC               *tcebpf.Config    `yaml:"tc,omitempty"`
}

// TCPFallback enables a separate TCP/443 TLS listener. It shares the
// authenticated SNI instance registry, but not the UDP socket or MPQUIC.
type TCPFallback struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen,omitempty"`
}

// HAConfig exposes local-only readiness for VRRP, BGP and TCP/UDP
// ingress health controllers. Ownership/election belongs to the Server
// deployment, never to the Client.
type HAConfig struct {
	ReadinessListen string `yaml:"readiness_listen,omitempty"`
}

type Config struct {
	HA            HAConfig    `yaml:"ha,omitempty"`
	TCPFallback   TCPFallback `yaml:"tcp_fallback,omitempty"`
	Listen        string      `yaml:"listen,omitempty"`
	PathScheduler string      `yaml:"path_scheduler,omitempty"`
	WANs          []wanPath   `yaml:"wans,omitempty"`
	XDP           *xdp.Config `yaml:"xdp,omitempty"`
	Instances     []Instance  `yaml:"instances"`
}

func loadServerConfig(path string) (Config, error) {
	var cfg Config
	if err := configfile.Read(path, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = defaultServerListen
	}
	policy, err := vpnwire.NormalizePathScheduler(c.PathScheduler)
	if err != nil {
		return err
	}
	c.PathScheduler = policy
	if c.HA.ReadinessListen != "" {
		host, port, err := net.SplitHostPort(c.HA.ReadinessListen)
		if err != nil {
			return fmt.Errorf("invalid ha.readiness_listen: %w", err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Zone() != "" || (addr.String() != "127.0.0.1" && addr.String() != "::1") {
			return errors.New("ha.readiness_listen must use a literal loopback IP (127.0.0.1 or ::1); never expose unauthenticated health checks publicly")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid ha.readiness_listen TCP port %q", port)
		}
	}
	if c.TCPFallback.Enabled && c.TCPFallback.Listen == "" {
		c.TCPFallback.Listen = "0.0.0.0:443"
	}
	if !c.TCPFallback.Enabled && c.TCPFallback.Listen != "" {
		return errors.New("tcp_fallback.listen requires tcp_fallback.enabled: true")
	}
	if c.TCPFallback.Enabled {
		_, tcpPort, err := net.SplitHostPort(c.TCPFallback.Listen)
		if err != nil {
			return fmt.Errorf("invalid TCP fallback listen %q: %w", c.TCPFallback.Listen, err)
		}
		n, err := strconv.Atoi(tcpPort)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid TCP fallback port %q", tcpPort)
		}
	}
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid shared listen %q: %w", c.Listen, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid shared listen UDP port %q", port)
	}
	if c.XDP != nil {
		normalized, err := c.XDP.Normalize()
		if err != nil {
			return fmt.Errorf("XDP: %w", err)
		}
		c.XDP = &normalized
	}
	if len(c.Instances) == 0 {
		return errors.New("at least one VPN instance is required")
	}
	if len(c.Instances) > 128 {
		return errors.New("maximum 128 VPN instances")
	}
	// A single wildcard UDP socket is needed for all MPQUIC paths:
	// independent listeners create unrelated QUIC connection registries.
	if len(c.WANs) != 0 {
		host, _, _ := net.SplitHostPort(c.Listen)
		if host != "" && host != "0.0.0.0" && host != "::" {
			return errors.New("server multi-WAN requires a wildcard listen address to receive packets on all WAN IPs")
		}
		seenIP := make(map[netip.Addr]bool, len(c.WANs))
		seenIface := make(map[string]bool, len(c.WANs))
		for i, link := range c.WANs {
			if link.Interface == "" || strings.TrimSpace(link.Interface) != link.Interface || seenIface[link.Interface] {
				return fmt.Errorf("server WAN %d invalid or duplicate interface %q", i+1, link.Interface)
			}
			ip, err := netip.ParseAddr(link.IP)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
				return fmt.Errorf("server WAN %d invalid unicast IP %q", i+1, link.IP)
			}
			ip = ip.Unmap()
			if seenIP[ip] {
				return fmt.Errorf("server WAN %d duplicate IP %s", i+1, ip)
			}
			if (host == "0.0.0.0" || host == "") && !ip.Is4() {
				return fmt.Errorf("server WAN %d address %s is not IPv4 for wildcard listen %q", i+1, ip, c.Listen)
			}
			seenIP[ip], seenIface[link.Interface] = true, true
		}
	}
	names, tuns, sni := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range c.Instances {
		inst := &c.Instances[i]
		if inst.Path == "" {
			inst.Path = vpnwire.DefaultPath
		}
		if inst.Name == "" || inst.ServerName == "" || inst.TUN == "" ||
			inst.Peers == "" || inst.Cert == "" || inst.Key == "" || inst.ClientCA == "" {
			return fmt.Errorf("instance %d requires name, server_name, tun, address, peers, cert, key and client_ca", i)
		}
		if inst.ClientRevocation != nil {
			policy := inst.ClientRevocation
			if policy.Mode == "" {
				policy.Mode = "off"
			}
			switch policy.Mode {
			case "off":
				if policy.CRLFile != "" {
					return fmt.Errorf("instance %s client_revocation.crl_file requires mode: crl", inst.Name)
				}
			case "crl":
				if policy.CRLFile == "" {
					return fmt.Errorf("instance %s client_revocation.mode: crl requires crl_file", inst.Name)
				}
			default:
				return fmt.Errorf("instance %s invalid client_revocation.mode %q: use off or crl", inst.Name, policy.Mode)
			}
		}
		if err := mtu.ValidateRequest(inst.TUN, inst.Address, inst.MTU, inst.MaxFrame); err != nil {
			return fmt.Errorf("instance %s: %w", inst.Name, err)
		}
		routes, err := routepush.Parse(inst.PushRoutes)
		if err != nil {
			return fmt.Errorf("instance %s push_routes: %w", inst.Name, err)
		}
		if len(routes) > 0 {
			inst.PushRoutes = make([]string, len(routes))
			for i, p := range routes {
				inst.PushRoutes[i] = p.String()
			}
		}
		dns, err := dnspush.Parse(inst.PushDNS)
		if err != nil {
			return fmt.Errorf("instance %s push_dns: %w", inst.Name, err)
		}
		if len(dns) > 0 {
			inst.PushDNS = make([]string, len(dns))
			for i, ip := range dns {
				inst.PushDNS[i] = ip.String()
			}
		}
		if inst.TC == nil {
			defaultTC := tcebpf.DefaultConfig()
			inst.TC = &defaultTC
		} else {
			next, err := inst.TC.Normalize()
			if err != nil {
				return fmt.Errorf("instance %s TC eBPF: %w", inst.Name, err)
			}
			inst.TC = &next // Preserve explicit mode: off; nil means default auto.
		}
		inst.ServerName = strings.ToLower(inst.ServerName)
		if err := validateInstanceIdentity(inst.ServerName, len(c.Instances) == 1); err != nil {
			return fmt.Errorf("instance %s: %w", inst.Name, err)
		}
		if err := vpnwire.ValidateMASQUEPath(inst.Path); err != nil {
			return fmt.Errorf("instance %s MASQUE path: %w", inst.Name, err)
		}
		if inst.MaxFrame != 0 && (inst.MaxFrame < 64 || inst.MaxFrame > 65535) {
			return fmt.Errorf("instance %s invalid max_frame", inst.Name)
		}
		if names[inst.Name] || tuns[inst.TUN] || sni[inst.ServerName] {
			return fmt.Errorf("duplicate instance name, TUN or TLS server_name in %s", inst.Name)
		}
		names[inst.Name], tuns[inst.TUN], sni[inst.ServerName] = true, true, true
	}
	return nil
}

// IP SAN certificates are supported only when no SNI demultiplexing is
// necessary. An IP TLS ClientHello does not carry a usable SNI extension.
// Multi-instance listeners must use distinct DNS identities.
func validateInstanceIdentity(identity string, single bool) error {
	if ip, err := netip.ParseAddr(identity); err == nil {
		if !single {
			return fmt.Errorf("IP server_name %q requires exactly one instance", identity)
		}
		if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return fmt.Errorf("IP server_name %q must be a unicast address without zone", identity)
		}
		return nil
	}
	return vpnwire.ValidateSNI(identity)
}
