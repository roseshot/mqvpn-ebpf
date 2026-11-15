package p2mp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
)

// PeerConfig identifies an authenticated session and the destination prefixes
// that should be delivered to it. Routes are NOT kernel routes or traffic ACLs.
type PeerConfig struct {
	ID string `yaml:"id"`
	// By default a peer's id is matched against the verified Client certificate CN.
	// certificate_cn permits a different human-friendly peer ID.
	CertificateCN string `yaml:"certificate_cn,omitempty"`
	Routes []string `yaml:"routes"`
	// Nil means inherit the instance setting; [] explicitly suppresses it.
	PushRoutes      []string `yaml:"push_routes,omitempty"`
	PushDNS         []string `yaml:"push_dns,omitempty"`
	DynamicTunnelIP bool     `yaml:"dynamic_tunnel_ip,omitempty"`
}

type FileConfig struct {
	Peers []PeerConfig `yaml:"peers"`
}

type Rule struct {
	ID              string
	CertificateCN   string
	PushRoutes      []string // nil => inherit instance-wide defaults
	PushDNS         []string
	Routes          []netip.Prefix
	DynamicTunnelIP bool
}

type Config struct {
	Peers []*Rule
}

func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("--peers YAML file is required to select destination sessions")
	}
	var file FileConfig
	if err := configfile.Read(path, &file); err != nil {
		return nil, fmt.Errorf("load peers: %w", err)
	}
	return Parse(file)
}

func Parse(f FileConfig) (*Config, error) {
	if len(f.Peers) == 0 {
		return nil, errors.New("peers list cannot be empty")
	}
	if len(f.Peers) > 1024 {
		return nil, errors.New("too many peers")
	}
	cfg := &Config{}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, p := range f.Peers {
		if p.ID == "" || ids[p.ID] {
			return nil, fmt.Errorf("duplicate or empty peer ID %q", p.ID)
		}
		ids[p.ID] = true
		cn := p.CertificateCN
		if cn == "" {
			cn = p.ID
		}
		if cn != strings.TrimSpace(cn) || strings.ContainsAny(cn, "\r\n\x00") || names[cn] {
			return nil, fmt.Errorf("peer %s has invalid or duplicate certificate CN %q", p.ID, cn)
		}
		names[cn] = true
		if len(p.Routes) == 0 && !p.DynamicTunnelIP {
			return nil, fmt.Errorf("peer %s has no destination prefixes", p.ID)
		}
		r := &Rule{ID: p.ID, CertificateCN: cn, DynamicTunnelIP: p.DynamicTunnelIP}
		if p.PushRoutes != nil {
			routes, err := routepush.Parse(p.PushRoutes)
			if err != nil {
				return nil, fmt.Errorf("peer %s push_routes: %w", p.ID, err)
			}
			r.PushRoutes = make([]string, 0, len(routes))
			for _, route := range routes {
				r.PushRoutes = append(r.PushRoutes, route.String())
			}
		}
		if p.PushDNS != nil {
			dns, err := dnspush.Parse(p.PushDNS)
			if err != nil {
				return nil, fmt.Errorf("peer %s push_dns: %w", p.ID, err)
			}
			r.PushDNS = make([]string, 0, len(dns))
			for _, ip := range dns {
				r.PushDNS = append(r.PushDNS, ip.String())
			}
		}
		for _, cidr := range p.Routes {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || !prefix.IsValid() || prefix.Addr().IsMulticast() {
				return nil, fmt.Errorf("peer %s invalid destination prefix %q", p.ID, cidr)
			}
			prefix = prefix.Masked()
			// Overlaps are ambiguous for the *session demux* even though
			// kernel routes remain fully independent from the daemon.
			for _, previous := range cfg.Peers {
				for _, existing := range previous.Routes {
					if prefix.Addr().Is4() == existing.Addr().Is4() && (prefix.Contains(existing.Addr()) || existing.Contains(prefix.Addr())) {
						return nil, fmt.Errorf("peer %s destination %s overlaps %s of %s", p.ID, prefix, existing, previous.ID)
					}
				}
			}
			r.Routes = append(r.Routes, prefix)
		}
		cfg.Peers = append(cfg.Peers, r)
	}
	return cfg, nil
}

// PeerByCertificate looks up an explicitly configured CN after the caller
// has verified Client mTLS against the tenant's trusted CA and optional CRL.
// A trusted CA alone never grants destination prefix ownership.
func (c *Config) PeerByCertificate(certDER []byte) *Rule {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil || cert.IsCA || cert.Subject.CommonName == "" {
		return nil
	}
	for _, rule := range c.Peers {
		if rule.CertificateCN == cert.Subject.CommonName {
			return rule
		}
	}
	return nil
}

// SameIdentity decides whether a hot-reloaded rule still authorizes a
// previously authenticated session under the same unique tenant CN.
func (r *Rule) SameIdentity(other *Rule) bool {
	return r != nil && other != nil &&
		r.ID == other.ID && r.CertificateCN == other.CertificateCN
}

// EffectivePush inherits instance defaults when the client-specific
// setting is omitted; an explicit empty YAML list suppresses the defaults.
func EffectivePush(defaults, override []string) []string {
	if override != nil {
		return override
	}
	return defaults
}

// Destination is forwarding-address resolution for unicast from the single
// P2MP TUN. The kernel route decided to emit the packet on that TUN already.
func (c *Config) Destination(addr netip.Addr) *Rule {
	if !addr.IsValid() || addr.IsMulticast() {
		return nil
	}
	var selected *Rule
	best := -1
	for _, rule := range c.Peers {
		for _, prefix := range rule.Routes {
			if prefix.Bits() > best && prefix.Contains(addr) {
				selected = rule
				best = prefix.Bits()
			}
		}
	}
	return selected
}
