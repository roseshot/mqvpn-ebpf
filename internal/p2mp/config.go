package p2mp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
)

// PeerConfig identifies an authenticated session and the destination prefixes
// that should be delivered to it. Routes are NOT kernel routes or traffic ACLs.
type PeerConfig struct {
	ID                string   `yaml:"id"`
	CertificateSHA256 string   `yaml:"certificate_sha256"`
	Routes            []string `yaml:"routes"`
	DynamicTunnelIP   bool     `yaml:"dynamic_tunnel_ip,omitempty"`
}

type FileConfig struct {
	Peers []PeerConfig `yaml:"peers"`
}

type Rule struct {
	ID              string
	Fingerprint     [32]byte
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
	digests := map[[32]byte]bool{}
	for _, p := range f.Peers {
		if p.ID == "" || ids[p.ID] {
			return nil, fmt.Errorf("duplicate or empty peer ID %q", p.ID)
		}
		ids[p.ID] = true
		raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(p.CertificateSHA256), ":", ""))
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("peer %s needs a 32-byte certificate SHA-256 fingerprint", p.ID)
		}
		var digest [32]byte
		copy(digest[:], raw)
		if digests[digest] {
			return nil, fmt.Errorf("duplicate client certificate fingerprint for %s", p.ID)
		}
		digests[digest] = true
		if len(p.Routes) == 0 && !p.DynamicTunnelIP {
			return nil, fmt.Errorf("peer %s has no destination prefixes", p.ID)
		}
		r := &Rule{ID: p.ID, Fingerprint: digest, DynamicTunnelIP: p.DynamicTunnelIP}
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

// PeerByCertificate is connection authentication only. It does not inspect
// or authorize any tunneled traffic's inner IP source or destination.
func (c *Config) PeerByCertificate(certDER []byte) *Rule {
	sum := sha256.Sum256(certDER)
	for _, p := range c.Peers {
		if p.Fingerprint == sum {
			return p
		}
	}
	return nil
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
