package p2mp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type PeerConfig struct {
	ID string `json:"id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Routes []string `json:"routes"`
	MulticastGroups []string `json:"multicast_groups,omitempty"`
}

type FileConfig struct {
	Peers []PeerConfig `json:"peers"`
	MulticastPPS int `json:"multicast_pps,omitempty"`
}

type Rule struct {
	ID string
	Fingerprint [32]byte
	Routes []netip.Prefix
	Groups map[netip.Addr]bool
}

type Config struct {
	Peers []*Rule
	MulticastPPS int
}

// Load enforces an explicit certificate-pin-to-route map. A QUIC connection
// with a CA-valid certificate but no configured fingerprint gets HTTP 403.
// Routes define both which source IPs the site may inject and the destination
// prefixes for routing back to that site.
func Load(path string) (*Config,error) {
	if path=="" { return nil,errors.New("--peers JSON file is required for point-to-multipoint") }
	raw,err:=os.ReadFile(path);if err!=nil{return nil,err}
	var f FileConfig
	if err:=json.Unmarshal(raw,&f);err!=nil{return nil,fmt.Errorf("parse peers JSON: %w",err)}
	return Parse(f)
}

func Parse(f FileConfig) (*Config,error) {
	if len(f.Peers)==0 {return nil,errors.New("peers list cannot be empty")}
	if len(f.Peers)>1024 {return nil,errors.New("too many peers")}
	if f.MulticastPPS==0 {f.MulticastPPS=20}
	if f.MulticastPPS<1 || f.MulticastPPS>1000 {return nil,errors.New("multicast_pps must be 1..1000")}
	cfg:=&Config{MulticastPPS:f.MulticastPPS}
	ids:=map[string]bool{}
	digests:=map[[32]byte]bool{}
	for _,p:=range f.Peers {
		if p.ID=="" || ids[p.ID] {return nil,fmt.Errorf("duplicate/empty peer ID %q",p.ID)}
		ids[p.ID]=true
		var sum [32]byte
		raw,err:=hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(p.CertificateSHA256),":",""))
		if err!=nil || len(raw)!=sha256.Size {return nil,fmt.Errorf("peer %q needs 32-byte certificate SHA256 fingerprint",p.ID)}
		copy(sum[:],raw)
		if digests[sum] {return nil,fmt.Errorf("duplicate certificate fingerprint for %s",p.ID)}
		digests[sum]=true
		if len(p.Routes)==0 {return nil,fmt.Errorf("peer %s has no advertised/allowed routes",p.ID)}
		rule:=&Rule{ID:p.ID,Fingerprint:sum,Groups:map[netip.Addr]bool{}}
		for _,cidr:=range p.Routes {
			prefix,err:=netip.ParsePrefix(cidr)
			if err!=nil || !prefix.IsValid() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
				return nil,fmt.Errorf("peer %s invalid route %q",p.ID,cidr)
			}
			prefix=prefix.Masked()
			if prefix.Bits()==0 {return nil,fmt.Errorf("peer %s cannot claim an all-address default route",p.ID)}
			// Avoid overlapping any two different peers' source ownership.
			for _,old:=range cfg.Peers {for _,existing:=range old.Routes {
				if prefix.Addr().Is4()==existing.Addr().Is4() && (prefix.Contains(existing.Addr()) || existing.Contains(prefix.Addr())) {
					return nil,fmt.Errorf("routes %s (%s) and %s (%s) overlap",prefix,p.ID,existing,old.ID)
				}
			}}
			rule.Routes=append(rule.Routes,prefix)
		}
		for _,group:=range p.MulticastGroups {
			ip,err:=netip.ParseAddr(group)
			if err!=nil || !ip.IsMulticast(){return nil,fmt.Errorf("peer %s invalid multicast group %q",p.ID,group)}
			rule.Groups[ip]=true
		}
		cfg.Peers=append(cfg.Peers,rule)
	}
	return cfg,nil
}

func (c *Config) PeerByCertificate(certDER []byte) *Rule {
	digest:=sha256.Sum256(certDER)
	for _,p:=range c.Peers {if p.Fingerprint==digest{return p}}
	return nil
}

func (p *Rule) Owns(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified() {return false}
	for _,prefix:=range p.Routes {if prefix.Contains(ip){return true}}
	return false
}

func (c *Config) Destination(ip netip.Addr) *Rule {
	if !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified(){return nil}
	var best *Rule
	bits:=-1
	for _,r:=range c.Peers {for _,p:=range r.Routes {
		if p.Bits()>bits && p.Contains(ip) {best=r;bits=p.Bits()}
	}}
	return best
}
