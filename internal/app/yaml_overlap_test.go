package app

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
)

func TestMultipleInstancesSamePortAndOverlappingSubnets(t *testing.T) {
	cfg, _ := testServerFiles(t)
	first := cfg.Instances[0]
	first.Name = "customer-a"
	first.ServerName = "customer-a.example.test"
	first.TUN = "mq0"
	second := first
	second.Name = "customer-b"
	second.ServerName = "customer-b.example.test"
	second.TUN = "mq1"
	for _, spec := range []*ServerInstance{&first, &second} {
		sum := sha256.Sum256([]byte(spec.Name))
		peerCfg := p2mp.FileConfig{Peers: []p2mp.PeerConfig{{
			ID: spec.Name + "-peer",
			CertificateSHA256: hex.EncodeToString(sum[:]),
			Routes: []string{"10.77.0.2/32", "192.168.20.0/24"},
		}}}
		path := filepath.Join(t.TempDir(), spec.Name+".yaml")
		b, err := configfile.Marshal(path, peerCfg)
		if err != nil { t.Fatal(err) }
		if err := os.WriteFile(path, b, 0600); err != nil { t.Fatal(err) }
		spec.Peers = path
	}
	cfg.Instances = []ServerInstance{first, second}
	prepared, err := prepareServer(cfg)
	if err != nil { t.Fatal(err) }
	if prepared.listen != "0.0.0.0:4433" { t.Fatal("not one shared UDP socket") }
	a, b := prepared.instances["customer-a"], prepared.instances["customer-b"]
	if a.peers == b.peers { t.Fatal("P2MP peer tables shared accidentally") }
	ip := netip.MustParseAddr("192.168.20.77")
	if a.peers.Destination(ip).ID != "customer-a-peer" || b.peers.Destination(ip).ID != "customer-b-peer" {
		t.Fatal("overlapping subnet mapped to wrong VPN tenant")
	}
	if a.tlsConfig == b.tlsConfig { t.Fatal("mTLS configurations must remain per instance") }
}

func TestAmbiguousRoutesInsideOneInstanceRejected(t *testing.T) {
	_, err := p2mp.Parse(p2mp.FileConfig{Peers: []p2mp.PeerConfig{
		{ID: "a", CertificateSHA256: strings.Repeat("a", 64), Routes: []string{"192.168.20.0/24"}},
		{ID: "b", CertificateSHA256: strings.Repeat("b", 64), Routes: []string{"192.168.20.1/32"}},
	}})
	if err == nil { t.Fatal("same VPN instance cannot choose a next hop") }
}
