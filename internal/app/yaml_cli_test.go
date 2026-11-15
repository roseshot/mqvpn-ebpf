package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
)

func TestPeerYAMLChangesHotReloadWithoutSharedListenerRestart(t *testing.T) {
	cfg, _ := testServerFiles(t)
	peerFile := filepath.Join(t.TempDir(), "peers.yaml")
	write := func(routes []string) {
		t.Helper()
		b, err := configfile.Marshal(peerFile, p2mp.FileConfig{Peers: []p2mp.PeerConfig{{
			ID: "peer-1", Routes: routes,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(peerFile, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write([]string{"10.77.0.2/32"})
	cfg.Instances[0].Peers = peerFile
	first, err := prepareServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write([]string{"10.77.0.2/32", "192.168.20.0/24"})
	second, err := prepareServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.instances["edge-a"], second.instances["edge-a"]
	if a.staticHash != b.staticHash || a.peerHash == b.peerHash || first.listen != second.listen {
		t.Fatal("peer update invalidated shared QUIC listener")
	}
}
