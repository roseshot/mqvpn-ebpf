package app

import (
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
)

func TestServerInstanceWANAutoMTUAndFrame(t *testing.T) {
	spec := sampleInstance("a", "a.example.test", "mq0")
	for _, tc := range []struct {
		links              []mtu.Underlay
		wantMTU, wantFrame int
	}{
		{[]mtu.Underlay{{Name: "enp1s0", MTU: 1500}}, 1400, 1414},
		{[]mtu.Underlay{{Name: "ppp0", MTU: 1492}}, 1392, 1406},
		{[]mtu.Underlay{{Name: "enp1s0", MTU: 1500}, {Name: "wwan0", MTU: 1420}}, 1320, 1334},
	} {
		inst := spec
		if err := resolveServerInstanceMTU(&inst, tc.links); err != nil {
			t.Fatal(err)
		}
		if inst.MTU != tc.wantMTU || inst.MaxFrame != tc.wantFrame {
			t.Fatalf("WANs %+v => MTU %d frame %d", tc.links, inst.MTU, inst.MaxFrame)
		}
	}
	if spec.MTU != 0 || spec.MaxFrame != 0 {
		t.Fatal("source YAML defaults were mutated")
	}
}

func TestServerExplicitMTUDoesNotNeedWANDiscovery(t *testing.T) {
	spec := sampleInstance("a", "a.example.test", "mq0")
	spec.MTU = 1360
	if err := resolveServerInstanceMTU(&spec, nil); err != nil {
		t.Fatal(err)
	}
	if spec.MTU != 1360 || spec.MaxFrame != 1374 {
		t.Fatalf("wrong explicit budget %+v", spec)
	}
}

func TestRemovedServerWANInterfacesYAMLIsRejected(t *testing.T) {
	var cfg ServerConfig
	err := configfile.Decode("server.yaml", []byte(`listen: ":8443"
wan_interfaces: [wan0, wan1]
instances: []
`), &cfg)
	if err == nil {
		t.Fatal("removed wan_interfaces YAML accepted")
	}
}
