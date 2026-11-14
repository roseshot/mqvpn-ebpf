//go:build linux

package xdp

import (
	"errors"
	"github.com/cilium/ebpf"
	"reflect"
	"testing"
)

type mockDevice struct {
	ports  []uint16
	closed bool
	fail   bool
}

func (m *mockDevice) ReplacePorts(p []uint16) error {
	if m.fail {
		return errors.New("simulated BPF map update failure")
	}
	m.ports = append([]uint16(nil), p...)
	return nil
}
func (m *mockDevice) Close() error                { m.closed = true; return nil }
func (m *mockDevice) Counters() (Counters, error) { return Counters{Packets: 7, Bytes: 123}, nil }

func TestSharedDispatcherHotReload(t *testing.T) {
	devices := map[string]*mockDevice{}
	c := &Controller{
		devices: map[string]portDevice{},
		open: func(name string, cfg Config) (portDevice, error) {
			d := &mockDevice{}
			devices[name] = d
			return d, nil
		},
	}
	cfg := Config{Interfaces: []string{"enp1s0", "enp2s0"}, Object: "bpf/xdp.o", Mode: "driver"}
	if err := c.Reconcile(cfg, []uint16{4433, 4434}); err != nil {
		t.Fatal(err)
	}
	first := devices["enp1s0"]
	if !reflect.DeepEqual(first.ports, []uint16{4433, 4434}) {
		t.Fatal(first.ports)
	}
	if err := c.Reconcile(cfg, []uint16{4434, 4435}); err != nil {
		t.Fatal(err)
	}
	if devices["enp1s0"] != first {
		t.Fatal("hot reload reattached existing NIC")
	}
	if !reflect.DeepEqual(first.ports, []uint16{4434, 4435}) {
		t.Fatal(first.ports)
	}
	if err := c.Reconcile(Config{Interfaces: []string{"enp1s0"}, Object: "bpf/xdp.o", Mode: "driver"}, []uint16{4435}); err != nil {
		t.Fatal(err)
	}
	if !devices["enp2s0"].closed {
		t.Fatal("removed interface remains attached")
	}
	if err := c.Reconcile(Config{}, []uint16{4435}); err != nil {
		t.Fatal(err)
	}
	if !devices["enp1s0"].closed {
		t.Fatal("remaining NIC not detached")
	}
}

func TestConfigChangeAndMapFailureAreRejected(t *testing.T) {
	c := &Controller{devices: map[string]portDevice{}, open: func(_ string, _ Config) (portDevice, error) {
		return &mockDevice{}, nil
	}}
	cfg := Config{Interfaces: []string{"enp1s0"}, Object: "xdp.o", Mode: "driver"}
	if err := c.Reconcile(cfg, []uint16{4433}); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconcile(Config{Interfaces: []string{"enp1s0"}, Object: "different.o", Mode: "driver"}, []uint16{4434}); err == nil {
		t.Fatal("live XDP ELF replacement should require explicit restart")
	}
	d := c.devices["enp1s0"].(*mockDevice)
	d.fail = true
	if err := c.Reconcile(cfg, []uint16{4434}); err == nil {
		t.Fatal("map update failure swallowed")
	}
	if !reflect.DeepEqual(c.ports, []uint16{4433}) {
		t.Fatalf("committed ports changed: %v", c.ports)
	}
}

func TestCurrentXDPObjectSchemaIsStrict(t *testing.T) {
	valid := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{"xdp_mqvpn": {}},
		Maps: map[string]*ebpf.MapSpec{
			"instance_ports": {}, "xdp_stats": {},
		},
	}
	if err := validateXDPObject(valid); err != nil {
		t.Fatal(err)
	}
	withoutStats := valid.Copy()
	delete(withoutStats.Maps, "xdp_stats")
	if err := validateXDPObject(withoutStats); err == nil {
		t.Fatal("XDP object without statistics map accepted")
	}
	withXSK := valid.Copy()
	withXSK.Maps["xsks_map"] = &ebpf.MapSpec{}
	if err := validateXDPObject(withXSK); err == nil {
		t.Fatal("XDP object with obsolete XSKMAP accepted")
	}
	if err := validateXDPObject(nil); err == nil {
		t.Fatal("nil XDP spec accepted")
	}
}

func TestXDPStatsAreCollectedWithoutCompatibilityFallback(t *testing.T) {
	c := &Controller{devices: map[string]portDevice{"wan0": &mockDevice{}}}
	stats, err := c.Snapshots()
	if err != nil {
		t.Fatal(err)
	}
	if stats["wan0"].Packets != 7 || stats["wan0"].Bytes != 123 {
		t.Fatalf("XDP stats missing: %+v", stats)
	}
}
