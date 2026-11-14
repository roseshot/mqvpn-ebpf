//go:build linux

package xdp

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// portDevice is abstracted for rootless tests. A live device owns one
// XDP counter program, its listener-port map, and statistics per WAN NIC.
type portDevice interface {
	ReplacePorts([]uint16) error
	Counters() (Counters, error)
	Close() error
}

type bpfDevice struct {
	mu         sync.Mutex
	collection *ebpf.Collection
	link       link.Link
	ports      *ebpf.Map
	stats      *ebpf.Map
	current    map[uint16]bool
}

// attachDevice is intentionally explicit: enabling XDP requires a compiled
// ELF and privileged BPF/link operations, but no CGO or libbpf at runtime.
func attachDevice(ifname string, cfg Config) (portDevice, error) {
	nic, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("find XDP interface %s: %w", ifname, err)
	}
	spec, err := LoadSpec(cfg.Object)
	if err != nil {
		return nil, fmt.Errorf("read BPF ELF: %w", err)
	}
	if err := validateXDPObject(spec); err != nil {
		return nil, fmt.Errorf("invalid XDP ELF %q: %w", cfg.Object, err)
	}
	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF program: %w", err)
	}
	program := col.Programs["xdp_mqvpn"]
	ports := col.Maps["instance_ports"]
	stats := col.Maps["xdp_stats"]
	flags := link.XDPDriverMode
	if cfg.Mode == "generic" {
		flags = link.XDPGenericMode
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program: program, Interface: nic.Index, Flags: flags,
	})
	if err != nil {
		col.Close()
		return nil, fmt.Errorf("attach XDP to %s: %w", ifname, err)
	}
	return &bpfDevice{collection: col, link: lnk, ports: ports, stats: stats, current: map[uint16]bool{}}, nil
}

func (d *bpfDevice) ReplacePorts(next []uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	target := make(map[uint16]bool, len(next))
	for _, p := range next {
		if p == 0 {
			return errors.New("UDP port 0 is not a valid XDP instance port")
		}
		target[p] = true
	}
	if len(target) > 1024 {
		return errors.New("too many XDP instance ports")
	}
	// Install additions before deleting removed entries. The XDP program
	// only observes packets and never redirects traffic from Go's UDP socket.
	for p := range target {
		if !d.current[p] {
			if err := d.ports.Update(p, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("register UDP port %d: %w", p, err)
			}
			d.current[p] = true
		}
	}
	for p := range d.current {
		if !target[p] {
			if err := d.ports.Delete(p); err != nil {
				return fmt.Errorf("remove UDP port %d: %w", p, err)
			}
			delete(d.current, p)
		}
	}
	return nil
}

func (d *bpfDevice) Close() error {
	if d.link != nil {
		_ = d.link.Close()
	}
	if d.collection != nil {
		d.collection.Close()
	}
	return nil
}

// Controller owns the NIC-level statistics program lifecycle. Go's UDP
// transport remains the only QUIC RX/TX implementation.
type Controller struct {
	devices map[string]portDevice
	cfg     Config
	ports   []uint16
	open    func(string, Config) (portDevice, error)
}

func NewController() *Controller {
	return &Controller{devices: map[string]portDevice{}, open: attachDevice}
}

func (c *Controller) Reconcile(next Config, ports []uint16) error {
	var err error
	next, err = next.Normalize()
	if err != nil {
		return err
	}
	if c.devices == nil {
		c.devices = map[string]portDevice{}
	}
	if c.open == nil {
		c.open = attachDevice
	}
	// Reloadable: port list and added/removed NICs. Replacing an already
	// attached XDP object/mode requires a deliberate daemon restart.
	if len(c.devices) > 0 && (next.Object != c.cfg.Object || next.Mode != c.cfg.Mode || next.ObjectChecksum != c.cfg.ObjectChecksum) && len(next.Interfaces) > 0 {
		return errors.New("XDP object/mode change requires daemon restart")
	}
	existing := make(map[string]bool, len(next.Interfaces))
	for _, name := range next.Interfaces {
		existing[name] = true
	}
	newDevices := make(map[string]portDevice)
	for _, name := range next.Interfaces {
		if _, ok := c.devices[name]; ok {
			continue
		}
		d, err := c.open(name, next)
		if err != nil {
			for _, n := range newDevices {
				_ = n.Close()
			}
			return fmt.Errorf("open new XDP interface %s: %w", name, err)
		}
		newDevices[name] = d
	}
	// Keep old state for best-effort map rollback on failure.
	changed := make([]portDevice, 0, len(c.devices)+len(newDevices))
	for _, d := range c.devices {
		if err := d.ReplacePorts(ports); err != nil {
			for _, prev := range changed {
				_ = prev.ReplacePorts(c.ports)
			}
			for _, fresh := range newDevices {
				_ = fresh.Close()
			}
			_ = d.ReplacePorts(c.ports)
			return err
		}
		changed = append(changed, d)
	}
	for _, d := range newDevices {
		if err := d.ReplacePorts(ports); err != nil {
			for _, prev := range changed {
				_ = prev.ReplacePorts(c.ports)
			}
			for _, fresh := range newDevices {
				_ = fresh.Close()
			}
			return err
		}
	}
	for name, d := range c.devices {
		if !existing[name] {
			_ = d.Close()
			delete(c.devices, name)
		}
	}
	for name, d := range newDevices {
		c.devices[name] = d
	}
	c.cfg = next
	c.ports = append([]uint16(nil), ports...)
	return nil
}

func (c *Controller) Close() error {
	for name, d := range c.devices {
		_ = d.Close()
		delete(c.devices, name)
	}
	c.cfg = Config{}
	c.ports = nil
	return nil
}

// Counters is the sum of per-CPU WAN ingress XDP counters.
// The xdp_stats map is mandatory in the current BPF object schema.
type Counters struct {
	Packets      uint64
	Bytes        uint64
	MatchedUDP   uint64
	MatchedBytes uint64
	VLAN         uint64
}

func (d *bpfDevice) Counters() (Counters, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return Counters{}, err
	}
	samples := make([]Counters, cpus)
	var index uint32
	if err := d.stats.Lookup(index, &samples); err != nil {
		return Counters{}, err
	}
	var result Counters
	for _, s := range samples {
		result.Packets += s.Packets
		result.Bytes += s.Bytes
		result.MatchedUDP += s.MatchedUDP
		result.MatchedBytes += s.MatchedBytes
		result.VLAN += s.VLAN
	}
	return result, nil
}
func (c *Controller) Snapshots() (map[string]Counters, error) {
	out := make(map[string]Counters, len(c.devices))
	var errs []error
	for name, d := range c.devices {
		stats, err := d.Counters()
		if err != nil {
			errs = append(errs, fmt.Errorf("XDP interface %s counters: %w", name, err))
			continue
		}
		out[name] = stats
	}
	return out, errors.Join(errs...)
}

// validateXDPObject enforces the only supported ELF schema before any
// privileged program/map load. Older XSKMAP dispatchers and statistics-less
// objects are not accepted: there is no AF_XDP backend to consume redirects.
func validateXDPObject(spec *ebpf.CollectionSpec) error {
	if spec == nil || spec.Programs["xdp_mqvpn"] == nil ||
		spec.Maps["instance_ports"] == nil || spec.Maps["xdp_stats"] == nil {
		return errors.New("XDP ELF requires xdp_mqvpn, instance_ports and xdp_stats")
	}
	if spec.Maps["xsks_map"] != nil {
		return errors.New("XDP ELF contains unsupported xsks_map redirect scaffold")
	}
	return nil
}
