//go:build linux

package tcebpf

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Counters are kernel-maintained per-CPU (per direction). Order matches
// struct tun_counters in bpf/tun_tc.c.
type Counters struct {
	Packets        uint64
	Bytes          uint64
	IPv4           uint64
	IPv6           uint64
	SYN            uint64
	Clamped        uint64
	Oversize       uint64
	ParseErrors    uint64
	ChecksumErrors uint64
}

func (c *Counters) add(v Counters) {
	c.Packets += v.Packets
	c.Bytes += v.Bytes
	c.IPv4 += v.IPv4
	c.IPv6 += v.IPv6
	c.SYN += v.SYN
	c.Clamped += v.Clamped
	c.Oversize += v.Oversize
	c.ParseErrors += v.ParseErrors
	c.ChecksumErrors += v.ChecksumErrors
}

type DirectionCounters struct {
	Ingress Counters
	Egress  Counters
}

// Attachment owns two TCX links and all maps/programs for exactly one TUN.
// No shell or iproute2 utility is executed. The caller closes the links
// before disposing of the interface to avoid dangling policies on re-attach.
type Attachment struct {
	mu      sync.Mutex
	col     *ebpf.Collection
	ingress link.Link
	egress  link.Link
	stats   *ebpf.Map
}

// Attach performs the kernel operation; the caller enforces auto/required
// error policy. TCX requires Linux 6.6+ and appropriate BPF permissions.
func Attach(ifname string, cfg Config, mtu int) (*Attachment, error) {
	norm, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	if !norm.Enabled() {
		return nil, nil
	}
	limits, err := EffectiveLimits(mtu, norm.MSSClamp)
	if err != nil {
		return nil, err
	}
	if norm.Stats {
		limits.Stats = 1
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("TUN TC interface %q: %w", ifname, err)
	}
	spec, err := LoadSpec(norm.Object)
	if err != nil {
		return nil, fmt.Errorf("load TUN TC eBPF ELF: %w", err)
	}
	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create TUN TC BPF collection: %w", err)
	}
	d := &Attachment{col: col, stats: col.Maps["tun_stats"]}
	configMap := col.Maps["tun_config"]
	if configMap == nil || d.stats == nil ||
		col.Programs["tc_mqvpn_ingress"] == nil || col.Programs["tc_mqvpn_egress"] == nil {
		_ = d.Close()
		return nil, errors.New("TC ELF must contain tun_config/tun_stats and tc_mqvpn_ingress/egress")
	}
	var key uint32
	if err := configMap.Put(key, limits); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("configure TUN MSS/MTU map: %w", err)
	}
	d.ingress, err = link.AttachTCX(link.TCXOptions{
		Program:   col.Programs["tc_mqvpn_ingress"],
		Interface: iface.Index, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("attach TCX ingress on TUN %s (kernel >= 6.6 and BPF permissions required): %w", ifname, err)
	}
	d.egress, err = link.AttachTCX(link.TCXOptions{
		Program:   col.Programs["tc_mqvpn_egress"],
		Interface: iface.Index, Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("attach TCX egress on TUN %s (kernel >= 6.6 and BPF permissions required): %w", ifname, err)
	}
	return d, nil
}

func (d *Attachment) Snapshot() (DirectionCounters, error) {
	if d == nil {
		return DirectionCounters{}, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stats == nil {
		return DirectionCounters{}, errors.New("TC statistics map closed")
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return DirectionCounters{}, fmt.Errorf("read possible CPUs: %w", err)
	}
	var out DirectionCounters
	for dir := uint32(0); dir < 2; dir++ {
		perCPU := make([]Counters, cpus)
		if err := d.stats.Lookup(dir, &perCPU); err != nil {
			return DirectionCounters{}, fmt.Errorf("read TC stats direction %d: %w", dir, err)
		}
		var sum Counters
		for _, s := range perCPU {
			sum.add(s)
		}
		if dir == 0 {
			out.Ingress = sum
		} else {
			out.Egress = sum
		}
	}
	return out, nil
}

func (d *Attachment) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var errs []error
	// Close both links first, then release the BPF maps/programs.
	if d.egress != nil {
		if e := d.egress.Close(); e != nil {
			errs = append(errs, e)
		}
		d.egress = nil
	}
	if d.ingress != nil {
		if e := d.ingress.Close(); e != nil {
			errs = append(errs, e)
		}
		d.ingress = nil
	}
	if d.col != nil {
		d.col.Close()
		d.col = nil
	}
	d.stats = nil
	return errors.Join(errs...)
}
