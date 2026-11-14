//go:build linux

package routepush

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

type fakeKernel struct {
	links      map[string]netlink.Link
	added      []netlink.Route
	deleted    []netlink.Route
	failPrefix string
}

func newFakeKernel() *fakeKernel {
	wan := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 3}}
	tun := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "mq0", Index: 8}}
	return &fakeKernel{links: map[string]netlink.Link{"eth0": wan, "mq0": tun}}
}
func (f *fakeKernel) LinkByName(n string) (netlink.Link, error) {
	if l := f.links[n]; l != nil {
		return l, nil
	}
	return nil, errors.New("link missing")
}
func (f *fakeKernel) LinkByIndex(idx int) (netlink.Link, error) {
	for _, l := range f.links {
		if l.Attrs().Index == idx {
			return l, nil
		}
	}
	return nil, errors.New("index missing")
}
func (f *fakeKernel) RouteGetWithOptions(dst net.IP, _ *netlink.RouteGetOptions) ([]netlink.Route, error) {
	// Model Linux longest-prefix route selection: /32 server pin wins
	// over /0 pushed TUN, preserving the live transport.
	best := netlink.Route{LinkIndex: 3, Gw: net.ParseIP("192.0.2.1"), Table: mainTable}
	bestBits := -1
	for _, r := range f.added {
		if r.Dst.Contains(dst) {
			bits, _ := r.Dst.Mask.Size()
			if bits > bestBits {
				bestBits = bits
				best = r
			}
		}
	}
	return []netlink.Route{best}, nil
}
func (f *fakeKernel) RouteAdd(r *netlink.Route) error {
	if f.failPrefix == r.Dst.String() {
		return errors.New("injected route failure")
	}
	for _, p := range f.added {
		if p.Dst.String() == r.Dst.String() {
			return errors.New("file exists")
		}
	}
	f.added = append(f.added, *r)
	return nil
}
func (f *fakeKernel) RouteDel(r *netlink.Route) error {
	for i, p := range f.added {
		if p.Dst.String() == r.Dst.String() {
			f.added = append(f.added[:i], f.added[i+1:]...)
			f.deleted = append(f.deleted, *r)
			return nil
		}
	}
	return errors.New("no such route")
}
func (f *fakeKernel) RouteListFiltered(_ int, r *netlink.Route, _ uint64) ([]netlink.Route, error) {
	var result []netlink.Route
	for _, x := range f.added {
		if x.Dst.String() == r.Dst.String() && x.Table == r.Table && x.LinkIndex == r.LinkIndex {
			result = append(result, x)
		}
	}
	return result, nil
}
func TestGuardPinsServerBeforeDefaultAndCleansOwnedRoutes(t *testing.T) {
	k := newFakeKernel()
	push, err := Parse([]string{"0.0.0.0/0", "10.50.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	remote := net.ParseIP("198.51.100.10")
	source := net.ParseIP("192.0.2.20")
	guard, err := protectWithKernel(k, remote, source, "eth0", "mq0", push, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.added) != 1 || k.added[0].Dst.String() != "198.51.100.10/32" || k.added[0].LinkIndex != 3 {
		t.Fatalf("server not pinned on WAN before TUN route: %+v", k.added)
	}
	if err := guard.Install("mq0", push); err != nil {
		t.Fatal(err)
	}
	if len(k.added) != 4 || k.added[1].Dst.String() != "0.0.0.0/1" || k.added[2].Dst.String() != "128.0.0.0/1" || k.added[1].LinkIndex != 8 {
		t.Fatalf("pushed route missing: %+v", k.added)
	}
	resolved, _ := k.RouteGetWithOptions(remote, nil)
	if resolved[0].LinkIndex != 3 {
		t.Fatal("underlay leaked into tunnel")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if len(k.added) != 0 || len(k.deleted) != 4 {
		t.Fatalf("managed routes not cleaned: %+v", k.added)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestGuardRollsBackOnRouteConflict(t *testing.T) {
	k := newFakeKernel()
	push, _ := Parse([]string{"10.50.0.0/16", "10.60.0.0/16"})
	k.failPrefix = "10.60.0.0/16"
	g, err := protectWithKernel(k, net.ParseIP("198.51.100.10"), net.ParseIP("192.0.2.20"), "eth0", "mq0", push, false)
	if err != nil {
		t.Fatal(err)
	}
	err = g.Install("mq0", push)
	if err == nil || !strings.Contains(err.Error(), "10.60.0.0/16") {
		t.Fatalf("expected route failure: %v", err)
	}
	if len(k.added) != 0 {
		t.Fatalf("transaction did not roll back: %+v", k.added)
	}
}
func TestGuardRejectsDualWANDefaultAndExistingTUNUnderlay(t *testing.T) {
	k := newFakeKernel()
	push, _ := Parse([]string{"0.0.0.0/0"})
	_, err := protectWithKernel(k, net.ParseIP("198.51.100.10"), net.ParseIP("192.0.2.20"), "eth0", "mq0", push, true)
	if err == nil || !strings.Contains(err.Error(), "dual WAN") {
		t.Fatalf("dual WAN must not route via a single WAN pin: %v", err)
	}
	if len(k.added) != 0 {
		t.Fatal("conflict left routes behind")
	}
	// Underlay resolution to the VPN TUN is rejected before mutating FIB.
	delete(k.links, "eth0")
	k.links["mq0"].Attrs().Index = 3
	_, err = protectWithKernel(k, net.ParseIP("198.51.100.10"), net.ParseIP("192.0.2.20"), "", "mq0", push, false)
	if err == nil {
		t.Fatal("underlay via tunnel accepted")
	}
}

func TestDNSHostRoutesShareOwnedGuardAndUnderlayProtection(t *testing.T) {
	k := newFakeKernel()
	dns := []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("2001:db8::53")}
	pushed := WithDNSHostRoutes(nil, dns, true)
	g, err := protectWithKernel(k, net.ParseIP("198.51.100.10"), net.ParseIP("192.0.2.20"), "eth0", "mq0", pushed, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Install("mq0", pushed); err != nil {
		t.Fatal(err)
	}
	if len(k.added) != 3 || k.added[1].Dst.String() != "10.77.0.1/32" ||
		k.added[2].Dst.String() != "2001:db8::53/128" {
		t.Fatalf("DNS host routes must use TUN: %+v", k.added)
	}
	route, _ := k.RouteGetWithOptions(net.ParseIP("198.51.100.10"), nil)
	if route[0].LinkIndex != 3 {
		t.Fatalf("VPN underlay redirected by DNS: %+v", route)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if len(k.added) != 0 {
		t.Fatalf("DNS route cleanup left routes: %+v", k.added)
	}
}
func TestDNSHostRouteConflictDoesNotHijackServerPin(t *testing.T) {
	k := newFakeKernel()
	remote := net.ParseIP("198.51.100.10")
	pushed := WithDNSHostRoutes(nil, []netip.Addr{netip.MustParseAddr("198.51.100.10")}, true)
	g, err := protectWithKernel(k, remote, net.ParseIP("192.0.2.20"), "eth0", "mq0", pushed, false)
	if err != nil {
		t.Fatal(err)
	}
	err = g.Install("mq0", pushed)
	if err == nil {
		t.Fatal("DNS host route may not override WAN server IP pin")
	}
	if len(k.added) != 0 {
		t.Fatalf("conflict left managed routes: %+v", k.added)
	}
}
