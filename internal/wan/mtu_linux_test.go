//go:build linux

package wan

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestSourceUnderlayLoopbackAndErrors(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("Linux loopback not found: %v", err)
	}
	got, err := SourceUnderlay(net.ParseIP("127.0.0.1"), "lo")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "lo" || got.MTU != iface.MTU || got.IPv6 {
		t.Fatalf("source interface MTU mismatch: %+v", got)
	}
	resolved, err := SourceUnderlay(net.ParseIP("127.0.0.1"), "")
	if err != nil || resolved.Name != "lo" {
		t.Fatalf("source auto-discovery: %+v %v", resolved, err)
	}
	if _, err := SourceUnderlay(nil, "lo"); err == nil {
		t.Fatal("nil WAN source accepted")
	}
	if _, err := SourceUnderlay(net.ParseIP("192.0.2.200"), "lo"); err == nil {
		t.Fatal("foreign WAN IP accepted")
	}
}

func TestDefaultRouteFilter(t *testing.T) {
	if !isDefaultRoute(netlink.Route{}) {
		t.Fatal("nil destination should be default")
	}
	_, nondefault, _ := net.ParseCIDR("192.0.2.0/24")
	if isDefaultRoute(netlink.Route{Dst: nondefault}) {
		t.Fatal("nondefault network selected")
	}
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	if !isDefaultRoute(netlink.Route{Dst: def}) {
		t.Fatal("explicit default not found")
	}
}

func TestServerUnderlaysRejectMissingInterface(t *testing.T) {
	if _, err := ServerUnderlays("0.0.0.0:443", []string{"definitely-no-such-nic"}); err == nil {
		t.Fatal("nonexistent configured WAN interface accepted")
	}
}
