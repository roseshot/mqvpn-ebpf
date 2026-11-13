//go:build linux

package wan

import (
	"net"
	"strings"
	"testing"
)

func TestResolveSource(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4433}
	ip, err := ResolveSource("127.0.0.1", "lo", peer)
	if err != nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("loopback source: %v, %v", ip, err)
	}
	ip, err = ResolveSource("", "lo", peer)
	if err != nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("choose unique address from interface: %v, %v", ip, err)
	}
	if _, err := ResolveSource("192.0.2.123", "lo", peer); err == nil {
		t.Fatal("address not present on interface must fail")
	}
	if _, err := ResolveSource("::1", "", peer); err == nil {
		t.Fatal("different IP family must fail")
	}
	if _, err := ResolveSource("", "", peer); err == nil {
		t.Fatal("missing source spec must fail")
	}
	if _, err := ResolveSource("", "nonexistent-mqvpn-interface", peer); err == nil {
		t.Fatal("unknown interface must fail")
	}
	if _, err := ResolveSource("bad-ip", "", peer); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid IP should fail, got %v", err)
	}
}
