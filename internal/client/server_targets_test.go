package client

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	quic "github.com/qoke/mp-quic-go"
)

func TestClientPerWANRemoteServerSelection(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8443}
	wans := []wanPath{
		{SourceIP: "192.0.2.2", Interface: "wan0"},
		{SourceIP: "198.51.100.2", Interface: "wan1"},
		{SourceIP: "203.0.113.2", Interface: "wan2"},
		{SourceIP: "192.0.2.6", Interface: "wan3"},
	}
	advertised := []quic.AdvertisedAddress{
		{ID: 0, Addr: netip.MustParseAddrPort("198.51.100.1:8443")},
		{ID: 1, Addr: netip.MustParseAddrPort("203.0.113.1:8443")},
		{ID: 2, Addr: netip.MustParseAddrPort("192.0.2.5:8443")},
	}
	targets, err := selectServerTargets(server, wans, advertised, true)
	if err != nil || len(targets) != 4 {
		t.Fatalf("Server address discovery failed: %v %+v", err, targets)
	}
	for i, want := range []string{"192.0.2.1:8443", "198.51.100.1:8443", "203.0.113.1:8443", "192.0.2.5:8443"} {
		if targets[i].String() != want {
			t.Errorf("WAN %d: got %s, want %s", i+1, targets[i], want)
		}
	}
	if _, err := selectServerTargets(server, wans, nil, true); err == nil {
		t.Fatal("Server advertisement required but absent")
	}
	// When no per-WAN destination is specified, all paths use the same
	// authenticated Server UDP endpoint.
	shared, err := selectServerTargets(server, wans, nil, false)
	if err != nil || shared[3].String() != "192.0.2.1:8443" {
		t.Fatalf("shared Server WAN target selection broke: %v %+v", err, shared)
	}
	wans[2].ServerIP = "203.0.113.1"
	pinned, err := selectServerTargets(server, wans, nil, false)
	if err != nil || pinned[2].IP.String() != "203.0.113.1" {
		t.Fatalf("pinned Server address ignored: %v %+v", err, pinned)
	}
	wans[0].ServerIP = "203.0.113.1"
	if _, err := selectServerTargets(server, wans, nil, false); err == nil ||
		!strings.Contains(err.Error(), "first WAN") {
		t.Fatalf("unsafe handshake destination override accepted: %v", err)
	}
}

func TestClientWANPinnedServerAndFlagSyntax(t *testing.T) {
	var flags wanFlags
	for _, item := range []string{
		"192.0.2.2@wan0=192.0.2.1",
		"198.51.100.2@wan1=198.51.100.1",
		"203.0.113.2@wan2=203.0.113.1",
		"192.0.2.6@wan3=192.0.2.5",
	} {
		if err := flags.Set(item); err != nil {
			t.Fatal(err)
		}
	}
	got, err := planClientWANs(nil, flags)
	if err != nil || len(got) != 4 || got[3].ServerIP != "192.0.2.5" {
		t.Fatalf("new Server IP CLI config lost: %+v %v", got, err)
	}
	if _, err := planClientWANs([]wanPath{
		{SourceIP: "192.0.2.2", Interface: "wan0", ServerIP: "not-an-ip"},
	}, nil); err == nil {
		t.Fatal("invalid Server IP accepted")
	}
}
