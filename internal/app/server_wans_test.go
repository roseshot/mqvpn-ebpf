package app

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	quic "github.com/qoke/mp-quic-go"
)

func fourServerWANs() []serverWAN {
	return []serverWAN{
		{Interface: "wan0", IP: "192.0.2.1"},
		{Interface: "wan1", IP: "198.51.100.1"},
		{Interface: "wan2", IP: "203.0.113.1"},
		{Interface: "wan3", IP: "192.0.2.5"},
	}
}

func TestServerWANMultiAddressValidation(t *testing.T) {
	config := ServerConfig{
		Listen: "0.0.0.0:8443",
		WANs: fourServerWANs(),
		Instances: []ServerInstance{sampleInstance("lab", "vpn.example.test", "mq0")},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid four-address wildcard config rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		change func(*ServerConfig)
	}{
		{"specific-listen", func(c *ServerConfig) { c.Listen = "192.0.2.1:8443" }},
		{"duplicate-interface", func(c *ServerConfig) { c.WANs[1].Interface = "wan0" }},
		{"duplicate-address", func(c *ServerConfig) { c.WANs[2].IP = "192.0.2.1" }},
		{"invalid-address", func(c *ServerConfig) { c.WANs[1].IP = "0.0.0.0" }},
		{"empty-interface", func(c *ServerConfig) { c.WANs[1].Interface = "" }},
		{"mixed-legacy", func(c *ServerConfig) { c.WANInterfaces = []string{"wan5"} }},
		{"family-mismatch", func(c *ServerConfig) { c.WANs[2].IP = "2001:db8::1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ServerConfig{
				Listen: "0.0.0.0:8443",
				WANs: fourServerWANs(),
				Instances: []ServerInstance{sampleInstance("lab", "vpn.example.test", "mq0")},
			}
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe Server WAN configuration accepted")
			}
		})
	}
}

func TestServerHTTP3MultiWANAddressAdvertisement(t *testing.T) {
	q := newSharedHTTP3Server(newServerMux(), fourServerWANs()...)
	if q.QUICConfig == nil || !q.QUICConfig.EnableAddressAdvertisement ||
		!q.QUICConfig.MultipathAutoAdvertise ||
		len(q.QUICConfig.MultipathAutoAddrs) != 4 {
		t.Fatalf("Server HTTP/3 did not advertise configured WANs: %+v", q.QUICConfig)
	}
	for i, item := range fourServerWANs() {
		if !q.QUICConfig.MultipathAutoAddrs[i].Equal(net.ParseIP(item.IP)) {
			t.Fatalf("advertisement order changed: %v", q.QUICConfig.MultipathAutoAddrs)
		}
	}
	if !newSharedHTTP3Server(newServerMux()).QUICConfig.EnableAddressAdvertisement {
		t.Fatal("Server must negotiate ADD_ADDRESS before a later WAN upgrade")
	}
}

func TestClientPerWANRemoteServerSelection(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8443}
	wans := []clientWAN{
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
	// Legacy secondary paths continue to use the handshake destination.
	legacy, err := selectServerTargets(server, wans, nil, false)
	if err != nil || legacy[3].String() != "192.0.2.1:8443" {
		t.Fatalf("legacy path selection broke: %v %+v", err, legacy)
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
	var flags clientWANFlags
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
	got, err := planClientWANs(nil, flags, "", "", "", "", false)
	if err != nil || len(got) != 4 || got[3].ServerIP != "192.0.2.5" {
		t.Fatalf("new Server IP CLI config lost: %+v %v", got, err)
	}
	if _, err := planClientWANs([]clientWAN{
		{SourceIP: "192.0.2.2", Interface: "wan0", ServerIP: "not-an-ip"},
	}, nil, "", "", "", "", false); err == nil {
		t.Fatal("invalid Server IP accepted")
	}
}
