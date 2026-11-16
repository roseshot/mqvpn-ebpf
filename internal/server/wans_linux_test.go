//go:build linux

package server

import (
	"net"
	"testing"

	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
)

func fourServerWANs() []wanPath {
	return []wanPath{
		{Interface: "wan0", IP: "192.0.2.1"},
		{Interface: "wan1", IP: "198.51.100.1"},
		{Interface: "wan2", IP: "203.0.113.1"},
		{Interface: "wan3", IP: "192.0.2.5"},
	}
}

func TestServerWANMultiAddressValidation(t *testing.T) {
	config := Config{
		Listen:    "0.0.0.0:8443",
		WANs:      fourServerWANs(),
		Instances: []Instance{sampleInstance("lab", "vpn.example.test", "mq0")},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid four-address wildcard config rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"specific-listen", func(c *Config) { c.Listen = "192.0.2.1:8443" }},
		{"duplicate-interface", func(c *Config) { c.WANs[1].Interface = "wan0" }},
		{"duplicate-address", func(c *Config) { c.WANs[2].IP = "192.0.2.1" }},
		{"invalid-address", func(c *Config) { c.WANs[1].IP = "0.0.0.0" }},
		{"empty-interface", func(c *Config) { c.WANs[1].Interface = "" }},
		{"family-mismatch", func(c *Config) { c.WANs[2].IP = "2001:db8::1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Listen:    "0.0.0.0:8443",
				WANs:      fourServerWANs(),
				Instances: []Instance{sampleInstance("lab", "vpn.example.test", "mq0")},
			}
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe Server WAN configuration accepted")
			}
		})
	}
}

func TestServerHTTP3MultiWANAddressAdvertisement(t *testing.T) {
	q := newSharedHTTP3Server(newMux(), vpnwire.SchedulerRoundRobin, fourServerWANs()...)
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
	if !newSharedHTTP3Server(newMux(), vpnwire.SchedulerRoundRobin).QUICConfig.EnableAddressAdvertisement {
		t.Fatal("Server must negotiate ADD_ADDRESS before a later WAN upgrade")
	}
}
