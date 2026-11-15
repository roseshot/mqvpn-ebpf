package client

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
)

func TestWANListDoesNotUseTwoPathCeiling(t *testing.T) {
	list := make([]wanPath, 80)
	for i := range list {
		list[i] = wanPath{Interface: "wan" + stringFromInt(i)}
	}
	planned, err := planClientWANs(list, nil)
	if err != nil || len(planned) != 80 || planned[79].Interface != "wan79" {
		t.Fatalf("WAN list unexpectedly capped: len=%d err=%v", len(planned), err)
	}
	// The mp-quic-go library still has its own concurrency cap (64
	// in v0.3.1); this test checks only application config parsing.
}

func stringFromInt(n int) string {
	return strconv.Itoa(n)
}

func TestWANListCLIAndDefaultSelection(t *testing.T) {
	var cli wanFlags
	for _, spec := range []string{
		"192.0.2.2@wan0",
		"198.51.100.2@wan1",
		"203.0.113.2@wan2",
		"192.0.2.6@wan3",
	} {
		if err := cli.Set(spec); err != nil {
			t.Fatal(err)
		}
	}
	out, err := planClientWANs(nil, cli)
	if err != nil || len(out) != 4 || out[3].Interface != "wan3" {
		t.Fatalf("repeatable CLI lost WAN4: %+v, %v", out, err)
	}
	single, err := planClientWANs(nil, nil)
	if err != nil || len(single) != 1 || single[0] != (wanPath{}) {
		t.Fatalf("default single WAN lost: %+v %v", single, err)
	}
}

func TestWANListRejectsAmbiguityAndDuplicates(t *testing.T) {
	tests := []struct {
		name string
		wans []wanPath
	}{
		{"duplicate-source", []wanPath{{SourceIP: "192.0.2.2", Interface: "wan0"}, {SourceIP: "192.0.2.2", Interface: "wan1"}}},
		{"duplicate-interface", []wanPath{{SourceIP: "192.0.2.2", Interface: "wan0"}, {SourceIP: "198.51.100.2", Interface: "wan0"}}},
		{"missing-secondary", []wanPath{{Interface: "wan0"}, {}}},
		{"invalid-IP", []wanPath{{SourceIP: "bad", Interface: "wan0"}}},
		{"unspecified-IP", []wanPath{{SourceIP: "0.0.0.0", Interface: "wan0"}}},
		{"multicast-source-v4", []wanPath{{SourceIP: "239.1.2.3", Interface: "wan0"}}},
		{"multicast-source-v6", []wanPath{{SourceIP: "ff02::1", Interface: "wan0"}}},
		{"mapped-multicast-source", []wanPath{{SourceIP: "::ffff:239.1.2.3", Interface: "wan0"}}},
		{"mapped-unspecified-source", []wanPath{{SourceIP: "::ffff:0.0.0.0", Interface: "wan0"}}},
		{"mapped-multicast-server", []wanPath{{SourceIP: "192.0.2.2", Interface: "wan0", ServerIP: "::ffff:239.1.2.3"}}},
		{"mapped-ip-family-mismatch", []wanPath{{SourceIP: "::ffff:192.0.2.2", Interface: "wan0", ServerIP: "2001:db8::1"}}},
		{"interface-leading-space", []wanPath{{SourceIP: "192.0.2.2", Interface: " wan0"}}},
		{"interface-embedded-nul", []wanPath{{SourceIP: "192.0.2.2", Interface: "wan0\x00wrong"}}},
		{"interface-too-long", []wanPath{{SourceIP: "192.0.2.2", Interface: "ethernetlongname0"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planClientWANs(tc.wans, nil); err == nil {
				t.Fatal("invalid WAN binding accepted")
			}
		})
	}

}

func TestWANListMappedIPv4UsesIPv4SocketFamily(t *testing.T) {
	paths, err := planClientWANs([]wanPath{{
		SourceIP: "::ffff:192.0.2.2", Interface: "wan0", ServerIP: "198.51.100.1",
	}}, nil)
	if err != nil || len(paths) != 1 {
		t.Fatalf("mapped IPv4 source and IPv4 destination should share a socket family: %+v %v", paths, err)
	}
	if _, err := planClientWANs([]wanPath{
		{SourceIP: "192.0.2.2", Interface: "wan0"},
		{SourceIP: "::ffff:192.0.2.2", Interface: "wan1"},
	}, nil); err == nil {
		t.Fatal("native and IPv4-mapped aliases must count as duplicate source addresses")
	}
}

func TestWANListYAMLConfigFourPathsAndCLIOverride(t *testing.T) {
	config := writeClientTestYAML(t, "server: vpn.example.com\n"+
		"wans:\n"+
		"  - source_ip: 192.0.2.2\n    interface: wan0\n"+
		"  - source_ip: 198.51.100.2\n    interface: wan1\n"+
		"  - source_ip: 203.0.113.2\n    interface: wan2\n"+
		"  - source_ip: 192.0.2.6\n    interface: wan3\n")
	cfg, err := loadClientFile(config)
	if err != nil || len(cfg.WANs) != 4 {
		t.Fatalf("YAML wans not decoded: %+v %v", cfg, err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Missing credentials are checked only after WAN parsing, so the
	// expected CA error proves flags reached the correct validation stage.
	err = Run(context.Background(), []string{
		"--config", config,
		"--ca", "/missing/ca.crt", "--cert", "/missing/client.crt",
		"--key", "/missing/client.key",
	}, logger)
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("valid four-WAN YAML rejected before identity check: %v", err)
	}
	err = Run(context.Background(), []string{
		"--config", config,
		"--wan", "192.0.2.2@wan0",
		"--wan", "198.51.100.2@wan1",
		"--ca", "/missing/ca.crt", "--cert", "/missing/client.crt",
		"--key", "/missing/client.key",
	}, logger)
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("CLI WAN list override rejected: %v", err)
	}
}

func TestWANFlagBadSpec(t *testing.T) {
	for _, bad := range []string{"", "wan0", "@wan0", "192.0.2.2@", "192.0.2.2"} {
		var w wanFlags
		if err := w.Set(bad); err == nil {
			t.Fatalf("invalid --wan %q accepted", bad)
		}
	}
}
