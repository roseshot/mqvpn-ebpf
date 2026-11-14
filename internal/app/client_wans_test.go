package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"strconv"
	"testing"
)

func TestWANListDoesNotUseTwoPathCeiling(t *testing.T) {
	list := make([]clientWAN, 80)
	for i := range list {
		list[i] = clientWAN{Interface: "wan" + stringFromInt(i)}
	}
	planned, err := planClientWANs(list, nil, "", "", "", "", false)
	if err != nil || len(planned) != 80 || planned[79].Interface != "wan79" {
		t.Fatalf("WAN list unexpectedly capped: len=%d err=%v", len(planned), err)
	}
	// The mp-quic-go library still has its own concurrency cap (64
	// in v0.3.1); this test checks only application config parsing.
}

func stringFromInt(n int) string {
	return strconv.Itoa(n)
}

func TestWANListCLIAndLegacyNormalization(t *testing.T) {
	var cli clientWANFlags
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
	out, err := planClientWANs(nil, cli, "", "", "", "", false)
	if err != nil || len(out) != 4 || out[3].Interface != "wan3" {
		t.Fatalf("repeatable CLI lost WAN4: %+v, %v", out, err)
	}
	old, err := planClientWANs(nil, nil, "192.0.2.2", "wan0",
		"198.51.100.2", "wan1", false)
	if err != nil || len(old) != 2 || old[1].Interface != "wan1" {
		t.Fatalf("legacy config lost: %+v %v", old, err)
	}
	single, err := planClientWANs(nil, nil, "", "", "", "", false)
	if err != nil || len(single) != 1 {
		t.Fatalf("default single WAN lost: %+v %v", single, err)
	}
}

func TestWANListRejectsAmbiguityAndDuplicates(t *testing.T) {
	tests := []struct {
		name string
		wans []clientWAN
	}{
		{"duplicate-source", []clientWAN{{SourceIP: "192.0.2.2", Interface: "wan0"}, {SourceIP: "192.0.2.2", Interface: "wan1"}}},
		{"duplicate-interface", []clientWAN{{SourceIP: "192.0.2.2", Interface: "wan0"}, {SourceIP: "198.51.100.2", Interface: "wan0"}}},
		{"missing-secondary", []clientWAN{{Interface: "wan0"}, {}}},
		{"invalid-IP", []clientWAN{{SourceIP: "bad", Interface: "wan0"}}},
		{"unspecified-IP", []clientWAN{{SourceIP: "0.0.0.0", Interface: "wan0"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planClientWANs(tc.wans, nil, "", "", "", "", false); err == nil {
				t.Fatal("invalid WAN binding accepted")
			}
		})
	}
	if _, err := planClientWANs([]clientWAN{{Interface: "wan0"}},
		nil, "", "", "", "", true); err == nil {
		t.Fatal("YAML and legacy CLI WAN conflict accepted")
	}
	if _, err := planClientWANs(nil,
		[]clientWAN{{SourceIP: "192.0.2.2", Interface: "wan0"}},
		"", "", "", "", true); err == nil {
		t.Fatal("repeated CLI --wan mixed with legacy flags")
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
	err = RunClient(context.Background(), []string{
		"--config", config,
		"--ca", "/missing/ca.crt", "--cert", "/missing/client.crt",
		"--key", "/missing/client.key",
	}, logger)
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("valid four-WAN YAML rejected before identity check: %v", err)
	}
	err = RunClient(context.Background(), []string{
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
		var w clientWANFlags
		if err := w.Set(bad); err == nil {
			t.Fatalf("invalid --wan %q accepted", bad)
		}
	}
}
