package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeClientTestYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClientCompactConfigAndDefaultEndpoint(t *testing.T) {
	path := writeClientTestYAML(t, "server: tenant.vpn.example.com\naddress: 10.77.0.2/24\nca: /etc/ca.crt\ncert: /etc/client.crt\nkey: /etc/client.key\n")
	cfg, err := loadClientFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "tenant.vpn.example.com" || cfg.Address != "10.77.0.2/24" || cfg.TUN != "" || cfg.SourceInterface != "" {
		t.Fatalf("unexpected client defaults %+v", cfg)
	}
	endpoint, err := planClientEndpoint(cfg.Server, cfg.Path, cfg.ConnectIP)
	if err != nil || endpoint.dialAddress != "tenant.vpn.example.com:443" || endpoint.serverName != "tenant.vpn.example.com" || !strings.HasSuffix(endpoint.requestURL, defaultPath) {
		t.Fatalf("invalid compact endpoint %+v: %v", endpoint, err)
	}
}

func TestClientYAMLStrictValidation(t *testing.T) {
	for _, raw := range []string{
		"server: tenant.example.com\nserver: other.example.com\n",
		"server: tenant.example.com\nunknown_option: true\n",
		"server: tenant.example.com\nurl: https://tenant.example.com/test\n",
		"server: tenant.example.com\nserver_name: tenant.example.com\n",
	} {
		if _, err := loadClientFile(writeClientTestYAML(t, raw)); err == nil {
			t.Fatalf("removed/invalid YAML accepted: %q", raw)
		}
	}
}

func TestClientYAMLAndCLIOverrideBeforeNetworking(t *testing.T) {
	path := writeClientTestYAML(t, "server: 198.51.100.10\naddress: 10.77.0.2/24\nca: /missing/ca.crt\ncert: /missing/client.crt\nkey: /missing/client.key\n")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := RunClient(context.Background(), []string{"--config", path}, logger)
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("IP SAN server target must pass endpoint validation before CA check: %v", err)
	}
	err = RunClient(context.Background(), []string{"--config", path, "--server", "tenant.vpn.example.com"}, logger)
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("CLI DNS server override ignored: %v", err)
	}
}

func TestClientYAMLTCPAndTCPolicy(t *testing.T) {
	path := writeClientTestYAML(t, "server: tenant.example.com\naddress: 10.77.0.2/24\ntc:\n  mss_clamp: auto\n  stats: false\n")
	cfg, err := loadClientFile(path)
	if err != nil || cfg.TC == nil || cfg.TC.MSSClamp != "auto" || cfg.TC.Stats == nil || *cfg.TC.Stats {
		t.Fatalf("TC YAML options lost: %+v %v", cfg, err)
	}
}
func TestClientConfigCanRequestDynamicAddress(t *testing.T) {
	cfg, err := loadClientFile(writeClientTestYAML(t, "server: tenant.vpn.example.com\nca: /etc/ca.crt\ncert: /etc/client.crt\nkey: /etc/client.key\n"))
	if err != nil || !dynamicAddressRequested(cfg.Address) {
		t.Fatalf("dynamic Tunnel IP defaults: %+v %v", cfg, err)
	}
}
func TestClientRoutePushConsentConfiguration(t *testing.T) {
	cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\naccept_routes: false\n"))
	if err != nil || cfg.AcceptRoutes == nil || *cfg.AcceptRoutes {
		t.Fatalf("Client opt-out not parsed: %+v %v", cfg, err)
	}
}
func TestClientYAMLMasquePathAndCLIOverride(t *testing.T) {
	cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\npath: /corp/connect/\n"))
	if err != nil || cfg.Path != "/corp/connect/" {
		t.Fatalf("client path YAML: %+v %v", cfg, err)
	}
	got, err := planClientEndpoint(cfg.Server, cfg.Path, "")
	if err != nil || !strings.HasSuffix(got.requestURL, "/corp/connect/") {
		t.Fatalf("YAML path: %+v %v", got, err)
	}
	got, err = planClientEndpoint(cfg.Server, "/cli/override/", "")
	if err != nil || !strings.HasSuffix(got.requestURL, "/cli/override/") {
		t.Fatalf("CLI path: %+v %v", got, err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = RunClient(context.Background(), []string{"--server", "vpn.example.com", "--path", "/invalid/../path"}, logger)
	if err == nil || !strings.Contains(err.Error(), "MASQUE") {
		t.Fatalf("invalid --path not rejected: %v", err)
	}
}

func TestClientReconnectConfiguration(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true}, {"false", false},
	} {
		cfg, err := loadClientFile(writeClientTestYAML(t,
			"server: vpn.example.com\nreconnect: "+tc.value+"\n"))
		if err != nil || cfg.Reconnect == nil || *cfg.Reconnect != tc.want {
			t.Fatalf("reconnect: %s parsed as %+v: %v", tc.value, cfg.Reconnect, err)
		}
	}
	cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\n"))
	if err != nil || cfg.Reconnect != nil {
		t.Fatalf("omitted reconnect must use the default true: %+v %v", cfg.Reconnect, err)
	}
}

func TestClientDNSConsentConfiguration(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true}, {"false", false},
	} {
		cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\naccept_dns: "+tc.value+"\n"))
		if err != nil || cfg.AcceptDNS == nil || *cfg.AcceptDNS != tc.want {
			t.Fatalf("accept_dns %s parsed incorrectly: %+v %v", tc.value, cfg.AcceptDNS, err)
		}
	}
	cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\n"))
	if err != nil || cfg.AcceptDNS != nil {
		t.Fatalf("omitted accept_dns should use default true: %+v %v", cfg.AcceptDNS, err)
	}
}

func TestClientDNSHostRoutesSwitch(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"true", true}, {"false", false},
	} {
		cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\ndns_routes: "+tc.raw+"\n"))
		if err != nil || cfg.DNSRoutes == nil || *cfg.DNSRoutes != tc.want {
			t.Fatalf("dns_routes %s parse: %+v %v", tc.raw, cfg.DNSRoutes, err)
		}
	}
	cfg, err := loadClientFile(writeClientTestYAML(t, "server: vpn.example.com\n"))
	if err != nil || cfg.DNSRoutes != nil {
		t.Fatalf("omitted dns_routes uses default true: %+v %v", cfg.DNSRoutes, err)
	}
}
