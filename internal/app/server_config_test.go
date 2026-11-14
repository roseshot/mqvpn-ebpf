package app

import (
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleInstance(name, serverName, tunName string) ServerInstance {
	return ServerInstance{
		Name: name, ServerName: serverName, TUN: tunName, Address: "10.77.0.1/24",
		Peers: "peers.yaml", Cert: "server.crt", Key: "server.key", ClientCA: "ca.crt",
	}
}

func TestSharedUDPConfigAndDefaults(t *testing.T) {
	cfg := ServerConfig{
		Instances: []ServerInstance{
			sampleInstance("a", "a.example.test", "mq0"),
			sampleInstance("b", "b.example.test", "mq1"),
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != defaultServerListen {
		t.Fatalf("expected UDP/443, got %q", cfg.Listen)
	}
	if cfg.Instances[0].TC == nil || cfg.Instances[0].TC.Mode != "auto" || !cfg.Instances[0].TC.Stats || cfg.Instances[0].TC.MSSClamp != "auto" || cfg.Instances[0].TC.Object != "" {
		t.Fatal("default TCX must use bundled ELF, auto MSS clamp and stats")
	}
	if cfg.Instances[0].Path != defaultPath || cfg.Instances[1].MaxFrame != 0 || cfg.Instances[0].MTU != 0 {
		t.Fatal("auto MTU/frame must stay omitted until runtime WAN discovery")
	}
}

func TestDuplicateSNIAndTUNRejected(t *testing.T) {
	first := sampleInstance("a", "a.example.test", "mq0")
	for _, second := range []ServerInstance{
		sampleInstance("b", "b.example.test", "mq0"),
		sampleInstance("b", "a.example.test", "mq1"),
		sampleInstance("a", "b.example.test", "mq1"),
	} {
		cfg := ServerConfig{Listen: ":4433", Instances: []ServerInstance{first, second}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted conflicting instance %+v", second)
		}
	}
}
func TestMissingSNIRejected(t *testing.T) {
	cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("a", "a.example.test", "mq0")}}
	if err := cfg.Validate(); err != nil || cfg.Listen != defaultServerListen {
		t.Fatalf("default listen: %q, %v", cfg.Listen, err)
	}
	cfg.Instances[0].ServerName = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server_name") {
		t.Fatal(err)
	}
	for _, s := range []string{"10.77.0.1", "*.vpn.test", "a", "a..test", "-a.test", "a.test."} {
		if err := validateSNI(s); err == nil {
			t.Fatalf("bad SNI accepted %q", s)
		}
	}
}

func TestRejectUnknownInstanceListenerAndNonYAML(t *testing.T) {
	dir := t.TempDir()
	for path, text := range map[string]string{
		filepath.Join(dir, "bad.yaml"):    "listen: ':4433'\ninstances:\n  - name: a\n    server_name: a.example.test\n    listen: ':4434'\n    tun: mq0\n    peers: p.yaml\n    cert: a.crt\n    key: a.key\n    client_ca: ca.crt\n",
		filepath.Join(dir, "config.json"): `{"listen":":4433","instances":[]}`,
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadServerConfig(path); err == nil {
			t.Fatalf("invalid config accepted %q", path)
		}
	}
}

func TestExplicitSharedUDPPortPreserved(t *testing.T) {
	cfg := ServerConfig{Listen: "127.0.0.1:54433", Instances: []ServerInstance{sampleInstance("a", "a.example.test", "mq0")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:54433" {
		t.Fatalf("explicit port changed to %q", cfg.Listen)
	}
}

func TestTCPFallbackEnabledDefaultPortAndExplicitPort(t *testing.T) {
	cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("vpn", "vpn.example.test", "mq0")}}
	cfg.TCPFallback = TCPFallbackConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:443" || cfg.TCPFallback.Listen != "0.0.0.0:443" {
		t.Fatalf("expected UDP and TCP to default independently to 443: %+v", cfg)
	}
	cfg.TCPFallback.Listen = "127.0.0.1:8443"
	if err := cfg.Validate(); err != nil || cfg.TCPFallback.Listen != "127.0.0.1:8443" {
		t.Fatalf("explicit TCP listener rejected: %+v %v", cfg, err)
	}
}

func TestTCPFallbackDisabledListenerRejected(t *testing.T) {
	cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("vpn", "vpn.example.test", "mq0")}}
	cfg.TCPFallback.Listen = "127.0.0.1:8443"
	if err := cfg.Validate(); err == nil {
		t.Fatal("disabled TCP listener configuration accepted")
	}
	cfg.TCPFallback.Enabled = true
	for _, listen := range []string{":0", "not-a-listen", ":70000"} {
		cfg.TCPFallback.Listen = listen
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid TCP listen %q accepted", listen)
		}
	}
}

func TestInstanceAddressAndMTUValidation(t *testing.T) {
	for _, tc := range []struct {
		address    string
		mtu, frame int
		valid      bool
	}{
		{"10.77.0.1/24", 0, 0, true},
		{"fd77::1/64", 1280, 1300, true},
		{"", 1100, 1160, false},
		{"10.77.0.1", 1100, 1160, false},
		{"10.77.0.1/24", 1200, 1160, false},
		{"fd77::1/64", 1100, 1160, false},
		{"fd77::1/64", 1280, 1160, false},
	} {
		inst := sampleInstance("a", "a.example.test", "mq0")
		inst.Address = tc.address
		inst.MTU = tc.mtu
		inst.MaxFrame = tc.frame
		cfg := ServerConfig{Instances: []ServerInstance{inst}}
		err := cfg.Validate()
		if (err == nil) != tc.valid {
			t.Fatalf("address %q mtu %d max-frame %d: %v", tc.address, tc.mtu, tc.frame, err)
		}
	}
}

func TestHighMTUProfilesAndPeerFrameSize(t *testing.T) {
	for _, tc := range []struct {
		address    string
		mtu, frame int
	}{
		{"10.77.0.1/24", 1360, 1374},
		{"10.77.0.1/24", 1400, 1414},
		{"fd77::1/64", 1420, 1434},
	} {
		inst := sampleInstance("mtu", "mtu.example.test", "mq0")
		inst.Address = tc.address
		inst.MTU = tc.mtu
		inst.MaxFrame = tc.frame
		cfg := ServerConfig{Instances: []ServerInstance{inst}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("TUN MTU %d and max_frame %d unexpectedly rejected: %v", tc.mtu, tc.frame, err)
		}
	}
}

func TestServerTCConfigWithoutLegacyObjectRequirements(t *testing.T) {
	inst := sampleInstance("tc", "tc.example.test", "mq0")
	inst.TC = &tcebpf.Config{MSSClamp: "auto", Stats: true}
	cfg := ServerConfig{Instances: []ServerInstance{inst}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Instances[0].TC.Mode != "auto" {
		t.Fatal("no TC mode must mean auto")
	}
	inst.TC = &tcebpf.Config{Mode: "off"}
	cfg = ServerConfig{Instances: []ServerInstance{inst}}
	if err := cfg.Validate(); err != nil || cfg.Instances[0].TC.Mode != "off" {
		t.Fatalf("off TC mode not respected: %v", err)
	}
	inst.TC = &tcebpf.Config{Object: "bpf/tun_tc.o", MSSClamp: "auto", Stats: true}
	cfg = ServerConfig{Instances: []ServerInstance{inst}}
	if err := cfg.Validate(); err != nil || cfg.Instances[0].TC.Mode != "auto" {
		t.Fatalf("object override unexpectedly required fail-closed TC: %v", err)
	}
	inst.TC = &tcebpf.Config{Mode: "required", MSSClamp: "auto", Stats: true}
	cfg = ServerConfig{Instances: []ServerInstance{inst}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit required mode: %v", err)
	}
	if cfg.Instances[0].TC.Object != "" {
		t.Fatal("bundled ELF should not require object")
	}
}

func TestInstancePushRoutesValidatedAndCanonical(t *testing.T) {
	cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("a", "a.example.test", "mq0")}}
	cfg.Instances[0].PushRoutes = []string{"192.168.99.6/24", "0.0.0.0/0", "2001:db8:2::1/64"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	got := cfg.Instances[0].PushRoutes
	if len(got) != 3 || got[0] != "192.168.99.0/24" || got[1] != "0.0.0.0/0" || got[2] != "2001:db8:2::/64" {
		t.Fatalf("routes not normalized: %v", got)
	}
	for _, bad := range [][]string{
		{"bad"},
		{"10.77.0.0/24", "10.77.0.13/24"},
		{"224.0.0.0/4"},
		{"127.0.0.0/8"},
	} {
		c := ServerConfig{Instances: []ServerInstance{sampleInstance("a", "a.example.test", "mq0")}}
		c.Instances[0].PushRoutes = bad
		if err := c.Validate(); err == nil {
			t.Fatalf("unsafe push_routes accepted: %v", bad)
		}
	}
}

func TestServerMasquePathDefaultAndCustom(t *testing.T) {
	inst := sampleInstance("a", "a.example.test", "mq0")
	cfg := ServerConfig{Instances: []ServerInstance{inst}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Instances[0].Path != defaultPath {
		t.Fatalf("server default path changed: %q", cfg.Instances[0].Path)
	}
	for _, good := range []string{"/corp/connect/", "/vpn", "/tenant-a/masque/ethernet/"} {
		inst.Path = good
		cfg = ServerConfig{Instances: []ServerInstance{inst}}
		if err := cfg.Validate(); err != nil || cfg.Instances[0].Path != good {
			t.Fatalf("custom path %q rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"vpn", "//tenant", "/tenant//path", "/tenant/../path", "/tenant?query=1", "/tenant#fragment", "/tenant%2fpath"} {
		inst.Path = bad
		cfg = ServerConfig{Instances: []ServerInstance{inst}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe path %q accepted", bad)
		}
	}
}

func TestSingleInstanceIPCertificateIdentity(t *testing.T) {
	for _, identity := range []string{"198.51.100.7", "2001:db8::7"} {
		cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("only", identity, "mq0")}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("single IP identity %s: %v", identity, err)
		}
		cfg.Instances = append(cfg.Instances, sampleInstance("second", "other.example.test", "mq1"))
		if err := cfg.Validate(); err == nil {
			t.Fatalf("multi-instance IP identity %s accepted", identity)
		}
	}
	for _, ip := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "127.0.0.1", "fe80::1%eth0"} {
		cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("only", ip, "mq0")}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unusable IP identity %s accepted", ip)
		}
	}
}

func TestInstancePushDNSValidation(t *testing.T) {
	cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("dns", "dns.example.test", "mq0")}}
	cfg.Instances[0].PushDNS = []string{"10.77.0.1", "fd77::53"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Instances[0].PushDNS; len(got) != 2 || got[0] != "10.77.0.1" || got[1] != "fd77::53" {
		t.Fatalf("server DNS push normalized unexpectedly: %v", got)
	}
	for _, bad := range [][]string{
		{"dns.example.test"}, {"1.1.1.1:53"}, {"0.0.0.0"}, {"ff02::1"},
		{"10.77.0.1", "10.77.0.1"}, {"10.77.0.1\r\nX-Injected: yes"},
	} {
		test := ServerConfig{Instances: []ServerInstance{sampleInstance("dns", "dns.example.test", "mq0")}}
		test.Instances[0].PushDNS = bad
		if err := test.Validate(); err == nil {
			t.Fatalf("invalid push_dns accepted: %v", bad)
		}
	}
}

func TestGo127QualifiedSNIRequiresValidTerminalLabel(t *testing.T) {
	for _, domain := range []string{"edge.example.com", "tenant.co.uk"} {
		if err := validateSNI(domain); err != nil {
			t.Fatalf("valid multi-label DNS SNI %q rejected: %v", domain, err)
		}
	}
	for _, domain := range []string{"edge", "edge.", ".edge", "edge..com", "192.0.2.1"} {
		if err := validateSNI(domain); err == nil {
			t.Fatalf("invalid DNS SNI %q accepted", domain)
		}
	}
}
