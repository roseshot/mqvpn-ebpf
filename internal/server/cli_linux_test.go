//go:build linux

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
)

func writeTestServerYAML(t *testing.T, cfg Config, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	b, err := configfile.Marshal(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstanceCLISharedPortUpsertDelete(t *testing.T) {
	cfg, _ := testServerFiles(t)
	path := writeTestServerYAML(t, cfg, 0640)
	first := cfg.Instances[0]
	if err := runInstanceCLI([]string{
		"upsert", "--config", path, "--name", "edge-b",
		"--server-name", "edge-b.example.test", "--tun", "mq1",
		"--address", "10.77.0.1/24",
		"--peers", first.Peers, "--cert", first.Cert,
		"--key", first.Key, "--client-ca", first.ClientCA,
	}, discardServerTestLogger()); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Listen != cfg.Listen || len(loaded.Instances) != 2 {
		t.Fatalf("shared listener changed: %+v", loaded)
	}
	if loaded.Instances[1].ServerName != "edge-b.example.test" {
		t.Fatal(loaded)
	}
	if err := runInstanceCLI([]string{
		"upsert", "--config", path, "--name", "edge-b", "--tun", "mq2",
	}, discardServerTestLogger()); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Instances[1].TUN != "mq2" || loaded.Instances[1].ServerName != "edge-b.example.test" {
		t.Fatal("partial update discarded SNI", loaded)
	}
	if err := runInstanceCLI([]string{
		"delete", "--config", path, "--name", "edge-b",
	}, discardServerTestLogger()); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadServerConfig(path)
	if err != nil || len(loaded.Instances) != 1 {
		t.Fatalf("%+v %v", loaded, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("file mode changed: %v %v", info, err)
	}
}

func TestInstanceCLIDuplicateSNIAtomicReject(t *testing.T) {
	cfg, _ := testServerFiles(t)
	path := writeTestServerYAML(t, cfg, 0600)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := cfg.Instances[0]
	err = runInstanceCLI([]string{
		"upsert", "--config", path, "--name", "edge-b",
		"--server-name", "edge-a.example.test", "--tun", "mq1",
		"--address", "10.77.0.1/24",
		"--peers", first.Peers, "--cert", first.Cert,
		"--key", first.Key, "--client-ca", first.ClientCA,
	}, discardServerTestLogger())
	if err == nil {
		t.Fatal("duplicated SNI should be rejected")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("failed YAML CLI changed persisted config")
	}
}

func TestRejectUnknownInstanceListenFlag(t *testing.T) {
	cfg, _ := testServerFiles(t)
	path := writeTestServerYAML(t, cfg, 0600)
	if err := runInstanceCLI([]string{
		"upsert", "--config", path, "--name", "edge-a", "--listen", ":4434",
	}, discardServerTestLogger()); err == nil {
		t.Fatal("unknown per-instance --listen flag accepted")
	}
}

func TestInstanceCLIUpdatesManagedTunAddressAndMTU(t *testing.T) {
	cfg, _ := testServerFiles(t)
	path := writeTestServerYAML(t, cfg, 0600)
	if err := runInstanceCLI([]string{
		"upsert", "--config", path, "--name", "edge-a",
		"--address", "10.77.0.254/24", "--mtu", "1000",
	}, discardServerTestLogger()); err != nil {
		t.Fatal(err)
	}
	out, err := loadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Instances[0].Address != "10.77.0.254/24" || out.Instances[0].MTU != 1000 {
		t.Fatalf("managed TUN edit not persisted: %+v", out.Instances[0])
	}
}
