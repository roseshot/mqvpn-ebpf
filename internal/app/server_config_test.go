package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

func sampleInstance(name, serverName, tunName string) ServerInstance {
	return ServerInstance{
		Name: name, ServerName: serverName, TUN: tunName,Address:"10.77.0.1/24",
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
	if err := cfg.Validate(); err != nil { t.Fatal(err) }
	if cfg.Listen != defaultServerListen { t.Fatalf("expected UDP/443, got %q", cfg.Listen) }
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
		if err := cfg.Validate(); err == nil { t.Fatalf("accepted conflicting instance %+v", second) }
	}
}
func TestMissingSNIRejected(t *testing.T) {
	cfg := ServerConfig{Instances: []ServerInstance{sampleInstance("a", "a.example.test", "mq0")}}
	if err := cfg.Validate(); err != nil || cfg.Listen != defaultServerListen { t.Fatalf("default listen: %q, %v", cfg.Listen, err) }
	cfg.Instances[0].ServerName = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server_name") { t.Fatal(err) }
	for _, s := range []string{"10.77.0.1", "*.vpn.test", "a", "a..test", "-a.test", "a.test."} {
		if err := validateSNI(s); err == nil { t.Fatalf("bad SNI accepted %q", s) }
	}
}

func TestLegacyPerInstanceListenerAndJSONRejected(t *testing.T) {
	dir := t.TempDir()
	for path, text := range map[string]string{
		filepath.Join(dir, "bad.yaml"): "listen: ':4433'\ninstances:\n  - name: a\n    server_name: a.example.test\n    listen: ':4434'\n    tun: mq0\n    peers: p.yaml\n    cert: a.crt\n    key: a.key\n    client_ca: ca.crt\n",
		filepath.Join(dir, "old.json"): `{"listen":":4433","instances":[]}`,
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil { t.Fatal(err) }
		if _, err := loadServerConfig(path); err == nil { t.Fatalf("legacy file accepted %q", path) }
	}
}

func TestExplicitSharedUDPPortPreserved(t *testing.T) {
	cfg := ServerConfig{Listen: "127.0.0.1:54433", Instances: []ServerInstance{sampleInstance("a","a.example.test","mq0")}}
	if err := cfg.Validate(); err != nil { t.Fatal(err) }
	if cfg.Listen != "127.0.0.1:54433" { t.Fatalf("explicit port changed to %q",cfg.Listen) }
}


func TestTCPFallbackEnabledDefaultPortAndExplicitPort(t *testing.T){
	cfg:=ServerConfig{Instances:[]ServerInstance{sampleInstance("vpn","vpn.example.test","mq0")}}
	cfg.TCPFallback=TCPFallbackConfig{Enabled:true}
	if err:=cfg.Validate();err!=nil{t.Fatal(err)}
	if cfg.Listen!="0.0.0.0:443" || cfg.TCPFallback.Listen!="0.0.0.0:443" {
		t.Fatalf("expected UDP and TCP to default independently to 443: %+v",cfg)
	}
	cfg.TCPFallback.Listen="127.0.0.1:8443"
	if err:=cfg.Validate();err!=nil || cfg.TCPFallback.Listen!="127.0.0.1:8443"{
		t.Fatalf("explicit TCP listener rejected: %+v %v",cfg,err)
	}
}

func TestTCPFallbackDisabledListenerRejected(t *testing.T){
	cfg:=ServerConfig{Instances:[]ServerInstance{sampleInstance("vpn","vpn.example.test","mq0")}}
	cfg.TCPFallback.Listen="127.0.0.1:8443"
	if err:=cfg.Validate();err==nil{t.Fatal("disabled TCP listener configuration accepted")}
	cfg.TCPFallback.Enabled=true
	for _,listen:=range []string{":0","not-a-listen",":70000"}{
		cfg.TCPFallback.Listen=listen
		if err:=cfg.Validate();err==nil{t.Fatalf("invalid TCP listen %q accepted",listen)}
	}
}


func TestInstanceAddressAndMTUValidation(t *testing.T) {
	for _,tc:=range []struct{address string;mtu,frame int;valid bool}{
		{"10.77.0.1/24",0,0,true},
		{"fd77::1/64",1280,1300,true},
		{"",1100,1160,false},
		{"10.77.0.1",1100,1160,false},
		{"10.77.0.1/24",1200,1160,false},
		{"fd77::1/64",1100,1160,false},
		{"fd77::1/64",1280,1160,false},
	}{
		inst:=sampleInstance("a","a.example.test","mq0")
		inst.Address=tc.address;inst.MTU=tc.mtu;inst.MaxFrame=tc.frame
		cfg:=ServerConfig{Instances:[]ServerInstance{inst}}
		err:=cfg.Validate()
		if (err==nil)!=tc.valid{t.Fatalf("address %q mtu %d max-frame %d: %v",tc.address,tc.mtu,tc.frame,err)}
	}
}


func TestHighMTUProfilesAndPeerFrameSize(t *testing.T) {
	for _,tc:=range []struct{address string;mtu,frame int}{
		{"10.77.0.1/24",1360,1374},
		{"10.77.0.1/24",1400,1414},
		{"fd77::1/64",1420,1434},
	}{
		inst:=sampleInstance("mtu","mtu.example.test","mq0")
		inst.Address=tc.address
		inst.MTU=tc.mtu
		inst.MaxFrame=tc.frame
		cfg:=ServerConfig{Instances:[]ServerInstance{inst}}
		if err:=cfg.Validate();err!=nil{
			t.Fatalf("TUN MTU %d and max_frame %d unexpectedly rejected: %v",tc.mtu,tc.frame,err)
		}
	}
}


func TestServerTCConfigRequiresExplicitELF(t *testing.T){
	inst:=sampleInstance("tc","tc.example.test","mq0")
	inst.TC=&tcebpf.Config{MSSClamp:"auto",Stats:true}
	cfg:=ServerConfig{Instances:[]ServerInstance{inst}}
	if err:=cfg.Validate();err==nil{t.Fatal("MSS clamp enabled without ELF accepted")}
	inst.TC=&tcebpf.Config{MSSClamp:"off"}
	cfg=ServerConfig{Instances:[]ServerInstance{inst}}
	if err:=cfg.Validate();err!=nil{t.Fatal(err)}
	if cfg.Instances[0].TC!=nil{t.Fatal("off-only TC config should normalize to disabled")}
	inst.TC=&tcebpf.Config{Object:"bpf/tun_tc.o",MSSClamp:"auto",Stats:true}
	cfg=ServerConfig{Instances:[]ServerInstance{inst}}
	if err:=cfg.Validate();err!=nil{t.Fatal(err)}
	if cfg.Instances[0].TC==nil||cfg.Instances[0].TC.MSSClamp!="auto"{t.Fatal("TC config lost")}
}
