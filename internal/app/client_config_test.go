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
	path:=filepath.Join(t.TempDir(),"client.yaml")
	if err:=os.WriteFile(path,[]byte(body),0600);err!=nil{t.Fatal(err)}
	return path
}

func TestClientCompactConfigAndDefaultEndpoint(t *testing.T){
	path:=writeClientTestYAML(t,"server: tenant.vpn.example.com\naddress: 10.77.0.2/24\nca: /etc/ca.crt\ncert: /etc/client.crt\nkey: /etc/client.key\n")
	cfg,err:=loadClientFile(path)
	if err!=nil{t.Fatal(err)}
	if cfg.Server!="tenant.vpn.example.com"||cfg.Address!="10.77.0.2/24"||cfg.TUN!=""||cfg.SourceInterface!="" {t.Fatalf("unexpected client defaults %+v",cfg)}
	url,err:=expandClientServer(cfg.Server)
	if err!=nil{t.Fatal(err)}
	endpoint,err:=planClientEndpoint(url,"","")
	if err!=nil||endpoint.dialAddress!="tenant.vpn.example.com:443"||endpoint.serverName!="tenant.vpn.example.com"||!strings.HasSuffix(endpoint.requestURL,defaultPath) {
		t.Fatalf("invalid compact endpoint %+v: %v",endpoint,err)
	}
}

func TestClientServerShortcutAndIdentity(t *testing.T){
	for _,tc:=range []struct{input,addr string}{
		{"tenant.vpn.example.com","tenant.vpn.example.com:443"},
		{"tenant.vpn.example.com:8443","tenant.vpn.example.com:8443"},
		{"https://tenant.vpn.example.com:4433/custom","tenant.vpn.example.com:4433"},
	}{
		url,err:=expandClientServer(tc.input)
		if err!=nil{t.Fatal(err)}
		got,err:=planClientEndpoint(url,"","")
		if err!=nil||got.dialAddress!=tc.addr||got.serverName!="tenant.vpn.example.com"{t.Fatalf("%q -> %+v, %v",tc.input,got,err)}
	}
	for _,bad:=range []string{"","http://tenant.vpn.example.com","https://"}{
		if _,err:=expandClientServer(bad);err==nil{t.Fatalf("unsafe server %q accepted",bad)}
	}
	url,err:=expandClientServer("198.51.100.10")
	if err!=nil{t.Fatal(err)}
	if _,err:=planClientEndpoint(url,"","");err==nil {t.Fatal("IP URL must require tenant DNS name")}
}

func TestClientYAMLStrictValidation(t *testing.T){
	for _,raw:=range []string{
		"server: tenant.example.com\nserver: other.example.com\n",
		"server: tenant.example.com\nunknown_option: true\n",
		"server: tenant.example.com\nurl: https://tenant.example.com/test\n",
	}{
		if _,err:=loadClientFile(writeClientTestYAML(t,raw));err==nil{t.Fatalf("bad YAML accepted: %q",raw)}
	}
}

func TestClientYAMLAndCLIOverrideBeforeNetworking(t *testing.T){
	path:=writeClientTestYAML(t,"server: 198.51.100.10\naddress: 10.77.0.2/24\nca: /missing/ca.crt\ncert: /missing/client.crt\nkey: /missing/client.key\n")
	logger:=slog.New(slog.NewTextHandler(io.Discard,nil))
	err:=RunClient(context.Background(),[]string{"--config",path},logger)
	if err==nil||!strings.Contains(err.Error(),"server-name"){t.Fatalf("IP-only server should fail SNI validation, got %v",err)}
	// Explicit CLI --server must override the YAML IP target while retaining
	// its TUN and mTLS settings. The expected next failure is missing CA.
	err=RunClient(context.Background(),[]string{"--config",path,"--server","tenant.vpn.example.com"},logger)
	if err==nil||strings.Contains(err.Error(),"server-name"){t.Fatalf("CLI server override ignored: %v",err)}
}

func TestClientYAMLTCPAndTCPolicy(t *testing.T){
	path:=writeClientTestYAML(t,"server: tenant.example.com\naddress: 10.77.0.2/24\ntc:\n  mode: off\n  stats: false\n")
	cfg,err:=loadClientFile(path)
	if err!=nil||cfg.TC==nil||cfg.TC.Mode!="off"||cfg.TC.Stats==nil||*cfg.TC.Stats {t.Fatalf("TC YAML options lost: %+v %v",cfg,err)}
}

func TestClientConfigCanRequestDynamicAddress(t *testing.T){
	path:=writeClientTestYAML(t,"server: tenant.vpn.example.com\nca: /etc/ca.crt\ncert: /etc/client.crt\nkey: /etc/client.key\n")
	cfg,err:=loadClientFile(path)
	if err!=nil{t.Fatal(err)}
	if !dynamicAddressRequested(cfg.Address) {t.Fatal("omitted client address must negotiate with the server")}
}
