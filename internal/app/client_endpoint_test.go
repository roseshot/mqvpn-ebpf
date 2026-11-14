package app

import (
	"net/url"
	"strings"
	"testing"
)

func TestClientEndpointCanonicalServer(t *testing.T){
	for _,tc:=range []struct{server,path,expectedDial,expectedURL string}{
		{"customer-a.vpn.example.com:4433","/.well-known/masque/ethernet/","customer-a.vpn.example.com:4433","https://customer-a.vpn.example.com:4433/.well-known/masque/ethernet/"},
		{"tenant.example.com","", "tenant.example.com:443", "https://tenant.example.com:443"+defaultPath},
		{"TENANT.EXAMPLE.COM:8443","/custom/masque","tenant.example.com:8443","https://tenant.example.com:8443/custom/masque"},
	}{
		got,err:=planClientEndpoint(tc.server,tc.path,"")
		if err!=nil{t.Fatal(err)}
		if got.dialAddress!=tc.expectedDial || got.requestURL!=tc.expectedURL || got.serverName!=strings.ToLower(strings.Split(tc.server,":")[0]){
			t.Fatalf("endpoint %q %+v: expected dial %q URL %q",tc.server,got,tc.expectedDial,tc.expectedURL)
		}
	}
}

func TestClientEndpointPinnedUnderlayDoesNotChangeTenantIdentity(t *testing.T){
	for _,ip:=range []string{"198.51.100.20","2001:db8::20"}{
		got,err:=planClientEndpoint("tenant.example.com:4433","/vpn/tun/",ip)
		if err!=nil{t.Fatal(err)}
		u,err:=url.Parse(got.requestURL)
		if err!=nil || u.Hostname()!="tenant.example.com" || got.serverName!="tenant.example.com" || u.Port()!="4433"{
			t.Fatalf("tenant SNI/authority mismatch %+v: %v",got,err)
		}
		if !strings.Contains(got.dialAddress,ip) {t.Fatalf("pinned underlay IP missing %+v",got)}
	}
}

func TestClientRejectsRemovedURLAndSNICompatibility(t *testing.T){
	for _,server:=range []string{
		"https://tenant.example.com/vpn", "http://tenant.example.com",
		"tenant.example.com/vpn",
		"tenant.example.com?x=1", "tenant.example.com#tag",
		"tenant.example.com:bad", "tenant.example.com:0", "tenant.example.com:65536",
		"tenant.example.com:", "tenant.example.com@evil.example.com",
		"*.example.com", "tenant..example.com","", "tenant.example.com%eth0",
	}{
		if _,err:=planClientEndpoint(server,"","");err==nil{t.Fatalf("unsafe/removed server form %q accepted",server)}
	}
	for _,ip:=range []string{"not-an-ip","0.0.0.0","224.0.0.1","fe80::1%eth0"}{
		if _,err:=planClientEndpoint("tenant.example.com","",ip);err==nil{t.Fatalf("unsafe pinned IP %q accepted",ip)}
	}
}

func TestClientSingleInstanceIPCertEndpoint(t *testing.T){
	for _,tc:=range []struct{raw,host,dial,url string}{
		{"198.51.100.10","198.51.100.10","198.51.100.10:443","https://198.51.100.10:443"+defaultPath},
		{"198.51.100.10:54433","198.51.100.10","198.51.100.10:54433","https://198.51.100.10:54433"+defaultPath},
		{"[2001:db8::10]","2001:db8::10","[2001:db8::10]:443","https://[2001:db8::10]:443"+defaultPath},
		{"[2001:db8::10]:54433","2001:db8::10","[2001:db8::10]:54433","https://[2001:db8::10]:54433"+defaultPath},
		{"2001:db8::10","2001:db8::10","[2001:db8::10]:443","https://[2001:db8::10]:443"+defaultPath},
	}{
		e,err:=planClientEndpoint(tc.raw,"","")
		if err!=nil||e.serverName!=tc.host||e.dialAddress!=tc.dial||e.requestURL!=tc.url{
			t.Fatalf("IP SAN client endpoint %s: %+v %v",tc.raw,e,err)
		}
	}
}
