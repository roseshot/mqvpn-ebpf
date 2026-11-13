package app

import (
	"strings"
	"testing"
)

func TestMasquePathDefaultAndOverride(t *testing.T){
	for _,tc:=range []struct{server,path,want string}{
		{"https://tenant.example.com","",defaultPath},
		{"https://tenant.example.com","/connect/custom", "/connect/custom"},
		{"https://tenant.example.com/custom/server","", "/custom/server"},
		{"https://tenant.example.com/custom/server","/tenant/vpn/","/tenant/vpn/"},
	}{
		raw,err:=applyClientMasquePath(tc.server,tc.path)
		if err!=nil{t.Fatal(err)}
		endpoint,err:=planClientEndpoint(raw,"","")
		if err!=nil||!strings.HasSuffix(endpoint.requestURL,tc.want) {
			t.Fatalf("server=%q override=%q endpoint=%+v err=%v",tc.server,tc.path,endpoint,err)
		}
	}
	if err:=validateMasquePath(defaultPath);err!=nil{t.Fatal(err)}
}

func TestMasquePathRejectsAmbiguity(t *testing.T){
	for _,path:=range []string{"","vpn","//vpn","/vpn//endpoint","/vpn/../admin","/vpn/./admin","/vpn?x=1","/vpn#frag","/vpn%2Fadmin","/vpn\\admin","/vpn\r\nX: injected", "/vpn path"}{
		if err:=validateMasquePath(path);err==nil{t.Fatalf("accepted unsafe MASQUE path %q",path)}
	}
	for _,bad:=range []string{"/vpn?x=1","/vpn#fragment"}{
		if _,err:=applyClientMasquePath("https://tenant.example.com",bad);err==nil{t.Fatal("bad override accepted")}
	}
}
