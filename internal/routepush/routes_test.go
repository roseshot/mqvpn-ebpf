package routepush

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPushRouteRoundTripAndCanonicalization(t *testing.T){
	routes,err:=Parse([]string{"10.77.0.9/24","192.168.20.0/24","0.0.0.0/0","::/0","2001:db8:2::1/64"})
	if err!=nil{t.Fatal(err)}
	encoded:=Encode(routes)
	if encoded!="10.77.0.0/24,192.168.20.0/24,0.0.0.0/0,::/0,2001:db8:2::/64"{
		t.Fatalf("unexpected push format %q",encoded)
	}
	decoded,err:=Decode(encoded)
	if err!=nil{t.Fatal(err)}
	if len(decoded)!=len(routes){t.Fatal("wire routes lost")}
	for i,p:=range decoded{if p!=routes[i]{t.Fatalf("route[%d]: %s vs %s",i,p,routes[i])}}
	if got,err:=Decode("");err!=nil||len(got)!=0{t.Fatalf("old Server compatibility: %v %v",got,err)}
	if !routes[2].Contains(netip.MustParseAddr("198.51.100.10")){t.Fatal("default route must cover underlay")}
}

func TestPushRouteValidationAndLimits(t *testing.T){
	for _,bad:=range [][]string{
		{"bad"}, {"192.168.1.0/24","192.168.1.45/24"},
		{"224.0.0.0/4"}, {"127.0.0.0/8"},{"169.254.0.0/16"},
		{"ff00::/8"},{"fe80::/64"},{"::ffff:192.0.2.1/128"},
		{"192.168.1.0/24\r\nX-Evil: true"},{" 10.0.0.0/8"},
		{"192.168.1.0/24",""}, {"255.255.255.255/32"},
	}{
		if _,err:=Parse(bad);err==nil{t.Fatalf("accepted unsafe routes: %v",bad)}
	}
	many:=make([]string,MaxRoutes+1)
	for i:=range many{many[i]="10.0.0.0/8"}
	if _,err:=Parse(many);err==nil{t.Fatal("route count limit ignored")}
	if _,err:=Decode(strings.Repeat("a",MaxHeaderLength+1));err==nil{t.Fatal("header limit ignored")}
}
