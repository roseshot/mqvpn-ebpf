package app

import "testing"

func TestTunnelIPNegotiation(t *testing.T){
	if !dynamicAddressRequested("")||!dynamicAddressRequested("auto")||dynamicAddressRequested("10.77.0.2/24"){t.Fatal("wrong address modes")}
	if on,err:=wantsTunnelIP("auto");err!=nil||!on{t.Fatalf("request: %t %v",on,err)}
	if on,err:=wantsTunnelIP("");err!=nil||on{t.Fatalf("legacy request: %t %v",on,err)}
	if _,err:=wantsTunnelIP("10.77.0.2/24");err==nil{t.Fatal("untrusted requested address accepted")}
	for _,bad:=range []string{"","auto","0.0.0.0/24","255.255.255.255/24","127.0.0.1/8","224.0.0.1/24","garbage"}{
		if _,err:=resolveClientTunnelAddress("auto",bad);err==nil{t.Fatalf("unsafe assigned address %q accepted",bad)}
	}
	for _,edge:=range []string{"10.77.0.0/24","10.77.0.255/24","10.77.0.0/31","fd77::/64"}{
		if got,err:=resolveClientTunnelAddress("auto",edge);err!=nil||got!=edge{t.Fatalf("dynamic address %s rejected: %s %v",edge,got,err)}
	}
	got,err:=resolveClientTunnelAddress("","10.77.0.2/24")
	if err!=nil||got!="10.77.0.2/24"{t.Fatalf("negotiated: %q %v",got,err)}
	if _,err:=resolveClientTunnelAddress("10.77.0.2/24","10.77.0.3/24");err==nil{t.Fatal("static address overwritten")}
	if got,err:=resolveClientTunnelAddress("10.77.0.2/24","");err!=nil||got!="10.77.0.2/24"{t.Fatalf("legacy address: %q %v",got,err)}
	if err:=validateClientAddressRequest("mq0","auto",0,0);err!=nil{t.Fatal(err)}
	if err:=validateClientAddressRequest("mq0","auto",100,0);err==nil{t.Fatal("invalid MTU accepted")}
	if _,err:=resolveClientTunnelAddress("","2001:db8::2/64");err!=nil{t.Fatal(err)}
}
