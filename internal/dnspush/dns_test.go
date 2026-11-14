package dnspush

import (
	"net/netip"
	"strings"
	"testing"
)

func TestAuthenticatedDNSWireRoundTrip(t *testing.T){
	got,err:=Parse([]string{"10.77.0.1","fd77::53","2001:db8::1"})
	if err!=nil{t.Fatal(err)}
	wire:=Encode(got)
	if wire!="10.77.0.1,fd77::53,2001:db8::1"{t.Fatalf("unexpected DNS header: %q",wire)}
	parsed,err:=Decode(wire)
	if err!=nil||len(parsed)!=len(got){t.Fatalf("DNS round trip: %v %v",parsed,err)}
	for i,ip:=range parsed{if ip!=got[i]{t.Fatalf("DNS[%d] differs",i)}}
	if len(got)!=3||got[0]!=netip.MustParseAddr("10.77.0.1"){t.Fatal("DNS addresses were modified")}
	if out,err:=Decode("");err!=nil||len(out)!=0{t.Fatalf("missing header: %v %v",out,err)}
}
func TestPushedDNSRejectsInvalidUnsafeAndDuplicates(t *testing.T){
	for _,bad:=range [][]string{
		{""}, {"dns.example.com"}, {"10.77.0.1:53"}, {"10.77.0.1 ","8.8.8.8"},
		{"8.8.8.8","8.8.8.8"}, {"::ffff:8.8.8.8"}, {"fe80::1%eth0"},
		{"0.0.0.0"}, {"::"}, {"224.0.0.1"}, {"ff02::1"},
		{"127.0.0.1"}, {"::1"}, {"169.254.1.1"}, {"fe80::1"},
		{"255.255.255.255"}, {"10.77.0.1\r\nHeader: attack"},
	}{
		if _,err:=Parse(bad);err==nil{t.Fatalf("invalid DNS accepted: %v",bad)}
	}
	many:=make([]string,MaxServers+1)
	for i:=range many{many[i]="8.8.8.8"}
	if _,err:=Parse(many);err==nil{t.Fatal("DNS count cap not enforced")}
	if _,err:=Decode(strings.Repeat("x",MaxHeaderLength+1));err==nil{t.Fatal("DNS header cap not enforced")}
}
