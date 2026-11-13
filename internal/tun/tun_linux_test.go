//go:build linux

package tun

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

type fakeOps struct {
	link *netlink.Dummy
	addr *netlink.Addr
	order []string
	failOn string
}
func(f *fakeOps)fail(step string)error{
	f.order=append(f.order,step)
	if f.failOn==step{return errors.New("permission denied")}
	return nil
}
func(f *fakeOps)ByName(name string)(netlink.Link,error){
	if err:=f.fail("find");err!=nil{return nil,err}
	return f.link,nil
}
func(f *fakeOps)SetMTU(_ netlink.Link,mtu int)error{
	if err:=f.fail("mtu");err!=nil{return err}
	f.link.MTU=mtu
	return nil
}
func(f *fakeOps)ReplaceAddr(_ netlink.Link,addr *netlink.Addr)error{
	if err:=f.fail("address");err!=nil{return err}
	f.addr=addr
	return nil
}
func(f *fakeOps)SetUp(_ netlink.Link)error{
	if err:=f.fail("up");err!=nil{return err}
	f.link.Flags|=net.FlagUp
	return nil
}
func(f *fakeOps)ListAddrs(_ netlink.Link)([]netlink.Addr,error){
	if err:=f.fail("list");err!=nil{return nil,err}
	if f.addr==nil{return nil,nil}
	return []netlink.Addr{*f.addr},nil
}
func TestValidateName(t *testing.T){
	for _,name:=range []string{"mq0","tun-main","tun.3"}{if err:=validateName(name);err!=nil{t.Fatal(err)}}
	for _,name:=range []string{"","bad name","abcdefghijklmnop","bad/name"}{
		if err:=validateName(name);err==nil{t.Fatalf("invalid name %q accepted",name)}
	}
}
func TestValidateAddress(t *testing.T){
	for _,tc:=range []struct{cidr string;mtu,frame int}{
		{"10.77.0.1/24",1100,1160},
		{"fd77::1/64",1280,1300},
		{"198.51.100.42/32",1500,1514},
		{"10.77.0.1/24",1360,1374}, // TUN MTU 1360: IPv4 TCP MSS ~1320
		{"10.77.0.1/24",1400,1414}, // IPv4 MSS 1360 (without options)
		{"fd77::1/64",1420,1434},  // IPv6 MSS 1360 (without options)
	}{
		if err:=ValidateAddress(tc.cidr,tc.mtu,tc.frame);err!=nil{t.Fatal(err)}
	}
	for _,tc:=range []struct{cidr string;mtu,frame int}{
		{"",1100,1160},{"10.77.0.1",1100,1160},
		{"0.0.0.0/24",1100,1160},{"224.0.0.1/24",1100,1160},
		{"127.0.0.1/8",1100,1160},{"fe80::1/64",1280,1300},
		{"10.77.0.1/24",1200,1160},{"fd77::1/64",1100,1160},
		{"fd77::1/64",1280,1160},
		{"10.77.0.1/24",1360,1373}, // missing one byte of Ethernet overhead
		{"10.77.0.1/24",1400,1400},
		{"fd77::1/64",1420,1433},
	}{
		if err:=ValidateAddress(tc.cidr,tc.mtu,tc.frame);err==nil{t.Fatalf("accepted %+v",tc)}
	}
}
func TestSetupCreatesReadyAddressAndAllowsKernelConnectedRoute(t *testing.T){
	for _,cidr:=range []string{"10.77.0.1/24","fd77::1/64"}{
		mtu:=1100
		if cidr=="fd77::1/64"{mtu=1280}
		f:=&fakeOps{link:&netlink.Dummy{LinkAttrs:netlink.LinkAttrs{Name:"mq0"}}}
		if err:=setupInterface("mq0",cidr,mtu,f);err!=nil{t.Fatal(err)}
		if f.addr==nil||f.addr.Flags!=0{t.Fatalf("expected normal Linux address flags for %s: %d",cidr,f.addr.Flags)}
		if got:=len(f.order);got!=6{t.Fatalf("expected six link/address/readiness calls, got %v",f.order)}
		if f.order[1]!="mtu"||f.order[2]!="address"||f.order[3]!="up"{t.Fatalf("wrong readiness order: %v",f.order)}
	}
}
func TestConfiguredAddressDoesNotDisableNormalIPv4Broadcast(t *testing.T) {
	f:=&fakeOps{link:&netlink.Dummy{LinkAttrs:netlink.LinkAttrs{Name:"mq0"}}}
	if err:=setupInterface("mq0","10.77.0.1/24",1360,f);err!=nil{t.Fatal(err)}
	if f.addr.Broadcast!=nil{t.Fatalf("IP broadcast unexpectedly forced to %s",f.addr.Broadcast)}
}

func TestSetupErrorsOnFailedConfiguration(t *testing.T){
	for _,step:=range []string{"find","mtu","address","up","list"}{
		f:=&fakeOps{link:&netlink.Dummy{LinkAttrs:netlink.LinkAttrs{Name:"mq0"}},failOn:step}
		if err:=setupInterface("mq0","10.77.0.1/24",1100,f);err==nil{t.Fatalf("%s failure ignored",step)}
	}
}
func TestOpenValidatesBeforeDeviceCreation(t *testing.T){
	if _,err:=Open("mq0","not-cidr",1100);err==nil{t.Fatal("invalid address reached /dev/net/tun")}
}

func TestSetupRoutedTUNAvoidsSubnetBroadcast(t *testing.T) {
	for _,tc:=range []struct{cidr,local,peer string; mtu int}{
		{"10.77.0.1/24","10.77.0.1/32","10.77.0.0/24",1400},
		{"10.77.0.0/24","10.77.0.0/32","10.77.0.1/24",1400},
		{"10.77.0.255/24","10.77.0.255/32","10.77.0.0/24",1400},
		{"10.77.0.0/31","10.77.0.0/32","10.77.0.1/31",1400},
		{"fd77::/64","fd77::/128","fd77::1/64",1400},
	}{
		f:=&fakeOps{link:&netlink.Dummy{LinkAttrs:netlink.LinkAttrs{Name:"mq0"}}}
		if err:=setupRoutedInterface("mq0",tc.cidr,tc.mtu,f);err!=nil{t.Fatalf("%s: %v",tc.cidr,err)}
		if f.addr==nil || f.addr.IPNet.String()!=tc.local || f.addr.Peer==nil || f.addr.Peer.String()!=tc.peer {
			t.Fatalf("%s: unexpected local/peer %+v",tc.cidr,f.addr)
		}
		if f.addr.IP.To4()!=nil && !f.addr.Broadcast.Equal(net.IPv4zero){
			t.Fatalf("%s: broadcast not explicitly disabled: %s",tc.cidr,f.addr.Broadcast)
		}
	}
	// Static TUN addresses use connected-prefix semantics.
	f:=&fakeOps{link:&netlink.Dummy{LinkAttrs:netlink.LinkAttrs{Name:"mq0"}}}
	if err:=setupInterface("mq0","10.77.0.1/24",1400,f);err!=nil{t.Fatal(err)}
	if f.addr.Peer!=nil {t.Fatal("static TUN unexpectedly has a peer route")}
}
