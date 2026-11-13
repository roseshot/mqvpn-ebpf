//go:build linux && tun_integration

package tun

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// Privileged integration: directly inspect the normal connected-prefix
// route created by the Linux kernel as a side effect of assigning an
// address. No route or rule add/replace calls are made by the daemon.
func TestIntegrationCreatesConnectedPrefixRoute(t *testing.T) {
	if os.Geteuid()!=0 {
		t.Fatal("this test requires root/CAP_NET_ADMIN; run with sudo")
	}
	name:=fmt.Sprintf("mqci%x",os.Getpid())
	if len(name)>=ifNameSize {t.Fatalf("TUN test name too long: %s",name)}
	pid:=os.Getpid()
	cidr:=fmt.Sprintf("198.19.%d.%d/30",byte(pid>>8),byte(pid&0xfc)|1)
	f,err:=Open(name,cidr,1360)
	if err!=nil{t.Fatalf("create test TUN: %v",err)}
	defer f.Close()
	link,err:=netlink.LinkByName(name)
	if err!=nil{t.Fatal(err)}
	if link.Attrs().MTU!=1360||link.Attrs().Flags&net.FlagUp==0{
		t.Fatalf("TUN not ready: %+v",link.Attrs())
	}
	_,prefix,err:=net.ParseCIDR(cidr)
	if err!=nil{t.Fatal(err)}
	var got bool
	deadline:=time.Now().Add(3*time.Second)
	for time.Now().Before(deadline) {
		routes,err:=netlink.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{LinkIndex:link.Attrs().Index,Dst:prefix},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST,
		)
		if err!=nil{t.Fatalf("list connected routes: %v",err)}
		for _,route:=range routes {
			if route.Dst!=nil&&route.Dst.String()==prefix.String() &&
				route.LinkIndex==link.Attrs().Index && route.Gw==nil {
				got=true
				break
			}
		}
		if got{break}
		time.Sleep(20*time.Millisecond)
	}
	if !got{t.Fatalf("kernel did not create connected route %s on %s",prefix,name)}
	assigned,err:=netlink.AddrList(link,netlink.FAMILY_V4)
	if err!=nil{t.Fatal(err)}
	found:=false
	for _,addr:=range assigned {
		if addr.IPNet!=nil && addr.IPNet.IP.String()==net.ParseIP(cidr[:len(cidr)-3]).String(){
			found=true
		}
	}
	if !found{t.Fatalf("address %s missing from %s",cidr,name)}

}

func TestIntegrationRoutedPoolUnicast(t *testing.T) {
	if os.Geteuid()!=0 {t.Fatal("this test requires root/CAP_NET_ADMIN")}
	name:=fmt.Sprintf("mqfull%x",os.Getpid())
	if len(name)>=ifNameSize {t.Fatalf("test TUN name too long: %s",name)}
	pid:=os.Getpid()
	local:=fmt.Sprintf("198.19.%d.%d/30",byte(pid>>8),int(byte(pid&0xfc))+1)
	f,err:=OpenRouted(name,local,1360)
	if err!=nil{t.Fatalf("routed TUN address: %v",err)}
	defer f.Close()
	link,err:=netlink.LinkByName(name)
	if err!=nil{t.Fatal(err)}
	for _,ip:=range []string{
		fmt.Sprintf("198.19.%d.%d",byte(pid>>8),byte(pid&0xfc)),
		fmt.Sprintf("198.19.%d.%d",byte(pid>>8),int(byte(pid&0xfc))+3),
	}{
		routes,err:=netlink.RouteGet(net.ParseIP(ip))
		if err!=nil{t.Fatalf("route lookup to %s: %v",ip,err)}
		found:=false
		for _,route:=range routes {
			// RouteGet does not populate the kernel RTN_UNICAST type in
			// all netlink responses. A route in the main table via this
			// TUN proves the destination was not captured by the kernel's
			// local broadcast table (255).
			if route.LinkIndex==link.Attrs().Index && route.Table==254 {found=true}
		}
		if !found{t.Fatalf("routed pool host %s was not unicast over TUN: %+v",ip,routes)}
	}
}

func TestIntegrationRoutedFirstLastAsLocalAddresses(t *testing.T) {
	if os.Geteuid()!=0 {t.Fatal("this test requires root/CAP_NET_ADMIN")}
	pid:=os.Getpid()
	for _,host:=range []int{0,3} {
		name:=fmt.Sprintf("mqhost%d%x",host,pid)
		if len(name)>=ifNameSize{t.Fatalf("TUN name too long: %s",name)}
		octet:=byte(pid>>8)^byte(host)
		base:=fmt.Sprintf("198.19.%d.%d",octet,byte(pid&0xfc))
		local:=fmt.Sprintf("198.19.%d.%d/30",octet,int(byte(pid&0xfc))+host)
		f,err:=OpenRouted(name,local,1360)
		if err!=nil{t.Fatalf("lease %s must be configurable as a host IP: %v",local,err)}
		link,err:=netlink.LinkByName(name)
		if err!=nil{f.Close();t.Fatal(err)}
		addrs,err:=netlink.AddrList(link,netlink.FAMILY_V4)
		if err!=nil{f.Close();t.Fatal(err)}
		found:=false
		for _,addr:=range addrs {
			if addr.IPNet==nil || !addr.IP.Equal(net.ParseIP(strings.Split(local,"/")[0])){continue}
			ones,_:=addr.IPNet.Mask.Size()
			if ones!=32 || addr.Peer==nil || addr.Peer.Mask.String()=="" || addr.Broadcast!=nil{
				f.Close()
				t.Fatalf("host %s was not configured as /32 peer-unicast without broadcast: %+v",local,addr)
			}
			found=true
		}
		if !found{f.Close();t.Fatalf("local host IP %s was not configured",local)}
		dest:=fmt.Sprintf("198.19.%d.%d",octet,int(byte(pid&0xfc))+1)
		routes,err:=netlink.RouteGet(net.ParseIP(dest))
		if err!=nil{f.Close();t.Fatalf("lookup %s from %s: %v",dest,base,err)}
		ok:=false
		for _,route:=range routes {if route.LinkIndex==link.Attrs().Index && route.Table==254{ok=true}}
		if !ok {f.Close();t.Fatalf("peer route to %s missing from TUN %s: %+v",dest,name,routes)}
		_ = f.Close()
	}
}
