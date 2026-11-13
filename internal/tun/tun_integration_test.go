//go:build linux && tun_integration

package tun

import (
	"fmt"
	"net"
	"os"
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
			if addr.Flags&noPrefixRoute!=0 {t.Fatal("TUN address still has noprefixroute")}
		}
	}
	if !found{t.Fatalf("address %s missing from %s",cidr,name)}
}
