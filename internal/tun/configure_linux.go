//go:build linux

package tun

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

type linkOps interface {
	ByName(string)(netlink.Link,error)
	SetMTU(netlink.Link,int)error
	ReplaceAddr(netlink.Link,*netlink.Addr)error
	SetUp(netlink.Link)error
	ListAddrs(netlink.Link)([]netlink.Addr,error)
}

type systemLinkOps struct{}
func(systemLinkOps)ByName(s string)(netlink.Link,error){return netlink.LinkByName(s)}
func(systemLinkOps)SetMTU(l netlink.Link,mtu int)error{return netlink.LinkSetMTU(l,mtu)}
func(systemLinkOps)ReplaceAddr(l netlink.Link,a *netlink.Addr)error{return netlink.AddrReplace(l,a)}
func(systemLinkOps)SetUp(l netlink.Link)error{return netlink.LinkSetUp(l)}
func(systemLinkOps)ListAddrs(l netlink.Link)([]netlink.Addr,error){return netlink.AddrList(l,netlink.FAMILY_ALL)}

func setupInterface(name,cidr string,mtu int,ops linkOps)error{
	return setupInterfaceMode(name,cidr,mtu,ops,false)
}

// setupRoutedInterface configures an individual /32 or /128 local address
// with a peer subnet route. This is a point-to-point unicast overlay: even
// the lowest/highest IPv4 addresses in the pool can be routed normally.
func setupRoutedInterface(name,cidr string,mtu int,ops linkOps)error{
	return setupInterfaceMode(name,cidr,mtu,ops,true)
}

func setupInterfaceMode(name,cidr string,mtu int,ops linkOps,routed bool)error{
	if err:=Validate(name,cidr,mtu,0);err!=nil{return err}
	link,err:=ops.ByName(name)
	if err!=nil{return fmt.Errorf("find created TUN: %w",err)}
	// The ioctl above already ensures this name is attached as TUN.
	addr,err:=netlink.ParseAddr(cidr)
	if err!=nil{return fmt.Errorf("parse IP/CIDR: %w",err)}
	if routed {
		// IFA_LOCAL is always a host address; IFA_ADDRESS holds a peer
		// subnet. The Linux kernel installs a unicast route to that
		// prefix without assigning it an IPv4 directed-broadcast address.
		prefix,err:=netip.ParsePrefix(cidr)
		if err!=nil{return err}
		subnet:=prefix.Masked()
		peerIP:=subnet.Addr()
		// IFA_LOCAL and IFA_ADDRESS must differ, including when the
		// leased host happens to be the subnet's first address.
		if peerIP==prefix.Addr(){
			peerIP=peerIP.Next()
			if !subnet.Contains(peerIP){return fmt.Errorf("routed TUN prefix %s has no separate peer address",subnet)}
		}
		bits:=prefix.Addr().BitLen()
		addr.IPNet=&net.IPNet{IP:net.ParseIP(prefix.Addr().String()),Mask:net.CIDRMask(bits,bits)}
		addr.Peer=&net.IPNet{IP:net.ParseIP(peerIP.String()),Mask:net.CIDRMask(subnet.Bits(),bits)}
		if prefix.Addr().Is4(){addr.Broadcast=net.IPv4zero}
	}
	// Static clients keep normal connected-prefix behavior. Routed
	// sessions obtain the same prefix through IFA_ADDRESS as a unicast
	// peer route, without making its first/last address a broadcast.
	if err:=ops.SetMTU(link,mtu);err!=nil{return fmt.Errorf("set MTU %d: %w",mtu,err)}
	if err:=ops.ReplaceAddr(link,addr);err!=nil{return fmt.Errorf("assign address %s: %w",cidr,err)}
	if err:=ops.SetUp(link);err!=nil{return fmt.Errorf("bring interface UP: %w",err)}
	// Verify the configured address, MTU and UP bit before TUN data transfer.
	ready,err:=ops.ByName(name)
	if err!=nil{return fmt.Errorf("verify TUN readiness: %w",err)}
	if ready.Attrs().Flags&net.FlagUp==0 {return fmt.Errorf("TUN %q not UP after configuration",name)}
	if ready.Attrs().MTU!=mtu {return fmt.Errorf("TUN %q MTU is %d, wanted %d",name,ready.Attrs().MTU,mtu)}
	assigned,err:=ops.ListAddrs(ready)
	if err!=nil{return fmt.Errorf("verify TUN address: %w",err)}
	for _,a:=range assigned {
		if a.IPNet==nil || a.IPNet.String()!=addr.IPNet.String(){continue}
		if !routed{return nil}
		if a.Peer!=nil && a.Peer.String()==addr.Peer.String(){return nil}
	}
	return fmt.Errorf("TUN %q has no assigned address %s after configuration",name,cidr)
}

