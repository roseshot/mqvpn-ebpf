//go:build linux

package tun

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

const (
	// Linux IFA_F_NOPREFIXROUTE: old configuration may have set it.
	// Keep checking it so Linux creates normal connected-prefix routes.
	noPrefixRoute = 0x200
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
	if err:=Validate(name,cidr,mtu,0);err!=nil{return err}
	link,err:=ops.ByName(name)
	if err!=nil{return fmt.Errorf("find created TUN: %w",err)}
	// The ioctl above already ensures this name is attached as TUN.
	addr,err:=netlink.ParseAddr(cidr)
	if err!=nil{return fmt.Errorf("parse IP/CIDR: %w",err)}
	// Use normal Linux address semantics, allowing kernel-managed
	// connected-prefix routes and normal IPv4 address defaults.
	// Clearing this also upgrades an existing NOPREFIXROUTE address.
	addr.Flags &^= noPrefixRoute
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
		if a.IPNet!=nil && a.IPNet.String()==addr.IPNet.String(){
			if a.Flags & noPrefixRoute!=0 {
				return fmt.Errorf("TUN %q address %s still has noprefixroute after setup",name,cidr)
			}
			return nil
		}
	}
	return fmt.Errorf("TUN %q has no assigned address %s after configuration",name,cidr)
}

