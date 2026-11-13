//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

const (
	ifNameSize = 16
	tunSetIFF = 0x400454ca
	iffTUN = 0x0001
	iffNoPI = 0x1000
	// Linux IFA_F_NOPREFIXROUTE. Retained only for verification when
	// upgrading an address configured by old releases. The flag MUST NOT
	// be set: ordinary connected-prefix routes belong to the Linux kernel.
	noPrefixRoute = 0x200
	DefaultMTU = 1400
	EthernetOverhead = 14
)

type ifreq struct {
	Name [ifNameSize]byte
	Flags uint16
	_ [22]byte
}

// ValidateAddress ensures a routable unicast host CIDR is supplied, not
// a network address inferred from a peer's route, subnet or VPN instance.
func ValidateAddress(cidr string, mtu, maxFrame int) error {
	prefix,err:=netip.ParsePrefix(cidr)
	if err!=nil {return fmt.Errorf("TUN address %q must be an IP/CIDR (e.g. 10.77.0.1/24): %w",cidr,err)}
	ip:=prefix.Addr()
	if ip.Is4In6()||ip.IsUnspecified()||ip.IsMulticast()||ip.IsLoopback()||ip.IsLinkLocalUnicast(){
		return fmt.Errorf("TUN address %q must be a non-link-local unicast IP",cidr)
	}
	minMTU:=576
	if ip.Is6() {minMTU=1280}
	if mtu<minMTU || mtu>65535 {
		return fmt.Errorf("TUN MTU %d must be between %d and 65535 for %s",mtu,minMTU,cidr)
	}
	if maxFrame>0 && mtu+EthernetOverhead>maxFrame {
		return fmt.Errorf("TUN MTU %d with Ethernet overhead exceeds max-frame %d",mtu,maxFrame)
	}
	return nil
}

func Validate(name,cidr string,mtu,maxFrame int)error{
	if err:=validateName(name);err!=nil{return err}
	return ValidateAddress(cidr,mtu,maxFrame)
}

// Open creates a Linux L3 TUN if missing, or attaches to the existing TUN.
// It assigns the explicitly requested IP/CIDR and MTU, then brings the
// device UP. Linux may create its standard connected and local address routes
// when the address is assigned. The daemon does not explicitly write routes,
// ip rules, VRFs, namespace changes, firewall or multicast routing.
// New nonpersistent TUNs exist while their file descriptor remains open.
func Open(name,cidr string,mtu int) (*os.File,error) {
	if err:=Validate(name,cidr,mtu,0);err!=nil{return nil,err}
	f,err:=os.OpenFile("/dev/net/tun",os.O_RDWR,0)
	if err!=nil{return nil,fmt.Errorf("open /dev/net/tun: %w (requires TUN access and CAP_NET_ADMIN)",err)}
	var req ifreq
	copy(req.Name[:],name)
	req.Flags=iffTUN|iffNoPI
	_,_,errno:=syscall.Syscall(syscall.SYS_IOCTL,f.Fd(),uintptr(tunSetIFF),uintptr(unsafe.Pointer(&req)))
	if errno!=0{
		_ = f.Close()
		return nil,fmt.Errorf("create/attach TUN %q: %w (requires CAP_NET_ADMIN and a TUN, not TAP)",name,errno)
	}
	if err:=setupInterface(name,cidr,mtu,systemLinkOps{});err!=nil{
		_ = f.Close()
		return nil,fmt.Errorf("configure TUN %q: %w",name,err)
	}
	return f,nil
}

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

func validateName(name string)error{
	if name==""||len(name)>=ifNameSize{return errors.New("TUN name must contain 1..15 ASCII characters")}
	for _,c:=range []byte(name){
		if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='_'||c=='-'||c=='.'){
			return fmt.Errorf("invalid TUN name %q",name)
		}
	}
	return nil
}
