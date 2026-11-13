//go:build linux

package routepush

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
)

const mainTable = 254
// A private route protocol distinguishes routes owned by this daemon from
// static routes. It is only used for conditional cleanup; not authorization.
const ownedProtocol = netlink.RouteProtocol(192)

// Kernel is a narrow rtnetlink API so protection, rollback and route ownership
// can be tested without CAP_NET_ADMIN.
type Kernel interface {
	LinkByName(string) (netlink.Link,error)
	LinkByIndex(int) (netlink.Link,error)
	RouteGetWithOptions(net.IP,*netlink.RouteGetOptions)([]netlink.Route,error)
	RouteAdd(*netlink.Route)error
	RouteDel(*netlink.Route)error
	RouteListFiltered(int,*netlink.Route,uint64)([]netlink.Route,error)
}

type systemKernel struct{}
func(systemKernel)LinkByName(n string)(netlink.Link,error){return netlink.LinkByName(n)}
func(systemKernel)LinkByIndex(i int)(netlink.Link,error){return netlink.LinkByIndex(i)}
func(systemKernel)RouteGetWithOptions(dst net.IP,o *netlink.RouteGetOptions)([]netlink.Route,error){
	return netlink.RouteGetWithOptions(dst,o)
}
func(systemKernel)RouteAdd(r *netlink.Route)error{return netlink.RouteAdd(r)}
func(systemKernel)RouteDel(r *netlink.Route)error{return netlink.RouteDel(r)}
func(systemKernel)RouteListFiltered(f int,r *netlink.Route,m uint64)([]netlink.Route,error){
	return netlink.RouteListFiltered(f,r,m)
}

// Guard protects the actual resolved VPN server IP on the physical underlay
// before the client creates a TUN or installs any pushed routes. Only routes
// created by this Guard will be removed when the authenticated session ends.
type Guard struct {
	k Kernel
	remote,source net.IP
	wanInterface,tunName string
	wanIndex int
	owned []netlink.Route
}

func ProtectServer(remote,source net.IP,wanInterface,tunName string,pushes []netip.Prefix,multipleWAN bool)(*Guard,error){
	return protectWithKernel(systemKernel{},remote,source,wanInterface,tunName,pushes,multipleWAN)
}

func protectWithKernel(k Kernel,remote,source net.IP,wanInterface,tunName string,pushes []netip.Prefix,multipleWAN bool)(*Guard,error){
	g:=&Guard{k:k,remote:remote,source:source,wanInterface:wanInterface,tunName:tunName}
	if len(pushes)==0{return g,nil}
	if remote==nil || source==nil || remote.IsUnspecified() || source.IsUnspecified() {
		return nil,errors.New("resolved underlay destination and source IP are required")
	}
	dst,ok:=netip.AddrFromSlice(remote)
	if !ok{return nil,errors.New("invalid underlay server IP")}
	dst=dst.Unmap()
	if multipleWAN {
		for _,p:=range pushes {
			if p.Contains(dst) {
				return nil,fmt.Errorf("pushed route %s covers VPN server %s with dual WAN: configure source-specific policy routing or disable server-pushed routes",p,dst)
			}
		}
		// With two WAN paths the same /32 pin via only one interface could
		// hijack the other path. If no pushed route covers the endpoint,
		// no host pin is necessary and both WAN routes remain untouched.
		return g,nil
	}
	opts:=&netlink.RouteGetOptions{SrcAddr:source}
	if wanInterface!="" {
		link,err:=k.LinkByName(wanInterface)
		if err!=nil{return nil,fmt.Errorf("WAN interface %s: %w",wanInterface,err)}
		opts.OifIndex=link.Attrs().Index
	}
	routes,err:=k.RouteGetWithOptions(remote,opts)
	if err!=nil{return nil,fmt.Errorf("resolve original underlay route to %s: %w",remote,err)}
	if len(routes)!=1 || routes[0].LinkIndex<=0 || len(routes[0].MultiPath)!=0 {
		return nil,fmt.Errorf("underlay route to %s is ambiguous or multipath; configure a pinned WAN route",remote)
	}
	underlay:=routes[0]
	link,err:=k.LinkByIndex(underlay.LinkIndex)
	if err!=nil{return nil,fmt.Errorf("inspect underlay link: %w",err)}
	if link.Attrs().Name==tunName {
		return nil,fmt.Errorf("VPN server %s already resolves through TUN %s",remote,tunName)
	}
	if opts.OifIndex!=0 && underlay.LinkIndex!=opts.OifIndex {
		return nil,fmt.Errorf("route to VPN server uses interface %s instead of required %s",link.Attrs().Name,wanInterface)
	}
	g.wanIndex=underlay.LinkIndex
	host:=netip.PrefixFrom(dst,dst.BitLen())
	pin:=netlink.Route{Dst:ipNet(host),LinkIndex:underlay.LinkIndex,Gw:underlay.Gw,Src:source,Table:mainTable,Protocol:ownedProtocol}
	if underlay.Gw==nil {pin.Scope=netlink.SCOPE_LINK}
	// RouteAdd does not replace an existing administrator-managed /32
	// or /128. If such an exact host route already exists, verify it
	// independently and retain its ownership.
	if err:=k.RouteAdd(&pin);err!=nil {
		if !isExists(err) {
			return nil,fmt.Errorf("pin VPN server %s outside TUN: %w",remote,err)
		}
	} else {
		g.owned=append(g.owned,pin)
	}
	if err:=g.VerifyUnderlay();err!=nil {
		_ = g.Close()
		return nil,err
	}
	return g,nil
}

func isExists(err error)bool{return errors.Is(err,syscall.EEXIST)}

// VerifyUnderlay fails closed if a route change made the protected server
// destination resolve through a different link. This does not install policy
// rules and cannot replace administrator-managed VRFs.
func(g *Guard)VerifyUnderlay()error{
	if g==nil || g.wanIndex==0{return nil}
	opts:=&netlink.RouteGetOptions{SrcAddr:g.source}
	if g.wanInterface!="" {opts.OifIndex=g.wanIndex}
	routes,err:=g.k.RouteGetWithOptions(g.remote,opts)
	if err!=nil{return fmt.Errorf("verify underlay server host route: %w",err)}
	if len(routes)!=1 || routes[0].LinkIndex!=g.wanIndex {
		return fmt.Errorf("VPN server %s would be routed into the tunnel instead of WAN index %d",g.remote,g.wanIndex)
	}
	return nil
}

// Install adds the authenticated prefixes to the main FIB via the TUN.
// Existing exact-prefix routes are never silently overwritten. Any failure
// rolls back only routes installed by this Guard (including the host pin).
func(g *Guard)Install(tunName string,pushes []netip.Prefix)error{
	if g==nil{return errors.New("route guard is nil")}
	if len(pushes)==0{return nil}
	link,err:=g.k.LinkByName(tunName)
	if err!=nil{return fmt.Errorf("pushed route TUN %q: %w",tunName,err)}
	if link.Attrs().Index==g.wanIndex{return errors.New("TUN and underlay must use different interfaces")}
	for _,p:=range pushes {
		// OpenVPN's def1 strategy: split /0 into two /1 routes. These
		// outrank the existing physical default without deleting or
		// replacing it. The protected server /32 or /128 wins over /1.
		for _,destination:=range expandDefault(p) {
			rt:=netlink.Route{Dst:ipNet(destination),LinkIndex:link.Attrs().Index,Table:mainTable,Protocol:ownedProtocol}
			if err:=g.k.RouteAdd(&rt);err!=nil{
				// A connected subnet route might have been created by
				// tun.Open / tun.OpenRouted. If the exact destination
				// already goes through this TUN, leave it managed by Linux.
				if isExists(err) && g.connectedOnTUN(destination,link.Attrs().Index) {
					continue
				}
				_ = g.Close()
				return fmt.Errorf("install pushed route %s via %s (existing route not overwritten): %w",destination,tunName,err)
			}
			g.owned=append(g.owned,rt)
		}
	}
	if err:=g.VerifyUnderlay();err!=nil{
		_ = g.Close()
		return err
	}
	return nil
}

func expandDefault(p netip.Prefix)[]netip.Prefix{
	if p.Bits()!=0{return []netip.Prefix{p}}
	if p.Addr().Is4(){
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"),netip.MustParsePrefix("128.0.0.0/1")}
	}
	return []netip.Prefix{netip.MustParsePrefix("::/1"),netip.MustParsePrefix("8000::/1")}
}

func(g *Guard)connectedOnTUN(prefix netip.Prefix,idx int)bool{
	family:=netlink.FAMILY_V4
	if prefix.Addr().Is6(){family=netlink.FAMILY_V6}
	filter:=&netlink.Route{Dst:ipNet(prefix),Table:mainTable}
	routes,err:=g.k.RouteListFiltered(family,filter,netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err!=nil{return false}
	for _,r:=range routes {
		if r.LinkIndex==idx && r.Dst!=nil && r.Dst.String()==prefix.String(){return true}
	}
	return false
}

// Close is safe to call more than once. It skips routes that no longer match
// the daemon's recorded link, gateway, table, protocol and priority.
func(g *Guard)Close()error{
	if g==nil{return nil}
	var out error
	for i:=len(g.owned)-1;i>=0;i--{
		rt:=g.owned[i]
		family:=netlink.FAMILY_V4
		if rt.Dst.IP.To4()==nil{family=netlink.FAMILY_V6}
		filter:=netlink.Route{Dst:rt.Dst,Table:mainTable,LinkIndex:rt.LinkIndex}
		found,err:=g.k.RouteListFiltered(family,&filter,netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if err!=nil {out=errors.Join(out,fmt.Errorf("inspect managed route %s: %w",rt.Dst,err));continue}
		for _,current:=range found {
			if current.Protocol!=ownedProtocol || current.Priority!=rt.Priority ||
				current.LinkIndex!=rt.LinkIndex || !current.Gw.Equal(rt.Gw) {continue}
			if err:=g.k.RouteDel(&rt);err!=nil {out=errors.Join(out,fmt.Errorf("remove managed route %s: %w",rt.Dst,err))}
			break
		}
	}
	g.owned=nil
	return out
}

func ipNet(p netip.Prefix)*net.IPNet{
	addr:=net.ParseIP(p.Addr().String())
	return &net.IPNet{IP:addr,Mask:net.CIDRMask(p.Bits(),p.Addr().BitLen())}
}
