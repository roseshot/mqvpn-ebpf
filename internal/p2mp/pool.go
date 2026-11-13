package p2mp

import (
	"errors"
	"fmt"
	"net/netip"
)

// TunnelPool is instance-local and never installs Linux routes. All address
// allocation is serialized by the parent Hub's session lock.
type TunnelPool struct {
	prefix netip.Prefix
	serverIP netip.Addr
	reserved map[netip.Addr]bool
}

// NewTunnelPool validates a lease pool against the server's connected TUN
// subnet and static peer routes. No lease may shadow an existing destination.
func NewTunnelPool(cidr,serverAddress string,peers *Config)(*TunnelPool,error){
	if cidr=="" {
		if peers!=nil {for _,peer:=range peers.Peers {if peer.DynamicTunnelIP{return nil,fmt.Errorf("peer %s requires tunnel_pool",peer.ID)}}}
		return nil,nil
	}
	if peers==nil {return nil,errors.New("tunnel pool requires peer configuration")}
	pool,err:=netip.ParsePrefix(cidr)
	if err!=nil || !pool.IsValid() || pool.Addr().Is4In6() || pool.Addr().IsMulticast() {
		return nil,fmt.Errorf("invalid tunnel_pool %q",cidr)
	}
	if pool!=pool.Masked() {return nil,fmt.Errorf("tunnel_pool %q must use canonical subnet address",cidr)}
	server,err:=netip.ParsePrefix(serverAddress)
	if err!=nil || !server.IsValid(){return nil,fmt.Errorf("invalid server TUN address %q",serverAddress)}
	if pool!=server.Masked() {
		return nil,fmt.Errorf("tunnel_pool %s must exactly match server TUN connected prefix %s",pool,server.Masked())
	}
	dynamicPeers:=0
	reserved:=map[netip.Addr]bool{}
	for _,peer:=range peers.Peers {
		if peer.DynamicTunnelIP {dynamicPeers++}
		for _,route:=range peer.Routes {
			if route.Addr().Is4()!=pool.Addr().Is4() {continue}
			if pool.Contains(route.Addr()) && route.Bits()==route.Addr().BitLen() {
				// A static peer's exact host route reserves this IP, allowing
				// static and dynamic clients to coexist within one tenant.
				reserved[route.Addr()]=true
				continue
			}
			if route.Contains(pool.Addr()) || pool.Contains(route.Addr()) {
				return nil,fmt.Errorf("peer %s route %s overlaps tunnel_pool %s",peer.ID,route,pool)
			}
		}
	}
	if dynamicPeers==0 {return nil,errors.New("tunnel_pool has no peers marked dynamic_tunnel_ip")}
	p:=&TunnelPool{prefix:pool,serverIP:server.Addr(),reserved:reserved}
	var count int
	for addr:=pool.Addr().Next(); addr.IsValid()&&pool.Contains(addr)&&count<dynamicPeers; addr=addr.Next(){
		if p.usable(addr){count++}
	}
	if count<dynamicPeers {
		return nil,fmt.Errorf("tunnel_pool %s cannot supply %d unique peer addresses",pool,dynamicPeers)
	}
	return p,nil
}

// usable skips the server, the network address and IPv4 broadcast. IPv6
// supports /64 and larger pools without eagerly allocating a giant bitmap.
func(p *TunnelPool)usable(addr netip.Addr)bool{
	if !addr.IsValid() || !p.prefix.Contains(addr) || addr==p.serverIP || addr==p.prefix.Addr() || p.reserved[addr] {return false}
	if addr.Is4(){
		// IPv4 subnet-directed broadcast is the final address, except for
		// /31-/32 which cannot provide a traditional host lease.
		if p.prefix.Bits()>=31 {return false}
		if !p.prefix.Contains(addr.Next()){return false}
	}
	return true
}

func(p *TunnelPool)allocate(active map[string]*Session)(netip.Prefix,error){
	if p==nil{return netip.Prefix{},errors.New("dynamic tunnel pool disabled")}
	used:=make(map[netip.Addr]bool,len(active))
	for _,session:=range active {
		if session.tunnelAddress.IsValid(){used[session.tunnelAddress.Addr()]=true}
	}
	// At most 1024 peers are accepted, so scan is bounded to available
	// host candidates plus reserved network/server/broadcast slots.
	for addr,tries:=p.prefix.Addr().Next(),0; addr.IsValid()&&p.prefix.Contains(addr)&&tries<len(active)+4; addr,tries=addr.Next(),tries+1 {
		if p.usable(addr)&&!used[addr] {return netip.PrefixFrom(addr,p.prefix.Bits()),nil}
	}
	return netip.Prefix{},fmt.Errorf("tunnel_pool %s exhausted",p.prefix)
}
