// Package dnspush validates authenticated Server-pushed DNS addresses.
// Linux uses systemd-resolved or a per-interface resolvconf entry.
package dnspush

import (
	"fmt"
	"net/netip"
	"strings"
)

const Header="Mqvpn-DNS"
const MaxServers=8
const MaxHeaderLength=512

// Parse accepts a bounded list of literal IPv4 and IPv6 unicast DNS
// addresses. No hostnames, ports, scope zones or encoded delimiters.
func Parse(values []string)([]netip.Addr,error){
	if len(values)>MaxServers{return nil,fmt.Errorf("too many pushed DNS servers (max %d)",MaxServers)}
	result:=make([]netip.Addr,0,len(values))
	seen:=map[netip.Addr]bool{}
	for _,raw:=range values{
		if raw=="" || raw!=strings.TrimSpace(raw) || len(raw)>64{
			return nil,fmt.Errorf("invalid pushed DNS address %q",raw)
		}
		ip,err:=netip.ParseAddr(raw)
		if err!=nil||!ip.IsValid()||ip.Is4In6()||ip.Zone()!=""||
			ip.IsUnspecified()||ip.IsMulticast()||ip.IsLoopback()||ip.IsLinkLocalUnicast()||
			(ip.Is4()&&ip==netip.MustParseAddr("255.255.255.255")){
			return nil,fmt.Errorf("invalid pushed DNS address %q",raw)
		}
		if seen[ip]{return nil,fmt.Errorf("duplicate pushed DNS address %s",ip)}
		seen[ip]=true
		result=append(result,ip)
	}
	if len(Encode(result))>MaxHeaderLength{return nil,fmt.Errorf("pushed DNS header exceeds %d bytes",MaxHeaderLength)}
	return result,nil
}

func Encode(servers []netip.Addr)string{
	parts:=make([]string,0,len(servers))
	for _,ip:=range servers{parts=append(parts,ip.String())}
	return strings.Join(parts,",")
}

func Decode(value string)([]netip.Addr,error){
	if value==""{return nil,nil}
	if len(value)>MaxHeaderLength{return nil,fmt.Errorf("pushed DNS header exceeds %d bytes",MaxHeaderLength)}
	return Parse(strings.Split(value,","))
}
