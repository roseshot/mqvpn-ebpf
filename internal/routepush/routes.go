// Package routepush validates server-advertised routes and serializes the
// authenticated CONNECT response header. Linux route changes live in its
// separate netlink implementation.
package routepush

import (
	"fmt"
	"net/netip"
	"strings"
)

const Header = "Mqvpn-Routes"
const MaxRoutes = 64
const MaxHeaderLength = 4096

// Parse validates canonical IP CIDRs, eliminating duplicate and ambiguous
// routes before they are sent or installed. /0 is allowed for full-tunnel.
func Parse(values []string) ([]netip.Prefix, error) {
	if len(values)>MaxRoutes {return nil,fmt.Errorf("too many pushed routes (max %d)",MaxRoutes)}
	if len(values)==0{return nil,nil}
	out:=make([]netip.Prefix,0,len(values))
	seen:=make(map[netip.Prefix]bool,len(values))
	for _,raw:=range values {
		if strings.TrimSpace(raw)!=raw || raw=="" {
			return nil,fmt.Errorf("invalid pushed route %q",raw)
		}
		p,err:=netip.ParsePrefix(raw)
		if err!=nil || !p.IsValid() || p.Addr().Is4In6() {
			return nil,fmt.Errorf("invalid pushed route %q",raw)
		}
		p=p.Masked()
		if p.Bits()!=0 && (p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() ||
			(p.Addr().Is4() && p.Addr()==netip.MustParseAddr("255.255.255.255"))) {
			return nil,fmt.Errorf("unsafe pushed route %q",raw)
		}
		if seen[p]{return nil,fmt.Errorf("duplicate pushed route %s",p)}
		seen[p]=true
		out=append(out,p)
	}
	if len(Encode(out))>MaxHeaderLength {return nil,fmt.Errorf("pushed routes header exceeds %d bytes",MaxHeaderLength)}
	return out,nil
}

func Encode(routes []netip.Prefix)string{
	parts:=make([]string,0,len(routes))
	for _,p:=range routes{parts=append(parts,p.String())}
	return strings.Join(parts,",")
}

func Decode(header string)([]netip.Prefix,error){
	if header==""{return nil,nil}
	if len(header)>MaxHeaderLength{return nil,fmt.Errorf("pushed routes header exceeds %d bytes",MaxHeaderLength)}
	parts:=strings.Split(header,",")
	for i,p:=range parts {parts[i]=strings.TrimSpace(p)}
	return Parse(parts)
}

// WithDNSHostRoutes adds exactly one /32 (IPv4) or /128 (IPv6) host
// route for each authenticated DNS server when enabled. It does not
// change ordinary pushed routes, and never appends duplicate prefixes.
// Using the existing route Guard makes DNS routes participate in underlay
// protection, conflict detection, rollback, and disconnect cleanup.
func WithDNSHostRoutes(pushed []netip.Prefix,servers []netip.Addr,enabled bool)[]netip.Prefix{
	result:=append([]netip.Prefix(nil),pushed...)
	if !enabled || len(servers)==0{return result}
	seen:=make(map[netip.Prefix]bool,len(pushed)+len(servers))
	for _,p:=range pushed{seen[p]=true}
	for _,ip:=range servers{
		if !ip.IsValid(){continue}
		host:=netip.PrefixFrom(ip,ip.BitLen())
		if seen[host]{continue}
		seen[host]=true
		result=append(result,host)
	}
	return result
}
