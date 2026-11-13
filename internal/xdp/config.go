//go:build linux

package xdp

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Config is optional. One dispatcher is attached to each WAN NIC, and its
// destination-UDP-port map covers *all* listeners in the server process.
// There is no per-instance XDP program, UMEM, or RX-queue ownership.
type Config struct {
	Interfaces []string `json:"interfaces,omitempty"`
	Object string `json:"object,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// Normalize checks syntax without touching kernel eBPF state. XDP is opt-in.
// A compiled ELF is required for any enabled interface.
func (c Config) Normalize() (Config,error) {
	if len(c.Interfaces)==0 {
		if c.Object!="" || c.Mode!="" {return Config{},errors.New("XDP interfaces must be set when object or mode is configured")}
		return Config{},nil
	}
	if c.Object=="" {return Config{},errors.New("xdp.object must point to a compiled BPF ELF")}
	if c.Mode=="" {c.Mode="driver"}
	if c.Mode!="driver"&&c.Mode!="generic" {return Config{},fmt.Errorf("invalid XDP mode %q (driver|generic)",c.Mode)}
	if len(c.Interfaces)>16 {return Config{},errors.New("too many XDP interfaces (max 16)")}
	seen:=make(map[string]bool)
	for _,name:=range c.Interfaces {
		if name==""||strings.ContainsAny(name,"/ 	
") {return Config{},fmt.Errorf("invalid XDP interface name %q",name)}
		if seen[name] {return Config{},fmt.Errorf("duplicate XDP interface %q",name)}
		seen[name]=true
	}
	sort.Strings(c.Interfaces)
	return c,nil
}

// ListenersToPorts extracts distinct server-side UDP destination ports.
// Neither the inner VPN data nor MPQUIC path IDs are used as map keys.
func ListenersToPorts(listens []string)([]uint16,error) {
	seen:=make(map[uint16]bool,len(listens))
	var ports []uint16
	for _,listen:=range listens {
		_,port,err:=net.SplitHostPort(listen)
		if err!=nil{return nil,fmt.Errorf("invalid UDP listen address %q: %w",listen,err)}
		n,err:=strconv.ParseUint(port,10,16)
		if err!=nil||n==0{return nil,fmt.Errorf("invalid UDP port %q",port)}
		p:=uint16(n)
		if !seen[p]{ports=append(ports,p);seen[p]=true}
	}
	if len(ports)>1024{return nil,errors.New("XDP port map limited to 1024 entries")}
	sort.Slice(ports,func(i,j int)bool{return ports[i]<ports[j]})
	return ports,nil
}
