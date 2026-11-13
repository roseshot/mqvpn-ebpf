package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// clientEndpoint separates the physical UDP/TCP destination from its
// authenticated tenant identity. A pinned connect_ip never changes SNI.
type clientEndpoint struct {
	dialAddress string
	serverName string
	requestURL string
}

// planClientEndpoint accepts exactly one configuration model:
// server = tenant DNS name[:port], path = optional canonical CONNECT path,
// connect_ip = optional literal underlay destination. No URL/SNI aliases.
func planClientEndpoint(server,path,connectIP string)(clientEndpoint,error){
	if server=="" || strings.ContainsAny(server,"/?#@\\%") || strings.Contains(server,"://") {
		return clientEndpoint{},errors.New("server must be an authenticated DNS hostname[:port] (use path separately)")
	}
	u,err:=url.Parse("https://"+server)
	if err!=nil || u.Host=="" || u.Opaque!="" || u.Path!="" || u.RawQuery!="" || u.Fragment!="" || u.User!=nil {
		return clientEndpoint{},errors.New("server must be a DNS hostname[:port]")
	}
	host:=strings.ToLower(u.Hostname())
	if err:=validateSNI(host);err!=nil{return clientEndpoint{},fmt.Errorf("server DNS identity: %w",err)}
	if strings.HasSuffix(u.Host,":"){return clientEndpoint{},errors.New("server port cannot be empty")}
	port:=u.Port()
	if port!="" {
		p,err:=strconv.Atoi(port)
		if err!=nil||p<1||p>65535{return clientEndpoint{},fmt.Errorf("invalid server port %q",port)}
	} else {port="443"}
	if path==""{path=defaultPath}
	if err:=validateMasquePath(path);err!=nil{return clientEndpoint{},err}
	dialHost:=host
	if connectIP!=""{
		ip,err:=netip.ParseAddr(connectIP)
		if err!=nil || !ip.IsValid() || ip.Zone()!="" || ip.IsUnspecified() || ip.IsMulticast(){
			return clientEndpoint{},fmt.Errorf("invalid connect_ip %q: expected unicast IP literal",connectIP)
		}
		dialHost=ip.String()
	}
	authority:=net.JoinHostPort(host,port)
	return clientEndpoint{
		dialAddress:net.JoinHostPort(dialHost,port),
		serverName:host,
		requestURL:(&url.URL{Scheme:"https",Host:authority,Path:path}).String(),
	},nil
}
