package app

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
)

// clientFileConfig is the concise daemon configuration. Only server, address,
// ca, cert and key are required in a standalone YAML file. Everything else is
// optional and the long-standing command-line flags remain available.
type clientFileConfig struct {
	Server string `yaml:"server,omitempty"`
	URL string `yaml:"url,omitempty"` // legacy full endpoint, if needed
	Address string `yaml:"address,omitempty"`
	CA string `yaml:"ca,omitempty"`
	Cert string `yaml:"cert,omitempty"`
	Key string `yaml:"key,omitempty"`

	TUN string `yaml:"tun,omitempty"`
	ConnectIP string `yaml:"connect_ip,omitempty"`
	ServerName string `yaml:"server_name,omitempty"`
	SourceIP string `yaml:"source_ip,omitempty"`
	SourceInterface string `yaml:"source_interface,omitempty"`
	WAN2IP string `yaml:"wan2_ip,omitempty"`
	WAN2Interface string `yaml:"wan2_interface,omitempty"`
	MTU int `yaml:"mtu,omitempty"`
	MaxFrame int `yaml:"max_frame,omitempty"`
	Transport string `yaml:"transport,omitempty"`
	UDPDialTimeout string `yaml:"udp_dial_timeout,omitempty"`
	TCPPort int `yaml:"tcp_port,omitempty"`
	TC *clientFileTC `yaml:"tc,omitempty"`
}

type clientFileTC struct {
	Mode string `yaml:"mode,omitempty"`
	Object string `yaml:"object,omitempty"`
	MSSClamp string `yaml:"mss_clamp,omitempty"`
	Stats *bool `yaml:"stats,omitempty"`
}

func loadClientFile(path string) (clientFileConfig,error) {
	var cfg clientFileConfig
	if err:=configfile.Read(path,&cfg);err!=nil{return clientFileConfig{},err}
	if cfg.Server!="" && cfg.URL!="" {
		return clientFileConfig{},fmt.Errorf("client YAML cannot specify both server and url")
	}
	return cfg,nil
}

// expandClientServer accepts a DNS hostname, host:port or an HTTPS URL.
// A missing path is the standard MASQUE CONNECT-ETHERNET endpoint.
func expandClientServer(server string)(string,error){
	if server==""{return "",fmt.Errorf("client requires server (or legacy --url)")}
	raw:=server
	if !strings.Contains(raw,"://"){raw="https://"+raw}
	u,err:=url.Parse(raw)
	if err!=nil{return "",fmt.Errorf("invalid server %q: %w",server,err)}
	if u.Scheme!="https"||u.Host==""||u.Opaque!="" {
		return "",fmt.Errorf("invalid server %q: expected DNS host[:port] or https URL",server)
	}
	if u.Path=="" {u.Path=defaultPath}
	return u.String(),nil
}
