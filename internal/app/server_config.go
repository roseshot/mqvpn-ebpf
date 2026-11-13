package app

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/xdp"
)

// defaultServerListen is the shared QUIC/UDP bind when YAML omits listen.
// Optional TCP fallback uses TCP/443 independently.
const defaultServerListen = "0.0.0.0:443"

// ServerInstance owns an isolated L3 P2MP forwarding domain and mTLS identity.
// All instances share ServerConfig.Listen and one HTTP/3 QUIC listener.
type ServerInstance struct {
	Name       string `yaml:"name"`
	ServerName string `yaml:"server_name"`
	TUN        string `yaml:"tun"`
	Address    string `yaml:"address"`
	TunnelPool string `yaml:"tunnel_pool,omitempty"`
	PushRoutes []string `yaml:"push_routes,omitempty"`
	MTU        int    `yaml:"mtu,omitempty"`
	Peers      string `yaml:"peers"`
	Path       string `yaml:"path,omitempty"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
	ClientCA   string `yaml:"client_ca"`
	MaxFrame   int    `yaml:"max_frame,omitempty"`
	TC         *tcebpf.Config `yaml:"tc,omitempty"`
}

// TCPFallbackConfig enables a separate TCP/443 TLS listener. It shares the
// authenticated SNI instance registry, but not the UDP socket or MPQUIC.
type TCPFallbackConfig struct {
	Enabled bool `yaml:"enabled"`
	Listen string `yaml:"listen,omitempty"`
}

type ServerConfig struct {
	TCPFallback TCPFallbackConfig `yaml:"tcp_fallback,omitempty"`
	Listen    string           `yaml:"listen,omitempty"`
	WANInterfaces []string `yaml:"wan_interfaces,omitempty"`
	XDP       *xdp.Config      `yaml:"xdp,omitempty"`
	Instances []ServerInstance `yaml:"instances"`
}

func loadServerConfig(path string) (ServerConfig, error) {
	var cfg ServerConfig
	if err := configfile.Read(path, &cfg); err != nil { return ServerConfig{}, err }
	if err := cfg.Validate(); err != nil { return ServerConfig{}, err }
	return cfg, nil
}

func (c *ServerConfig) Validate() error {
	if c.Listen == "" { c.Listen = defaultServerListen }
	if c.TCPFallback.Enabled && c.TCPFallback.Listen=="" {
		c.TCPFallback.Listen="0.0.0.0:443"
	}
	if !c.TCPFallback.Enabled && c.TCPFallback.Listen!="" {
		return errors.New("tcp_fallback.listen requires tcp_fallback.enabled: true")
	}
	if c.TCPFallback.Enabled {
		_, tcpPort, err:=net.SplitHostPort(c.TCPFallback.Listen)
		if err!=nil {return fmt.Errorf("invalid TCP fallback listen %q: %w",c.TCPFallback.Listen,err)}
		n,err:=strconv.Atoi(tcpPort)
		if err!=nil||n<1||n>65535{return fmt.Errorf("invalid TCP fallback port %q",tcpPort)}
	}
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil { return fmt.Errorf("invalid shared listen %q: %w", c.Listen, err) }
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 { return fmt.Errorf("invalid shared listen UDP port %q", port) }
	if c.XDP != nil {
		normalized, err := c.XDP.Normalize()
		if err != nil { return fmt.Errorf("XDP: %w", err) }
		c.XDP = &normalized
	}
	if len(c.Instances) == 0 { return errors.New("at least one VPN instance is required") }
	if len(c.Instances) > 128 { return errors.New("maximum 128 VPN instances") }
	seenWAN:=map[string]bool{}
	for _,name:=range c.WANInterfaces {
		if strings.TrimSpace(name)!=name || name=="" || seenWAN[name] {
			return fmt.Errorf("invalid or duplicate wan_interfaces entry %q",name)
		}
		seenWAN[name]=true
	}
	names, tuns, sni := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range c.Instances {
		inst := &c.Instances[i]
		if inst.Path == "" { inst.Path = defaultPath }
		if inst.Name == "" || inst.ServerName == "" || inst.TUN == "" ||
			inst.Peers == "" || inst.Cert == "" || inst.Key == "" || inst.ClientCA == "" {
			return fmt.Errorf("instance %d requires name, server_name, tun, address, peers, cert, key and client_ca", i)
		}
		if err:=mtu.ValidateRequest(inst.TUN,inst.Address,inst.MTU,inst.MaxFrame);err!=nil{
			return fmt.Errorf("instance %s: %w",inst.Name,err)
		}
		routes,err:=routepush.Parse(inst.PushRoutes)
		if err!=nil{return fmt.Errorf("instance %s push_routes: %w",inst.Name,err)}
		if len(routes)>0 {
			inst.PushRoutes=make([]string,len(routes))
			for i,p:=range routes {inst.PushRoutes[i]=p.String()}
		}
		if inst.TC==nil {
			defaultTC:=tcebpf.DefaultConfig()
			inst.TC=&defaultTC
		} else {
			next,err:=inst.TC.Normalize()
			if err!=nil{return fmt.Errorf("instance %s TC eBPF: %w",inst.Name,err)}
			inst.TC=&next // Preserve explicit mode: off; nil means default auto.
		}
		inst.ServerName = strings.ToLower(inst.ServerName)
		if err := validateSNI(inst.ServerName); err != nil { return fmt.Errorf("instance %s: %w", inst.Name, err) }
		if err:=validateMasquePath(inst.Path);err!=nil{return fmt.Errorf("instance %s MASQUE path: %w",inst.Name,err)}
		if inst.MaxFrame != 0 && (inst.MaxFrame < 64 || inst.MaxFrame > 65535) { return fmt.Errorf("instance %s invalid max_frame", inst.Name) }
		if names[inst.Name] || tuns[inst.TUN] || sni[inst.ServerName] {
			return fmt.Errorf("duplicate instance name, TUN or TLS server_name in %s", inst.Name)
		}
		names[inst.Name], tuns[inst.TUN], sni[inst.ServerName] = true, true, true
	}
	return nil
}

// SNI must be an unambiguous DNS hostname, not an IP literal or wildcard.
// An IP-literal HTTPS URL cannot reliably transmit SNI for demultiplexing.
func validateSNI(s string) error {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil || !strings.Contains(s, ".") {
		return fmt.Errorf("invalid server_name %q: use a DNS hostname, not an IP", s)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS server_name %q", s)
		}
		for _, b := range []byte(label) {
			if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' {
				continue
			}
			return fmt.Errorf("invalid DNS server_name %q", s)
		}
	}
	return nil
}
