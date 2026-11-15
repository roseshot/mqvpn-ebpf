package app

import "github.com/roseshot/mqvpn-ebpf/internal/configfile"

// clientFileConfig is the current daemon configuration. Server is always
// the authenticated DNS identity. connect_ip optionally pins the underlay
// destination without changing TLS SNI. No old URL/SNI aliases are accepted.
type clientFileConfig struct {
	Server         string        `yaml:"server,omitempty"`
	Path           string        `yaml:"path,omitempty"`
	Address        string        `yaml:"address,omitempty"`
	CA             string        `yaml:"ca,omitempty"`
	Cert           string        `yaml:"cert,omitempty"`
	Key            string        `yaml:"key,omitempty"`
	TUN            string        `yaml:"tun,omitempty"`
	ConnectIP      string        `yaml:"connect_ip,omitempty"`
	WANs           []clientWAN   `yaml:"wans,omitempty"`
	UseServerWANs  *bool         `yaml:"use_server_wans,omitempty"`
	MTU            int           `yaml:"mtu,omitempty"`
	MaxFrame       int           `yaml:"max_frame,omitempty"`
	Transport      string        `yaml:"transport,omitempty"`
	PathScheduler  string        `yaml:"path_scheduler,omitempty"`
	StickyVoIP     *bool         `yaml:"sticky_voip,omitempty"`
	UDPDialTimeout string        `yaml:"udp_dial_timeout,omitempty"`
	TCPPort        int           `yaml:"tcp_port,omitempty"`
	TC             *clientFileTC `yaml:"tc,omitempty"`
	AcceptRoutes   *bool         `yaml:"accept_routes,omitempty"`
	AcceptDNS      *bool         `yaml:"accept_dns,omitempty"`
	DNSRoutes      *bool         `yaml:"dns_routes,omitempty"`
	Reconnect      *bool         `yaml:"reconnect,omitempty"`
}

type clientFileTC struct {
	Mode     string `yaml:"mode,omitempty"`
	Object   string `yaml:"object,omitempty"`
	MSSClamp string `yaml:"mss_clamp,omitempty"`
	Stats    *bool  `yaml:"stats,omitempty"`
}

func loadClientFile(path string) (clientFileConfig, error) {
	var cfg clientFileConfig
	if err := configfile.Read(path, &cfg); err != nil {
		return clientFileConfig{}, err
	}
	return cfg, nil
}
