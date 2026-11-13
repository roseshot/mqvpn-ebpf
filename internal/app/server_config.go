package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"io"
	"strconv"
	"strings"

 "github.com/roseshot/mqvpn-ebpf/internal/xdp"
)

// ServerInstance is an independent QUIC listener, TUN and peer namespace.
// The daemon attaches to an existing TUN; IP/multicast/routes are configured
// by external system administration, not by the daemon.
type ServerInstance struct {
	Name     string `json:"name"`
	Listen   string `json:"listen"`
	TUN      string `json:"tun"`
	Peers    string `json:"peers"`
	Path     string `json:"path,omitempty"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"client_ca"`
	MaxFrame int    `json:"max_frame,omitempty"`
}

type ServerConfig struct {
	Instances []ServerInstance `json:"instances"`
	XDP *xdp.Config `json:"xdp,omitempty"`
}

func loadServerConfig(path string) (ServerConfig,error) {
	f,err:=os.Open(path)
	if err!=nil{return ServerConfig{},fmt.Errorf("open server configuration: %w",err)}
	defer f.Close()
	var cfg ServerConfig
	d:=json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err:=d.Decode(&cfg);err!=nil{return ServerConfig{},fmt.Errorf("decode server configuration: %w",err)}
	var extra any
	if err:=d.Decode(&extra);err==nil {
		return ServerConfig{},errors.New("multiple JSON documents in server configuration")
	} else if !errors.Is(err,io.EOF) {
		return ServerConfig{},fmt.Errorf("invalid trailing data in server configuration: %w",err)
	}
	if err:=cfg.Validate();err!=nil{return ServerConfig{},err}
	return cfg,nil
}

func (c *ServerConfig)Validate()error {
	if c.XDP != nil {
		normalized,err:=c.XDP.Normalize()
		if err!=nil{return fmt.Errorf("XDP configuration: %w",err)}
		c.XDP=&normalized
	}
	if len(c.Instances)==0{return errors.New("server requires at least one instance")}
	if len(c.Instances)>128{return errors.New("server instance count exceeds 128")}
	names:=map[string]bool{}
	tuns:=map[string]bool{}
	ports:=map[string]bool{}
	for i:=range c.Instances {
		s:=&c.Instances[i]
		if s.Path==""{s.Path=defaultPath}
		if s.MaxFrame==0{s.MaxFrame=1160}
		if s.Name=="" || s.TUN=="" || s.Listen=="" || s.Peers=="" || s.Cert=="" || s.Key=="" || s.ClientCA=="" {
			return fmt.Errorf("instance %d must set name, listen, tun, peers, cert, key, client_ca",i)
		}
		if !strings.HasPrefix(s.Path,"/"){return fmt.Errorf("instance %s path must begin with /",s.Name)}
		if s.MaxFrame<64||s.MaxFrame>65535{return fmt.Errorf("instance %s max_frame outside 64..65535",s.Name)}
		_,port,err:=net.SplitHostPort(s.Listen)
		if err!=nil{return fmt.Errorf("instance %s invalid listen address: %w",s.Name,err)}
		p,err:=strconv.Atoi(port)
		if err!=nil||p<1||p>65535{return fmt.Errorf("instance %s invalid listen port %s",s.Name,port)}
		// Reject overlapping wildcard listeners conservatively: one UDP port
		// per instance. Future per-address socket sharing needs explicit logic.
		if names[s.Name]||tuns[s.TUN]||ports[port]{
			return fmt.Errorf("duplicate instance name, TUN, or UDP port at %s",s.Name)
		}
		names[s.Name]=true;tuns[s.TUN]=true;ports[port]=true
	}
	return nil
}
