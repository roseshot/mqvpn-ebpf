package app

import (
	"os"
	"strings"
	"testing"
)

func sampleInstance(name,listen,tun string)ServerInstance {
	return ServerInstance{Name:name,Listen:listen,TUN:tun,Peers:"peers.json",Cert:"s.crt",Key:"s.key",ClientCA:"ca.crt"}
}

func TestServerMultiInstanceConfig(t *testing.T){
	cfg:=ServerConfig{Instances:[]ServerInstance{sampleInstance("siteA",":4433","mq0"),sampleInstance("siteB",":4434","mq1")}}
	if err:=cfg.Validate();err!=nil{t.Fatal(err)}
	if cfg.Instances[0].Path!=defaultPath || cfg.Instances[1].MaxFrame!=1160{t.Fatal("wrong defaults",cfg)}
}
func TestDuplicateTUNAndPortRejected(t *testing.T){
	a:=sampleInstance("a",":4433","mq0")
	for _,b:=range []ServerInstance{
		sampleInstance("b",":4434","mq0"),
		sampleInstance("b","0.0.0.0:4433","mq1"),
		sampleInstance("a",":4434","mq1"),
	}{
		cfg:=ServerConfig{Instances:[]ServerInstance{a,b}}
		if err:=cfg.Validate();err==nil{t.Fatalf("accepted duplicate %+v",b)}
	}
}
func TestServerConfigMissingField(t *testing.T){
	cfg:=ServerConfig{Instances:[]ServerInstance{sampleInstance("a",":4433","mq0")}}
	cfg.Instances[0].ClientCA=""
	if err:=cfg.Validate();err==nil||!strings.Contains(err.Error(),"client_ca"){t.Fatal(err)}
}
func TestReadServerConfigRejectsUnknown(t *testing.T){
	path:=t.TempDir()+"/instances.json"
	if err:=os.WriteFile(path,[]byte(`{"instances":[{"name":"a","listen":":4433","tun":"mq0","peers":"p","cert":"c","key":"k","client_ca":"ca","unknown":true}]}`),0600);err!=nil{t.Fatal(err)}
	if _,err:=loadServerConfig(path);err==nil{t.Fatal("unknown key accepted")}
}
