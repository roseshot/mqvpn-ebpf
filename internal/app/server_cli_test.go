package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestServerInstanceCLIUpsertAndDelete(t *testing.T){
	original,_:=testServerFiles(t)
	configPath:=filepath.Join(t.TempDir(),"server.json")
	bytes,err:=json.Marshal(original)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(configPath,bytes,0600);err!=nil{t.Fatal(err)}
	first:=original.Instances[0]
	err=runInstanceCLI([]string{
		"upsert","--config",configPath,
		"--name","edge-b","--listen",":4434","--tun","mq1",
		"--peers",first.Peers,"--cert",first.Cert,
		"--key",first.Key,"--client-ca",first.ClientCA,
	},nil)
	if err!=nil{t.Fatal(err)}
	cfg,err:=loadServerConfig(configPath)
	if err!=nil{t.Fatal(err)}
	if len(cfg.Instances)!=2||cfg.Instances[1].TUN!="mq1"{t.Fatalf("bad upsert: %+v",cfg)}
	// Updating one flag must preserve all other fields for the instance.
	err=runInstanceCLI([]string{
		"upsert","--config",configPath,"--name","edge-b","--listen",":4435",
	},nil)
	if err!=nil{t.Fatal(err)}
	cfg,err=loadServerConfig(configPath)
	if err!=nil{t.Fatal(err)}
	if cfg.Instances[1].Listen!=":4435"||cfg.Instances[1].TUN!="mq1"{t.Fatalf("bad partial edit %+v",cfg.Instances[1])}
	err=runInstanceCLI([]string{"delete","--config",configPath,"--name","edge-b"},nil)
	if err!=nil{t.Fatal(err)}
	cfg,err=loadServerConfig(configPath)
	if err!=nil{t.Fatal(err)}
	if len(cfg.Instances)!=1||cfg.Instances[0].Name!="edge-a"{t.Fatalf("bad delete %+v",cfg)}
	stat,err:=os.Stat(configPath)
	if err!=nil{t.Fatal(err)}
	if stat.Mode().Perm()!=0600{t.Fatalf("config permissions %v",stat.Mode())}
}

func TestInstanceEditBadConfigPreservesFile(t *testing.T){
	original,_:=testServerFiles(t)
	configPath:=filepath.Join(t.TempDir(),"server.json")
	bytes,err:=json.Marshal(original)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(configPath,bytes,0600);err!=nil{t.Fatal(err)}
	err=runInstanceCLI([]string{
		"upsert","--config",configPath,"--name","edge-b",
		"--listen",":4433","--tun","mq1",
		"--peers",original.Instances[0].Peers,
		"--cert",original.Instances[0].Cert,
		"--key",original.Instances[0].Key,
		"--client-ca",original.Instances[0].ClientCA,
	},nil)
	if err==nil{t.Fatal("duplicate UDP listener accepted")}
	after,err:=os.ReadFile(configPath)
	if err!=nil{t.Fatal(err)}
	if string(after)!=string(bytes){t.Fatal("invalid edit modified original config")}
}


func TestInstanceCLIEditPreservesPermissions(t *testing.T){
	cfg,_:=testServerFiles(t)
	configPath:=filepath.Join(t.TempDir(),"server.json")
	bytes,err:=json.Marshal(cfg)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(configPath,bytes,0640);err!=nil{t.Fatal(err)}
	if err:=os.Chmod(configPath,0640);err!=nil{t.Fatal(err)}
	if err:=runInstanceCLI([]string{
		"upsert","--config",configPath,"--name","edge-a","--listen",":4437",
	},nil);err!=nil{t.Fatal(err)}
	stat,err:=os.Stat(configPath)
	if err!=nil{t.Fatal(err)}
	if stat.Mode().Perm()!=0640{t.Fatalf("config access mode changed to %v",stat.Mode().Perm())}
}
