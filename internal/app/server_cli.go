package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// runInstanceCLI edits the on-disk source-of-truth JSON configuration.
// Atomic rename prevents the watcher from observing partial JSON writes.
// The watcher reloads changed files automatically; --pid requests immediate
// reload via SIGHUP when using --reload-interval=0 or for faster application.
func runInstanceCLI(args []string,logger *slog.Logger)error{
	if len(args)==0{return errors.New("usage: mqvpn-server instance list|upsert|delete --config /path/to/server.json")}
	if logger==nil{logger=slog.Default()}
	action:=args[0]
	fs:=flag.NewFlagSet("instance "+action,flag.ContinueOnError)
	configPath:=fs.String("config","","server JSON configuration path")
	name:=fs.String("name","","instance name (upsert/delete)")
	listen:=fs.String("listen","","UDP bind address")
	tunName:=fs.String("tun","","pre-existing TUN interface name")
	peers:=fs.String("peers","","peer destination mapping JSON path")
	cert:=fs.String("cert","","TLS server certificate path")
	key:=fs.String("key","","TLS private key path")
	ca:=fs.String("client-ca","","client CA certificate path")
	path:=fs.String("path","","CONNECT-ETHERNET URI path")
	maxFrame:=fs.Int("max-frame",0,"maximum Ethernet frame bytes")
	pid:=fs.Int("pid",0,"optional running daemon PID to notify after a successful edit")
	if err:=fs.Parse(args[1:]);err!=nil{return err}
	if *configPath==""||fs.NArg()!=0{return errors.New("--config path is required, with no positional arguments")}
	if *pid<0||*pid==1{return errors.New("--pid must be 0 (disabled) or a daemon PID greater than 1")}
	if action!="list"&&action!="upsert"&&action!="delete"{
		return fmt.Errorf("unknown instance command %q; use list|upsert|delete",action)
	}
	cfg,err:=loadServerConfig(*configPath)
	if err!=nil{return err}
	if action=="list"{
		b,err:=json.MarshalIndent(cfg,"","  ")
		if err!=nil{return err}
		fmt.Println(string(b))
		return nil
	}
	if *name==""{return errors.New("--name is required for upsert/delete")}
	if action=="delete"{
		out:=cfg.Instances[:0]
		found:=false
		for _,inst:=range cfg.Instances{
			if inst.Name==*name{found=true;continue}
			out=append(out,inst)
		}
		if !found{return fmt.Errorf("instance %q not found",*name)}
		cfg.Instances=out
	}else{
		updates:=map[string]bool{}
		fs.Visit(func(f *flag.Flag){updates[f.Name]=true})
		var inst ServerInstance
		found:=false
		index:=-1
		for i,p:=range cfg.Instances{
			if p.Name==*name{inst=p;found=true;index=i;break}
		}
		if !found{inst.Name=*name}
		if updates["listen"]{inst.Listen=*listen}
		if updates["tun"]{inst.TUN=*tunName}
		if updates["peers"]{inst.Peers=*peers}
		if updates["cert"]{inst.Cert=*cert}
		if updates["key"]{inst.Key=*key}
		if updates["client-ca"]{inst.ClientCA=*ca}
		if updates["path"]{inst.Path=*path}
		if updates["max-frame"]{inst.MaxFrame=*maxFrame}
		if found{cfg.Instances[index]=inst}else{cfg.Instances=append(cfg.Instances,inst)}
	}
	// Validation includes the referenced cert/keys and peer JSON, not just
	// the shape of the configuration. Rejected edits leave the file intact.
	if _,err:=prepareServer(cfg);err!=nil{return fmt.Errorf("refuse invalid instance edit: %w",err)}
	if err:=writeServerConfigAtomic(*configPath,cfg);err!=nil{return err}
	logger.Info("server instances configuration updated","config",*configPath,"action",action,"instance",*name)
	if *pid>1{
		if err:=syscall.Kill(*pid,syscall.SIGHUP);err!=nil{
			return fmt.Errorf("configuration saved, but reload signal to PID %d failed: %w",*pid,err)
		}
		logger.Info("server reload requested","pid",*pid)
	}
	return nil
}

func writeServerConfigAtomic(path string,cfg ServerConfig)error{
	if !strings.HasSuffix(strings.ToLower(path),".json"){
		return fmt.Errorf("config path %q must end with .json",path)
	}
	data,err:=json.MarshalIndent(cfg,"","  ")
	if err!=nil{return err}
	data=append(data,'\n')
	dir:=filepath.Dir(path)
	temp,err:=os.CreateTemp(dir,".mqvpn-server-*.tmp")
	if err!=nil{return fmt.Errorf("create temp config in %s: %w",dir,err)}
	defer os.Remove(temp.Name())
	if err:=temp.Chmod(0600);err!=nil{temp.Close();return err}
	if _,err:=temp.Write(data);err!=nil{temp.Close();return err}
	if err:=temp.Sync();err!=nil{temp.Close();return err}
	if err:=temp.Close();err!=nil{return err}
	if err:=os.Rename(temp.Name(),path);err!=nil{
		return fmt.Errorf("replace %s atomically: %w",path,err)
	}
	return nil
}
