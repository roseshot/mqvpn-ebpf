package app

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

// runInstanceCLI edits the YAML instance configuration. Shared UDP listen is top-level.
// Atomic rename prevents the watcher from observing partial JSON writes.
// Existing file owner and permissions are preserved.
// The watcher reloads changed files automatically; --pid requests immediate
// reload via SIGHUP when using --reload-interval=0 or for faster application.
func runInstanceCLI(args []string,logger *slog.Logger)error{
	if len(args)==0{return errors.New("usage: mqvpn-server instance list|upsert|delete --config /path/to/server.yaml")}
	if logger==nil{logger=slog.Default()}
	action:=args[0]
	fs:=flag.NewFlagSet("instance "+action,flag.ContinueOnError)
	configPath:=fs.String("config","","server YAML configuration path")
	name:=fs.String("name","","instance name (upsert/delete)")
	serverName:=fs.String("server-name","","TLS SNI hostname unique to this VPN instance")
	tunName:=fs.String("tun","","Linux TUN interface name (created or attached by daemon)")
	address:=fs.String("address","","TUN local host IPv4/IPv6 CIDR (required)")
	tunnelPool:=fs.String("tunnel-pool","","optional per-instance connected-prefix dynamic Tunnel IP pool")
	pushRoutes:=fs.String("push-routes","","optional comma-separated CIDRs to push to authenticated Clients")
	mtu:=fs.Int("mtu",0,"TUN MTU (0 or omitted = automatic based on WAN, capped at 1400)")
	peers:=fs.String("peers","","peer destination mapping YAML path")
	cert:=fs.String("cert","","TLS server certificate path")
	key:=fs.String("key","","TLS private key path")
	ca:=fs.String("client-ca","","client CA certificate path")
	path:=fs.String("path","","CONNECT-ETHERNET URI path")
	maxFrame:=fs.Int("max-frame",0,"maximum Ethernet frame bytes")
	tcMode:=fs.String("tc-mode","","TUN TCX mode: off, auto or required")
	tcObject:=fs.String("tc-object","","per-instance compiled TUN TCX eBPF ELF")
	mssClamp:=fs.String("mss-clamp","","TUN TCP MSS clamp: off, auto or numeric")
	tcStats:=fs.Bool("tc-stats",false,"enable TUN TCX packet counters")
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
		b,err:=configfile.Marshal(*configPath,cfg)
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
		if updates["server-name"]{inst.ServerName=*serverName}
		if updates["tun"]{inst.TUN=*tunName}
		if updates["address"]{inst.Address=*address}
		if updates["tunnel-pool"]{inst.TunnelPool=*tunnelPool}
		if updates["push-routes"] {
			inst.PushRoutes=nil
			if *pushRoutes!=""{inst.PushRoutes=strings.Split(*pushRoutes,",")}
		}
		if updates["mtu"]{inst.MTU=*mtu}
		if updates["peers"]{inst.Peers=*peers}
		if updates["cert"]{inst.Cert=*cert}
		if updates["key"]{inst.Key=*key}
		if updates["client-ca"]{inst.ClientCA=*ca}
		if updates["path"]{inst.Path=*path}
		if updates["max-frame"]{inst.MaxFrame=*maxFrame}
		if updates["tc-mode"]||updates["tc-object"]||updates["mss-clamp"]||updates["tc-stats"]{
			if inst.TC==nil{inst.TC=&tcebpf.Config{}}
			if updates["tc-mode"]{inst.TC.Mode=*tcMode}
			if updates["tc-object"]{inst.TC.Object=*tcObject}
			if updates["mss-clamp"]{inst.TC.MSSClamp=*mssClamp}
			if updates["tc-stats"]{inst.TC.Stats=*tcStats}
		}
		if found{cfg.Instances[index]=inst}else{cfg.Instances=append(cfg.Instances,inst)}
	}
	// Validation includes the referenced cert/keys and peer YAML, not just
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
	data,err:=configfile.Marshal(path,cfg)
	if err!=nil{return err}
	dir:=filepath.Dir(path)
	current,err:=os.Stat(path)
	if err!=nil{return fmt.Errorf("stat existing config %s: %w",path,err)}
	temp,err:=os.CreateTemp(dir,".mqvpn-server-*.tmp")
	if err!=nil{return fmt.Errorf("create temp config in %s: %w",dir,err)}
	defer os.Remove(temp.Name())
	// Preserve existing mode and ownership so an unprivileged daemon can
	// still read the file after an admin-driven atomic rename.
	if err:=temp.Chmod(current.Mode().Perm());err!=nil{temp.Close();return err}
	owner,ownerOK:=current.Sys().(*syscall.Stat_t)
	tempInfo,statErr:=temp.Stat()
	if statErr!=nil{temp.Close();return statErr}
	tempOwner,tempOK:=tempInfo.Sys().(*syscall.Stat_t)
	if ownerOK && tempOK && (owner.Uid!=tempOwner.Uid || owner.Gid!=tempOwner.Gid){
		if err:=temp.Chown(int(owner.Uid),int(owner.Gid));err!=nil{
			temp.Close()
			return fmt.Errorf("preserve config owner: %w",err)
		}
	}
	if _,err:=temp.Write(data);err!=nil{temp.Close();return err}
	if err:=temp.Sync();err!=nil{temp.Close();return err}
	if err:=temp.Close();err!=nil{return err}
	if err:=os.Rename(temp.Name(),path);err!=nil{
		return fmt.Errorf("replace %s atomically: %w",path,err)
	}
	return nil
}
