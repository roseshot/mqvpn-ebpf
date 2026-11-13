package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"strings"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
	"github.com/roseshot/mqvpn-ebpf/internal/xdp"
)

// RunServer supports config-file hot reload, signal-driven reload via CLI,
// and the legacy single-instance flags. It never modifies Linux interface,
// routing, firewall, or kernel multicast state.
func RunServer(ctx context.Context,args []string,logger *slog.Logger)error {
	if logger==nil{logger=slog.Default()}
	if len(args)>0{
		switch args[0]{
		case "validate":return validateServerCLI(args[1:],logger)
		case "reload":return reloadServerCLI(args[1:],logger)
		case "instance":return runInstanceCLI(args[1:],logger)
		}
	}
	fs:=flag.NewFlagSet("server",flag.ContinueOnError)
	configFile:=fs.String("config","","YAML multi-instance configuration file (.yaml/.yml; .json legacy)")
	reloadInterval:=fs.Duration("reload-interval",2*time.Second,"file watch interval in config mode; 0 disables automatic reload")
	listen:=fs.String("listen",":4433","UDP listen address for single-instance mode")
	tunName:=fs.String("tun","mq0","existing IP-addressed TUN for single-instance mode")
	peerFile:=fs.String("peers","","P2MP peer authentication and destination map")
	path:=fs.String("path",defaultPath,"CONNECT-ETHERNET URL path")
	certFile:=fs.String("cert","","server TLS certificate")
	keyFile:=fs.String("key","","server TLS private key")
	clientCA:=fs.String("client-ca","","mTLS client certificate CA")
	maxFrame:=fs.Int("max-frame",1160,"max encapsulated Ethernet frame bytes")
	xdpInterfaces:=fs.String("xdp-interfaces","","opt-in XDP WAN interface list (comma separated)")
	xdpObject:=fs.String("xdp-object","","compiled BPF ELF path (required with --xdp-interfaces)")
	xdpMode:=fs.String("xdp-mode","driver","XDP attach mode: driver or generic")
	if err:=fs.Parse(args);err!=nil{return err}
	if *reloadInterval<0{return errors.New("--reload-interval cannot be negative")}
	if *configFile!=""{
		var invalid string
		fs.Visit(func(f *flag.Flag){
			if f.Name!="config"&&f.Name!="reload-interval"{invalid=f.Name}
		})
		if invalid!=""{return fmt.Errorf("--config cannot be combined with --%s",invalid)}
		return runManagedServer(ctx,func()(preparedServer,error){
			return prepareConfigFile(*configFile)
		},*reloadInterval,logger)
	}
	// Without a config file, the command-line flags remain the source of
	// truth. SIGHUP is accepted but re-evaluates the same settings; no watch.
	cfg:=ServerConfig{Instances:[]ServerInstance{{
		Name:"default",Listen:*listen,TUN:*tunName,Peers:*peerFile,Path:*path,
		Cert:*certFile,Key:*keyFile,ClientCA:*clientCA,MaxFrame:*maxFrame,
	}}}
	if *xdpInterfaces!=""{
		var interfaces []string
		for _,name:=range strings.Split(*xdpInterfaces,","){interfaces=append(interfaces,strings.TrimSpace(name))}
		cfg.XDP=&xdp.Config{Interfaces:interfaces,Object:*xdpObject,Mode:*xdpMode}
	} else if *xdpObject!=""{
		return errors.New("--xdp-object requires --xdp-interfaces")
	}
	if err:=cfg.Validate();err!=nil{return err}
	return runManagedServer(ctx,func()(preparedServer,error){
		return prepareServer(cfg)
	},0,logger)
}

// validate checks the YAML schema, peer directory, and TLS files without
// opening TUN devices or binding sockets, and without changing the daemon.
func validateServerCLI(args []string,logger *slog.Logger)error{
	if logger==nil{logger=slog.Default()}
	fs:=flag.NewFlagSet("validate",flag.ContinueOnError)
	path:=fs.String("config","","configuration file to validate")
	if err:=fs.Parse(args);err!=nil{return err}
	if *path==""||fs.NArg()!=0{return errors.New("usage: mqvpn-server validate --config /path/to/server.yaml")}
	prepared,err:=prepareConfigFile(*path)
	if err!=nil{return err}
	logger.Info("server configuration valid","config",*path,"instances",len(prepared.instances))
	return nil
}

// reload is a control-plane CLI request to the running server via SIGHUP.
// Successful kill(2) means the request was delivered, not that the new config
// passed validation. The daemon logs the final reload result.
func reloadServerCLI(args []string,logger *slog.Logger)error{
	fs:=flag.NewFlagSet("reload",flag.ContinueOnError)
	pid:=fs.Int("pid",0,"PID of running mqvpn-server daemon")
	if err:=fs.Parse(args);err!=nil{return err}
	if *pid<=1||fs.NArg()!=0{return errors.New("usage: mqvpn-server reload --pid <daemon-pid>")}
	if err:=syscall.Kill(*pid,syscall.SIGHUP);err!=nil{
		return fmt.Errorf("request reload of daemon PID %d: %w",*pid,err)
	}
	logger.Info("server reload signal sent","pid",*pid)
	return nil
}
func runServerInstance(ctx context.Context,instance ServerInstance,logger *slog.Logger,ready chan<- *p2mp.Hub)error {
	peerCfg,err:=p2mp.Load(instance.Peers)
	if err!=nil{return fmt.Errorf("instance %s load peers: %w",instance.Name,err)}
	cert,err:=keyPair(instance.Cert,instance.Key)
	if err!=nil{return fmt.Errorf("instance %s: %w",instance.Name,err)}
	pool,err:=certPool(instance.ClientCA)
	if err!=nil{return fmt.Errorf("instance %s: %w",instance.Name,err)}
	device,err:=tun.Open(instance.TUN)
	if err!=nil{return fmt.Errorf("instance %s TUN: %w",instance.Name,err)}
	hub,err:=p2mp.New(device,peerCfg,instance.MaxFrame,logger)
	if err!=nil{_ = device.Close();return err}
	// Bind the UDP listener before advertising the instance as ready.
	// A port conflict rejects the new instance and allows manager rollback.
	packetConn,err:=net.ListenPacket("udp",instance.Listen)
	if err!=nil{_ = device.Close();return fmt.Errorf("instance %s bind %s: %w",instance.Name,instance.Listen,err)}
	defer packetConn.Close()

	runCtx,cancel:=context.WithCancel(ctx)
	defer cancel()
	hubDone:=make(chan error,1)
	go func(){
		hubDone<-hub.Run(runCtx)
		cancel()
	}()
	handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Method!=http.MethodConnect||r.Proto!="connect-ethernet"||r.URL.Path!=instance.Path{
			http.Error(w,"CONNECT-ETHERNET required",http.StatusBadRequest)
			return
		}
		if r.Header.Get("Capsule-Protocol")!="?1"{
			http.Error(w,"Capsule-Protocol: ?1 required",http.StatusBadRequest)
			return
		}
		if r.TLS==nil||len(r.TLS.PeerCertificates)==0{
			http.Error(w,"TLS client certificate required",http.StatusForbidden)
			return
		}
		rule,err:=hub.Authorize(r.TLS.PeerCertificates[0].Raw)
		if err!=nil{
			logger.Warn("unauthorized client certificate","remote",r.RemoteAddr)
			http.Error(w,"unauthorized site",http.StatusForbidden)
			return
		}
		setter,ok:=w.(interface{
			ReceivedSettings()<-chan struct{}
			Settings()*http3.Settings
		})
		if !ok{http.Error(w,"HTTP/3 required",http.StatusHTTPVersionNotSupported);return}
		select{
		case <-r.Context().Done():return
		case <-setter.ReceivedSettings():
		}
		if !setter.Settings().EnableDatagrams{
			http.Error(w,"HTTP/3 DATAGRAM required",http.StatusBadRequest)
			return
		}
		streamer,ok:=w.(http3.HTTPStreamer)
		if !ok{http.Error(w,"HTTP/3 stream unavailable",http.StatusInternalServerError);return}
		w.Header().Set("Capsule-Protocol","?1")
		w.WriteHeader(http.StatusOK)
		session,err:=hub.Attach(r.Context(),rule,streamer.HTTPStream())
		if err!=nil {
			logger.Warn("duplicate or invalid site session","site",rule.ID,"error",err)
			return
		}
		defer hub.Detach(session)
		logger.Info("peer connected","site",rule.ID,"remote",r.RemoteAddr)
		if err:=hub.Receive(r.Context(),session);err!=nil{
			logger.Warn("peer receive ended","site",rule.ID,"error",err)
		}else{
			logger.Info("peer disconnected","site",rule.ID)
		}
	})

	srv:=&http3.Server{
		Addr:instance.Listen,
		Handler:handler,
		TLSConfig:&tls.Config{
			MinVersion:tls.VersionTLS13,
			Certificates:[]tls.Certificate{cert},
			ClientCAs:pool,
			ClientAuth:tls.RequireAndVerifyClientCert,
		},
		EnableDatagrams:true,
		QUICConfig:&quic.Config{
			EnableDatagrams:true,
			MaxPaths:2,
			MultipathControllerFactory:func()quic.MultipathController{
				return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
			},
			KeepAlivePeriod:10*time.Second,
			MaxIdleTimeout:30*time.Second,
		},
	}
	closerDone:=make(chan struct{})
	go func(){
		select{
		case <-runCtx.Done():_ = srv.Close()
		case <-closerDone:
		}
	}()
	logger.Info("server instance listening","listen",instance.Listen,
		"path",instance.Path,"peers",len(peerCfg.Peers))
	if ready!=nil{ready<-hub}
	listenErr:=srv.Serve(packetConn)
	cancel()
	close(closerDone)
	hubErr:=<-hubDone
	if hubErr!=nil{return fmt.Errorf("instance %s TUN read: %w",instance.Name,hubErr)}
	if ctx.Err()!=nil{return nil}
	if errors.Is(listenErr,http.ErrServerClosed){
		return fmt.Errorf("instance %s stopped unexpectedly without daemon shutdown",instance.Name)
	}
	if listenErr!=nil{return fmt.Errorf("instance %s QUIC listener: %w",instance.Name,listenErr)}
	return nil
}
