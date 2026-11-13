package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

// RunServer supports a single listener by flags or a multi-instance JSON
// server configuration. Every instance owns one independent, pre-existing
// L3 TUN, UDP listener, TLS credentials and authenticated peer namespace.
// No calls to iproute2, netlink route changes, or kernel multicast APIs.
func RunServer(ctx context.Context,args []string,logger *slog.Logger)error {
	fs:=flag.NewFlagSet("server",flag.ContinueOnError)
	configFile:=fs.String("config","","JSON containing independent server instances")
	listen:=fs.String("listen",":4433","UDP listen address for single-instance mode")
	tunName:=fs.String("tun","mq0","preconfigured IP-addressed TUN for single-instance mode")
	peerFile:=fs.String("peers","","peer authentication and overlay forwarding map")
	path:=fs.String("path",defaultPath,"CONNECT-ETHERNET URL path")
	certFile:=fs.String("cert","","TLS server certificate")
	keyFile:=fs.String("key","","TLS private key")
	clientCA:=fs.String("client-ca","","TLS client certificate CA")
	maxFrame:=fs.Int("max-frame",1160,"maximum Ethernet frame size")
	if err:=fs.Parse(args);err!=nil{return err}
	if logger==nil{logger=slog.Default()}

	var cfg ServerConfig
	if *configFile!="" {
		var invalidFlag string
		fs.Visit(func(f *flag.Flag){if f.Name!="config"{invalidFlag=f.Name}})
		if invalidFlag!=""{return fmt.Errorf("--config cannot be combined with --%s",invalidFlag)}
		loaded,err:=loadServerConfig(*configFile)
		if err!=nil{return err}
		cfg=loaded
	} else {
		cfg=ServerConfig{Instances:[]ServerInstance{{
			Name:"default",Listen:*listen,TUN:*tunName,Peers:*peerFile,
			Path:*path,Cert:*certFile,Key:*keyFile,ClientCA:*clientCA,MaxFrame:*maxFrame,
		}}}
		if err:=cfg.Validate();err!=nil{return err}
	}
	runCtx,cancel:=context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs:=make(chan error,len(cfg.Instances))
	for _,inst:=range cfg.Instances {
		instance:=inst
		wg.Add(1)
		go func(){
			defer wg.Done()
			err:=runServerInstance(runCtx,instance,logger.With("instance",instance.Name,"tun",instance.TUN))
			if err!=nil{cancel()}
			errs<-err
		}()
	}
	wg.Wait()
	close(errs)
	var all []error
	for err:=range errs {
		if err!=nil{all=append(all,err)}
	}
	if len(all)>0{return errors.Join(all...)}
	return nil
}

func runServerInstance(ctx context.Context,instance ServerInstance,logger *slog.Logger)error {
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
	listenErr:=srv.ListenAndServe()
	cancel()
	close(closerDone)
	hubErr:=<-hubDone
	if hubErr!=nil{return fmt.Errorf("instance %s TUN read: %w",instance.Name,hubErr)}
	if ctx.Err()!=nil||errors.Is(listenErr,http.ErrServerClosed){return nil}
	if listenErr!=nil{return fmt.Errorf("instance %s QUIC listener: %w",instance.Name,listenErr)}
	return nil
}
