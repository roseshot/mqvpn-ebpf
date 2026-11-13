package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

// RunServer presents exactly ONE IP-addressed TUN, regardless of the number
// of authenticated CONNECT-ETHERNET / MPQUIC client sessions.
func RunServer(ctx context.Context,args []string,logger *slog.Logger)error{
	fs:=flag.NewFlagSet("server",flag.ContinueOnError)
	listen:=fs.String("listen",":4433","UDP listening address")
	tunName:=fs.String("tun","mq0","single L3 TUN device, shared by all peers")
	tunnelIP:=fs.String("tunnel-ip","","server TUN IP/CIDR, e.g. 10.77.0.1/24")
	tunnelMTU:=fs.Int("tunnel-mtu",1100,"L3 TUN MTU (IPv4 testing)")
	maxFrame:=fs.Int("max-frame",1160,"maximum CONNECT-ETHERNET frame bytes")
	peerFile:=fs.String("peers","","required JSON file mapping client certificate fingerprints to owned IP routes")
	path:=fs.String("path",defaultPath,"exact CONNECT-ETHERNET URL path")
	certFile:=fs.String("cert","","TLS server certificate PEM")
	keyFile:=fs.String("key","","TLS server key PEM")
	clientCA:=fs.String("client-ca","","mTLS client certificate CA")
	if err:=fs.Parse(args);err!=nil{return err}
	if len(*path)==0||(*path)[0]!='/'{return errors.New("--path must start with /")}
	cfg,err:=p2mp.Load(*peerFile)
	if err!=nil{return fmt.Errorf("peer authorization: %w",err)}
	cert,err:=keyPair(*certFile,*keyFile)
	if err!=nil{return err}
	pool,err:=certPool(*clientCA)
	if err!=nil{return err}
	if err:=tun.Configure(*tunName,*tunnelIP,*tunnelMTU,*maxFrame);err!=nil{
		return fmt.Errorf("configure single TUN: %w",err)
	}
	device,err:=tun.Open(*tunName)
	if err!=nil{return err}
	hub,err:=p2mp.New(device,cfg,*maxFrame,logger)
	if err!=nil{device.Close();return err}

	runCtx,cancel:=context.WithCancel(ctx)
	defer cancel()
	hubDone:=make(chan error,1)
	go func(){hubDone<-hub.Run(runCtx);cancel()}()

	handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Method!=http.MethodConnect || r.Proto!="connect-ethernet" || r.URL.Path!=*path {
			http.Error(w,"CONNECT-ETHERNET required",http.StatusBadRequest)
			return
		}
		if r.Header.Get("Capsule-Protocol")!="?1" {
			http.Error(w,"Capsule-Protocol: ?1 required",http.StatusBadRequest)
			return
		}
		if r.TLS==nil||len(r.TLS.PeerCertificates)==0 {
			http.Error(w,"client certificate required",http.StatusForbidden)
			return
		}
		rule,err:=hub.Authorize(r.TLS.PeerCertificates[0].Raw)
		if err!=nil{
			logger.Warn("unauthorized CONNECT-ETHERNET peer","remote",r.RemoteAddr)
			http.Error(w,"peer certificate not authorized for site",http.StatusForbidden)
			return
		}
		setter,ok:=w.(interface{
			ReceivedSettings()<-chan struct{}
			Settings()*http3.Settings
		})
		if !ok {http.Error(w,"HTTP/3 required",http.StatusHTTPVersionNotSupported);return}
		select{
		case <-r.Context().Done():return
		case <-setter.ReceivedSettings():
		}
		if !setter.Settings().EnableDatagrams {
			http.Error(w,"HTTP DATAGRAM required",http.StatusBadRequest)
			return
		}
		streamer,ok:=w.(http3.HTTPStreamer)
		if !ok{http.Error(w,"HTTP/3 stream unavailable",http.StatusInternalServerError);return}
		w.Header().Set("Capsule-Protocol","?1")
		w.WriteHeader(http.StatusOK)
		stream:=streamer.HTTPStream()
		session,err:=hub.Attach(r.Context(),rule,stream)
		if err!=nil{
			logger.Warn("peer connection rejected","site",rule.ID,"error",err)
			return
		}
		defer hub.Detach(session)
		logger.Info("peer connected","site",rule.ID,"remote",r.RemoteAddr)
		if err:=hub.Receive(r.Context(),session);err!=nil{
			logger.Warn("peer disconnected","site",rule.ID,"error",err)
		}else{
			logger.Info("peer disconnected","site",rule.ID)
		}
	})
	srv:=&http3.Server{
		Addr:*listen,
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
	go func(){<-runCtx.Done();_ = srv.Close()}()
	logger.Info("single-TUN point-to-multipoint server listening",
		"listen",*listen,"tun",*tunName,"cidr",*tunnelIP,"authorized_sites",len(cfg.Peers))
	err=srv.ListenAndServe()
	cancel()
	herr:=<-hubDone
	if herr!=nil{return fmt.Errorf("single TUN terminated: %w",herr)}
	if ctx.Err()!=nil||errors.Is(err,http.ErrServerClosed){return nil}
	return err
}
