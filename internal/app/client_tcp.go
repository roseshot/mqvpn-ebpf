package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/capsule"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

type clientTCPOptions struct {
	endpoint clientEndpoint
	wanIP,wanInterface,tunName string
	tunAddress string
	tunMTU int
	tcConfig tcebpf.Config
	caFile,certFile,keyFile string
	maxFrame int
	tcpPort int
	acceptRoutes bool
}

// tcpTarget supports an independent TCP port without weakening tenant TLS
// SNI validation or the HTTP Host authority.
func tcpTarget(o clientTCPOptions)(string,string,error){
	host,_,err:=net.SplitHostPort(o.endpoint.dialAddress)
	if err!=nil{return "","",err}
	port:=strconv.Itoa(o.tcpPort)
	u,err:=url.Parse(o.endpoint.requestURL)
	if err!=nil{return "","",err}
	u.Host=net.JoinHostPort(o.endpoint.serverName,port)
	return net.JoinHostPort(host,port),u.String(),nil
}

// runTCPFallback sends HTTP/1.1 GET Upgrade and then exchanges RFC 9297
// DATAGRAM Capsules bidirectionally over an authenticated TLS 1.3 stream.
func runTCPFallback(ctx context.Context,o clientTCPOptions,logger *slog.Logger)(result error){
	dialAddress,requestURL,err:=tcpTarget(o)
	if err!=nil{return err}
	server,err:=net.ResolveTCPAddr("tcp",dialAddress)
	if err!=nil{return fmt.Errorf("resolve TCP fallback destination: %w",err)}
	raw,ip,err:=wan.DialTCP(ctx,o.wanIP,o.wanInterface,server)
	if err!=nil{return err}
	defer raw.Close()
	logger.Info("TCP fallback primary WAN connected","local",raw.LocalAddr(),"remote",raw.RemoteAddr(),"source",ip)
	roots,err:=certPool(o.caFile)
	if err!=nil{return err}
	cert,err:=keyPair(o.certFile,o.keyFile)
	if err!=nil{return err}
	conf:=&tls.Config{
		MinVersion:tls.VersionTLS13,
		ServerName:o.endpoint.serverName,
		NextProtos:[]string{"http/1.1"},
		RootCAs:roots,
		Certificates:[]tls.Certificate{cert},
	}
	conn:=tls.Client(raw,conf)
	defer conn.Close()
	stop:=context.AfterFunc(ctx,func(){_ = conn.Close()})
	defer stop()
	handshakeCtx,cancel:=context.WithTimeout(ctx,10*time.Second)
	err=conn.HandshakeContext(handshakeCtx)
	cancel()
	if err!=nil{return fmt.Errorf("TCP TLS handshake: %w",err)}
	if conn.ConnectionState().NegotiatedProtocol!="http/1.1" {
		return fmt.Errorf("TCP fallback negotiated unexpected ALPN %q",conn.ConnectionState().NegotiatedProtocol)
	}
	request,err:=http.NewRequestWithContext(ctx,http.MethodGet,requestURL,nil)
	if err!=nil{return err}
	request.Header.Set("Connection","Upgrade")
	request.Header.Set("Upgrade","connect-ethernet")
	request.Header.Set("Capsule-Protocol","?1")
	if dynamicAddressRequested(o.tunAddress){request.Header.Set(tunnelAddressHeader,"auto")}
	if err:=request.Write(conn);err!=nil{return fmt.Errorf("send TCP CONNECT-ETHERNET Upgrade: %w",err)}
	_ = conn.SetReadDeadline(time.Now().Add(10*time.Second))
	br:=bufio.NewReader(conn)
	response,err:=http.ReadResponse(br,request)
	if err!=nil{return fmt.Errorf("read TCP Upgrade response: %w",err)}
	if response.StatusCode!=http.StatusSwitchingProtocols ||
		!hasHeaderToken(response.Header.Get("Connection"),"Upgrade") ||
		!strings.EqualFold(response.Header.Get("Upgrade"),"connect-ethernet") ||
		response.Header.Get("Capsule-Protocol")!="?1" {
		_ = response.Body.Close()
		return fmt.Errorf("TCP CONNECT-ETHERNET rejected: %s",response.Status)
	}
	_ = conn.SetReadDeadline(time.Time{})
	effectiveAddress,err:=resolveClientTunnelAddress(o.tunAddress,response.Header.Get(tunnelAddressHeader))
	if err!=nil{return fmt.Errorf("TCP tunnel IP negotiation: %w",err)}
	var pushedRoutes []netip.Prefix
	if o.acceptRoutes {
		pushedRoutes,err=routepush.Decode(response.Header.Get(routepush.Header))
		if err!=nil{return fmt.Errorf("TCP pushed routes: %w",err)}
	}
	var underlays []mtu.Underlay
	if o.tunMTU==0 {
		link,err:=wan.SourceUnderlay(ip,o.wanInterface)
		if err!=nil{return fmt.Errorf("TCP fallback WAN MTU: %w",err)}
		underlays=append(underlays,link)
	}
	budget,err:=mtu.Plan(o.tunName,effectiveAddress,o.tunMTU,o.maxFrame,underlays)
	if err!=nil{return err}
	guard,err:=routepush.ProtectServer(server.IP,ip,o.wanInterface,o.tunName,pushedRoutes,false)
	if err!=nil{return fmt.Errorf("protect TCP VPN server underlay route: %w",err)}
	defer func(){
		if err:=guard.Close();err!=nil{
			result=errors.Join(result,fmt.Errorf("%w: cleanup pushed TCP routes: %v",errUnsafeReconnect,err))
			logger.Error("unsafe reconnect: TCP route cleanup failed","error",err)
		}
	}()
	logger.Info("effective TCP fallback TUN MTU","mtu",budget.TUNMTU,
		"max_frame",budget.MaxFrame,"auto",budget.Auto,"wan_links",underlays)
	stream,err:=capsule.New(conn,br,budget.MaxFrame)
	if err!=nil{return err}
	device,err:=tun.OpenClient(o.tunName,effectiveAddress,budget.TUNMTU,dynamicAddressRequested(o.tunAddress))
	if err!=nil{return err}
	if err:=guard.Install(o.tunName,pushedRoutes);err!=nil{
		closeErr:=device.Close()
		if errors.Is(closeErr,tun.ErrCleanup){return errors.Join(fmt.Errorf("apply TCP authenticated Server routes: %w",err),closeErr,errUnsafeReconnect)}
		return errors.Join(fmt.Errorf("apply TCP authenticated Server routes: %w",err),closeErr)
	}
	if len(pushedRoutes)>0{logger.Info("authenticated Server routes installed over TCP","routes",routepush.Encode(pushedRoutes),"server_ip",server.IP)}
	tcAttachment,err:=attachConfiguredTC(o.tunName,o.tcConfig,budget.TUNMTU,logger)
	if err!=nil{
		closeErr:=device.Close()
		if errors.Is(closeErr,tun.ErrCleanup){return errors.Join(fmt.Errorf("attach TCP TUN TC eBPF: %w",err),closeErr,errUnsafeReconnect)}
		return errors.Join(fmt.Errorf("attach TCP TUN TC eBPF: %w",err),closeErr)
	}
	pumpDevice:=newManagedPumpDevice(device,tcAttachment,logger)
	logger.Info("TCP fallback VPN session established","remote",dialAddress,"tenant",o.endpoint.serverName,"tun",o.tunName,"tunnel_address",effectiveAddress)
	err=p2mp.ClientPump(ctx,pumpDevice,stream,budget.MaxFrame,logger)
	if errors.Is(err,tun.ErrCleanup){return errors.Join(err,errUnsafeReconnect)}
	return err
}
