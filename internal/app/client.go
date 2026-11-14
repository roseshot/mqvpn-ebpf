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
	"net/netip"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
			"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

func RunClient(ctx context.Context, args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	configPath := fs.String("config", "", "optional concise client YAML configuration")
	server := fs.String("server", "", "authenticated tenant DNS hostname[:port]")
	pathFlag := fs.String("path", "", "optional MASQUE CONNECT path (default /.well-known/masque/ethernet/)")
	connectIP := fs.String("connect-ip", "", "connect to server IP without DNS resolution")
	wan1 := fs.String("source-ip", "", "primary WAN local source IPv4/IPv6 address")
	wan2 := fs.String("wan2-ip", "", "secondary WAN local source IPv4/IPv6 address (optional)")
	wan1Iface := fs.String("source-interface", "", "primary WAN network interface (SO_BINDTODEVICE)")
	wan2Iface := fs.String("wan2-interface", "", "secondary WAN network interface (SO_BINDTODEVICE)")
	tunName := fs.String("tun", "mq0", "Linux L3 TUN name (created and configured by daemon)")
	tunAddress := fs.String("tun-address", "", "required local TUN host IPv4/IPv6 CIDR")
	tunMTU := fs.Int("tun-mtu", 0, "TUN MTU (default auto, capped at 1400 based on WAN MTU)")
	caFile := fs.String("ca", "", "CA verifying the remote server")
	certFile := fs.String("cert", "", "client TLS certificate PEM")
	keyFile := fs.String("key", "", "client TLS key PEM")
	maxFrame := fs.Int("max-frame", 0, "maximum Ethernet frame bytes, 0 = computed TUN MTU + 14")
	tcMode := fs.String("tc-mode", "auto", "TUN TCX mode: off|auto|required")
	tcObject := fs.String("tc-object", tcebpf.DefaultObject, "optional external TUN TCX ELF (default: built into binary)")
	mssClamp := fs.String("mss-clamp", "auto", "TUN TCP SYN MSS clamp: off|auto|numeric")
	tcStats := fs.Bool("tc-stats", true, "collect TUN ingress/egress BPF counters")
	transportMode := fs.String("transport", "auto", "VPN transport: auto (QUIC first, TCP on UDP timeout), quic or tcp")
	udpTimeout := fs.Duration("udp-dial-timeout", 5*time.Second, "QUIC connection timeout before auto mode tries TCP")
	tcpPort:=fs.Int("tcp-port",443,"TCP fallback server port (independent of QUIC URL port)")
	acceptRoutes:=fs.Bool("accept-routes",true,"apply authenticated Server-pushed routes (default true)")
	acceptDNS:=fs.Bool("accept-dns",true,"apply authenticated Server-pushed DNS (default true)")
	dnsRoutes:=fs.Bool("dns-routes",true,"install per-DNS /32 or /128 routes via VPN TUN (default true)")
	reconnect:=fs.Bool("reconnect",true,"automatically reconnect on session loss or initial connection failure (default true)")
	if err := fs.Parse(args); err != nil { return err }
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if *configPath!="" {
		file,err:=loadClientFile(*configPath)
		if err!=nil{return err}
		// Explicit CLI flags always override YAML. Unspecified settings
		// retain their existing defaults, including TCP and TCX policies.
		setString:=func(name string, dst *string, value string) {
			if !explicit[name] && value!="" {*dst=value}
		}
		setInt:=func(name string, dst *int, value int) {
			if !explicit[name] && value!=0 {*dst=value}
		}
		setString("server",server,file.Server)
		setString("path",pathFlag,file.Path)
		setString("connect-ip",connectIP,file.ConnectIP)
		setString("source-ip",wan1,file.SourceIP)
		setString("source-interface",wan1Iface,file.SourceInterface)
		setString("wan2-ip",wan2,file.WAN2IP)
		setString("wan2-interface",wan2Iface,file.WAN2Interface)
		setString("tun",tunName,file.TUN)
		setString("tun-address",tunAddress,file.Address)
		setInt("tun-mtu",tunMTU,file.MTU)
		setInt("max-frame",maxFrame,file.MaxFrame)
		setString("ca",caFile,file.CA)
		setString("cert",certFile,file.Cert)
		setString("key",keyFile,file.Key)
		setString("transport",transportMode,file.Transport)
		setInt("tcp-port",tcpPort,file.TCPPort)
		if !explicit["udp-dial-timeout"] && file.UDPDialTimeout!="" {
			timeout,err:=time.ParseDuration(file.UDPDialTimeout)
			if err!=nil{return fmt.Errorf("client udp_dial_timeout: %w",err)}
			*udpTimeout=timeout
		}
		if file.TC!=nil {
			setString("tc-mode",tcMode,file.TC.Mode)
			setString("tc-object",tcObject,file.TC.Object)
			setString("mss-clamp",mssClamp,file.TC.MSSClamp)
			if !explicit["tc-stats"] && file.TC.Stats!=nil {*tcStats=*file.TC.Stats}
		}
		if !explicit["accept-routes"] && file.AcceptRoutes!=nil {*acceptRoutes=*file.AcceptRoutes}
		if !explicit["accept-dns"] && file.AcceptDNS!=nil {*acceptDNS=*file.AcceptDNS}
		if !explicit["dns-routes"] && file.DNSRoutes!=nil {*dnsRoutes=*file.DNSRoutes}
		if !explicit["reconnect"] && file.Reconnect!=nil {*reconnect=*file.Reconnect}
	}
	if fs.NArg()!=0{return errors.New("unexpected positional client arguments")}
	if *maxFrame != 0 && (*maxFrame < 64 || *maxFrame > 65535) { return fmt.Errorf("invalid --max-frame %d", *maxFrame) }
	if err:=validateClientAddressRequest(*tunName,*tunAddress,*tunMTU,*maxFrame);err!=nil{return err}
	tcConfig,err:=(tcebpf.Config{Mode:*tcMode,Object:*tcObject,MSSClamp:*mssClamp,Stats:*tcStats}).Normalize()
	if err!=nil{return fmt.Errorf("TUN TC eBPF config: %w",err)}
	if *transportMode!="auto"&&*transportMode!="quic"&&*transportMode!="tcp" {
		return fmt.Errorf("invalid --transport %q (auto|quic|tcp)",*transportMode)
	}
	if *udpTimeout<=0{return errors.New("--udp-dial-timeout must be positive")}
	if *tcpPort<1||*tcpPort>65535{return fmt.Errorf("invalid --tcp-port %d",*tcpPort)}
	// No WAN selector means follow the kernel's route to the server.
	// Secondary WAN paths still require explicit selection.
	if *wan2 != "" && *wan1 == *wan2 { return errors.New("WAN source IPs must be different") }
	if *wan2Iface != "" && *wan2Iface == *wan1Iface { return errors.New("primary and secondary WAN interfaces must be different") }
	endpoint, err := planClientEndpoint(*server,*pathFlag,*connectIP)
	if err != nil { return err }
	logger.Info("VPN endpoint configured", "destination", endpoint.dialAddress, "tls_server_name", endpoint.serverName,"transport",*transportMode)
	tcpOptions:=clientTCPOptions{
		endpoint:endpoint,wanIP:*wan1,wanInterface:*wan1Iface,tunName:*tunName,tcpPort:*tcpPort,
		caFile:*caFile,certFile:*certFile,keyFile:*keyFile,maxFrame:*maxFrame,
		tunAddress:*tunAddress,tunMTU:*tunMTU,tcConfig:tcConfig,acceptRoutes:*acceptRoutes,acceptDNS:*acceptDNS,dnsRoutes:*dnsRoutes,
	}
	if *transportMode=="tcp" && (*wan2!=""||*wan2Iface!="") {
		return errors.New("TCP fallback only supports primary WAN; remove WAN2 options")
	}
	// Configuration and identity-file failures are not transient network
	// outages. Validate them once before starting the retry supervisor.
	if _,err:=certPool(*caFile);err!=nil{return err}
	if _,err:=keyPair(*certFile,*keyFile);err!=nil{return err}
	options:=clientSessionOptions{
		tcp:tcpOptions,transport:*transportMode,udpDialTimeout:*udpTimeout,
		secondaryWANIP:*wan2,secondaryWANInterface:*wan2Iface,
	}
	return runClientSupervisor(ctx,*reconnect,logger,func(sessionCtx context.Context)error{
		return runClientSession(sessionCtx,options,logger)
	})
}

type clientSessionOptions struct {
	tcp clientTCPOptions
	transport string
	udpDialTimeout time.Duration
	secondaryWANIP string
	secondaryWANInterface string
}

// runClientSession owns exactly one transport and TUN session. On every
// return its defers close the transport, TUN/TCX attachment and session
// routes before the reconnect supervisor starts another attempt.
func runClientSession(ctx context.Context,o clientSessionOptions,logger *slog.Logger)(result error){
	if o.transport=="tcp" {
		return runTCPFallback(ctx,o.tcp,logger)
	}
	endpoint:=o.tcp.endpoint
	pool, err := certPool(o.tcp.caFile)
	if err != nil { return err }
	cert, err := keyPair(o.tcp.certFile, o.tcp.keyFile)
	if err != nil { return err }
	serverAddr, err := net.ResolveUDPAddr("udp", endpoint.dialAddress)
	if err != nil { return fmt.Errorf("resolve QUIC peer: %w", err) }
	base, selectedIP, err := wan.Listen(ctx, o.tcp.wanIP, o.tcp.wanInterface, serverAddr)
	if err != nil { return err }
	logger.Info("primary WAN bound", "source_ip", selectedIP, "interface", o.tcp.wanInterface, "local", base.LocalAddr())
	tr := &quic.Transport{Conn: base}
	qconf := &quic.Config{
		EnableDatagrams: true,
		MaxPaths: 2,
		MultipathController: quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler()),
		KeepAlivePeriod: 10 * time.Second,
		MaxIdleTimeout: 30 * time.Second,
	}
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: endpoint.serverName,
		NextProtos: []string{http3.NextProtoH3},
		RootCAs: pool,
		Certificates: []tls.Certificate{cert},
	}
	dialCtx,cancelDial:=context.WithTimeout(ctx,o.udpDialTimeout)
	conn, err := tr.Dial(dialCtx, serverAddr, tlsConf, qconf)
	fallbackAllowed:=eligibleTCPFallback(ctx,dialCtx,err)
	cancelDial()
	if err != nil {
		_ = tr.Close()
		if o.transport=="auto" && fallbackAllowed {
			logger.Warn("QUIC UDP handshake timed out; trying authenticated TCP fallback","timeout",o.udpDialTimeout)
			if o.secondaryWANIP!=""||o.secondaryWANInterface!="" {logger.Warn("TCP fallback uses primary WAN only; secondary WAN unavailable over TCP")}
			if tcpErr:=runTCPFallback(ctx,o.tcp,logger);tcpErr!=nil{
				return errors.Join(fmt.Errorf("QUIC dial: %w",err),fmt.Errorf("TCP fallback: %w",tcpErr))
			}
			return nil
		}
		return fmt.Errorf("QUIC dial: %w", err)
	}
	var second *quic.Transport
	var secondIPForMTU net.IP
	defer func() {
		_ = conn.CloseWithError(0, "shutdown")
		if second != nil { _ = second.Close() }
		_ = tr.Close()
	}()

	h3 := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	select {
	case <-ctx.Done(): return ctx.Err()
	case <-h3.ReceivedSettings():
	}
	settings := h3.Settings()
	if !settings.EnableExtendedConnect || !settings.EnableDatagrams {
		return errors.New("peer does not support HTTP/3 Extended CONNECT and DATAGRAM")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, endpoint.requestURL, nil)
	if err != nil { return err }
	// mp-quic-go's HTTP/3 request writer maps req.Proto to the :protocol pseudo-header.
	request.Proto = "connect-ethernet"
	request.Header.Set("Capsule-Protocol", "?1")
	if dynamicAddressRequested(o.tcp.tunAddress){request.Header.Set(tunnelAddressHeader,"auto")}
	stream, err := h3.OpenRequestStream(ctx)
	if err != nil { return err }
	defer stream.Close()
	if err = stream.SendRequestHeader(request); err != nil { return fmt.Errorf("CONNECT headers: %w", err) }
	response, err := stream.ReadResponse()
	if err != nil { return fmt.Errorf("CONNECT response: %w", err) }
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("CONNECT-ETHERNET rejected: %s", response.Status)
	}
	if response.Header.Get("Capsule-Protocol") != "?1" {
		return errors.New("missing successful Capsule-Protocol response")
	}
	effectiveAddress,err:=resolveClientTunnelAddress(o.tcp.tunAddress,response.Header.Get(tunnelAddressHeader))
	if err!=nil{return fmt.Errorf("CONNECT-ETHERNET tunnel IP negotiation: %w",err)}
	var pushedRoutes []netip.Prefix
	if o.tcp.acceptRoutes {
		pushedRoutes,err=routepush.Decode(response.Header.Get(routepush.Header))
		if err!=nil{return fmt.Errorf("CONNECT-ETHERNET pushed routes: %w",err)}
	}
	var pushedDNS []netip.Addr
	if o.tcp.acceptDNS{
		pushedDNS,err=dnspush.Decode(response.Header.Get(dnspush.Header))
		if err!=nil{return fmt.Errorf("CONNECT-ETHERNET pushed DNS: %w",err)}
	}
	// DNS host routes are independent from ordinary route acceptance, and
	// are protected by the same underlay guard and owned-route cleanup.
	pushedRoutes=routepush.WithDNSHostRoutes(pushedRoutes,pushedDNS,o.tcp.dnsRoutes)
	logger.Info("CONNECT-ETHERNET accepted", "remote", endpoint.dialAddress, "tenant", endpoint.serverName,"tunnel_address",effectiveAddress)

	if o.secondaryWANIP != "" || o.secondaryWANInterface != "" {
		if !conn.ConnectionState().SupportsMultipath {
			return errors.New("peer did not negotiate IETF Multipath QUIC")
		}
		otherUDP, secondIP, err := wan.Listen(ctx, o.secondaryWANIP, o.secondaryWANInterface, serverAddr)
		if err != nil { return err }
		logger.Info("secondary WAN bound", "source_ip", secondIP, "interface", o.secondaryWANInterface, "local", otherUDP.LocalAddr())
		secondIPForMTU=secondIP
		second = &quic.Transport{Conn: otherUDP}
		path, err := conn.AddPath(second)
		if err != nil { return fmt.Errorf("add second path: %w", err) }
		probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err = path.Probe(probeCtx)
		cancel()
		if err != nil { return fmt.Errorf("validate second WAN path: %w", err) }
		pathID, _ := path.ID()
		logger.Info("second QUIC path validated", "path_id", pathID, "source", otherUDP.LocalAddr())
	}
	// Compute the final TUN/frame budget only after both MPQUIC WAN paths
	// have been selected. A slower WAN must not silently receive overlarge
	// inner DATAGRAMs from the shared TUN.
	var underlays []mtu.Underlay
	if o.tcp.tunMTU==0 {
		primary,err:=wan.SourceUnderlay(selectedIP,o.tcp.wanInterface)
		if err!=nil{return fmt.Errorf("primary WAN MTU: %w",err)}
		underlays=append(underlays,primary)
		if second!=nil {
			secondary,err:=wan.SourceUnderlay(secondIPForMTU,o.secondaryWANInterface)
			if err!=nil{return fmt.Errorf("secondary WAN MTU: %w",err)}
			underlays=append(underlays,secondary)
		}
	}
	budget,err:=mtu.Plan(o.tcp.tunName,effectiveAddress,o.tcp.tunMTU,o.tcp.maxFrame,underlays)
	if err!=nil{return err}
	guard,err:=routepush.ProtectServer(serverAddr.IP,selectedIP,o.tcp.wanInterface,o.tcp.tunName,pushedRoutes,second!=nil)
	if err!=nil{return fmt.Errorf("protect VPN server underlay route: %w",err)}
	defer func(){
		if err:=guard.Close();err!=nil{
			result=errors.Join(result,fmt.Errorf("%w: cleanup pushed routes: %v",errUnsafeReconnect,err))
			logger.Error("unsafe reconnect: route cleanup failed","error",err)
		}
	}()
	logger.Info("effective VPN TUN MTU","mtu",budget.TUNMTU,"max_frame",budget.MaxFrame,
		"auto",budget.Auto,"wan_links",underlays)
	pumpDevice,err:=openClientNetworkSession(guard,o.tcp,effectiveAddress,budget,pushedRoutes,pushedDNS,logger)
	if err!=nil{return err}
	done := make(chan struct{})
	go printPaths(done, conn, logger)
	logger.Info("L3 route-based TUN forwarding started", "tun", o.tcp.tunName,"address",effectiveAddress,"mtu",budget.TUNMTU)
	err = p2mp.ClientPump(ctx, pumpDevice, stream, budget.MaxFrame, logger)
	close(done)
	return classifyClientCleanup(err)
}

func printPaths(done <-chan struct{}, conn *quic.Conn, logger *slog.Logger) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done: return
		case <-ticker.C:
			for _, p := range conn.Paths() {
				logger.Info("QUIC path", "id", p.ID, "state", p.State, "local", p.LocalAddr, "remote", p.RemoteAddr)
			}
		}
	}
}
