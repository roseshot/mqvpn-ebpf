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
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

func RunClient(ctx context.Context, args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	urlFlag := fs.String("url", "", "https domain or IP URL of CONNECT-ETHERNET endpoint")
	connectIP := fs.String("connect-ip", "", "connect to server IP without DNS resolution")
	serverName := fs.String("server-name", "", "authenticated tenant DNS name used for TLS SNI and HTTP/3 authority")
	wan1 := fs.String("source-ip", "", "primary WAN local source IPv4/IPv6 address")
	wan2 := fs.String("wan2-ip", "", "secondary WAN local source IPv4/IPv6 address (optional)")
	wan1Iface := fs.String("source-interface", "", "primary WAN network interface (SO_BINDTODEVICE)")
	wan2Iface := fs.String("wan2-interface", "", "secondary WAN network interface (SO_BINDTODEVICE)")
	tunName := fs.String("tun", "mq0", "single L3 TUN interface, IP-addressed and route-based")
	caFile := fs.String("ca", "", "CA verifying the remote server")
	certFile := fs.String("cert", "", "client TLS certificate PEM")
	keyFile := fs.String("key", "", "client TLS key PEM")
	maxFrame := fs.Int("max-frame", 1160, "maximum Ethernet frame bytes, excluding FCS")
	transportMode := fs.String("transport", "auto", "VPN transport: auto (QUIC first, TCP on UDP timeout), quic or tcp")
	udpTimeout := fs.Duration("udp-dial-timeout", 5*time.Second, "QUIC connection timeout before auto mode tries TCP")
	if err := fs.Parse(args); err != nil { return err }
	if *maxFrame < 64 || *maxFrame > 65535 { return fmt.Errorf("invalid --max-frame %d", *maxFrame) }
	if *transportMode!="auto"&&*transportMode!="quic"&&*transportMode!="tcp" {
		return fmt.Errorf("invalid --transport %q (auto|quic|tcp)",*transportMode)
	}
	if *udpTimeout<=0{return errors.New("--udp-dial-timeout must be positive")}
	if *wan1 == "" && *wan1Iface == "" { return errors.New("primary WAN requires --source-ip and/or --source-interface") }
	if *wan2 != "" && *wan1 == *wan2 { return errors.New("WAN source IPs must be different") }
	if *wan2Iface != "" && *wan2Iface == *wan1Iface { return errors.New("primary and secondary WAN interfaces must be different") }
	endpoint, err := planClientEndpoint(*urlFlag, *connectIP, *serverName)
	if err != nil { return err }
	logger.Info("VPN endpoint configured", "destination", endpoint.dialAddress, "tls_server_name", endpoint.serverName,"transport",*transportMode)
	tcpOptions:=clientTCPOptions{
		endpoint:endpoint,wanIP:*wan1,wanInterface:*wan1Iface,tunName:*tunName,
		caFile:*caFile,certFile:*certFile,keyFile:*keyFile,maxFrame:*maxFrame,
	}
	if *transportMode=="tcp" {
		if *wan2!=""||*wan2Iface!="" {return errors.New("TCP fallback only supports primary WAN; remove WAN2 options")}
		return runTCPFallback(ctx,tcpOptions,logger)
	}
	pool, err := certPool(*caFile)
	if err != nil { return err }
	cert, err := keyPair(*certFile, *keyFile)
	if err != nil { return err }
	serverAddr, err := net.ResolveUDPAddr("udp", endpoint.dialAddress)
	if err != nil { return fmt.Errorf("resolve QUIC peer: %w", err) }
	base, selectedIP, err := wan.Listen(ctx, *wan1, *wan1Iface, serverAddr)
	if err != nil { return err }
	logger.Info("primary WAN bound", "source_ip", selectedIP, "interface", *wan1Iface, "local", base.LocalAddr())
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
	dialCtx,cancelDial:=context.WithTimeout(ctx,*udpTimeout)
	conn, err := tr.Dial(dialCtx, serverAddr, tlsConf, qconf)
	fallbackAllowed:=eligibleTCPFallback(ctx,dialCtx,err)
	cancelDial()
	if err != nil {
		_ = tr.Close()
		if *transportMode=="auto" && fallbackAllowed {
			logger.Warn("QUIC UDP handshake timed out; trying authenticated TCP fallback","timeout",*udpTimeout)
			if *wan2!=""||*wan2Iface!="" {logger.Warn("TCP fallback uses primary WAN only; secondary WAN unavailable over TCP")}
			if tcpErr:=runTCPFallback(ctx,tcpOptions,logger);tcpErr!=nil{
				return errors.Join(fmt.Errorf("QUIC dial: %w",err),fmt.Errorf("TCP fallback: %w",tcpErr))
			}
			return nil
		}
		return fmt.Errorf("QUIC dial: %w", err)
	}
	var second *quic.Transport
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
	logger.Info("CONNECT-ETHERNET accepted", "remote", endpoint.dialAddress, "tenant", endpoint.serverName)

	if *wan2 != "" || *wan2Iface != "" {
		if !conn.ConnectionState().SupportsMultipath {
			return errors.New("peer did not negotiate IETF Multipath QUIC")
		}
		otherUDP, secondIP, err := wan.Listen(ctx, *wan2, *wan2Iface, serverAddr)
		if err != nil { return err }
		logger.Info("secondary WAN bound", "source_ip", secondIP, "interface", *wan2Iface, "local", otherUDP.LocalAddr())
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
	dev, err := tun.Open(*tunName)
	if err != nil { return err }
	done := make(chan struct{})
	go printPaths(done, conn, logger)
	logger.Info("L3 route-based TUN forwarding started", "tun", *tunName)
	err = p2mp.ClientPump(ctx, dev, stream, *maxFrame, logger)
	close(done)
	return err
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
