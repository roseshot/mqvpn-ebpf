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
	"net/url"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

func RunClient(ctx context.Context, args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	urlFlag := fs.String("url", "", "https URL of remote CONNECT-ETHERNET proxy")
	wan1 := fs.String("wan1", "", "source IPv4/IPv6 address for primary QUIC path (required)")
	wan2 := fs.String("wan2", "", "source address for secondary QUIC path (optional)")
	wan1Iface := fs.String("source-interface", "", "primary WAN network interface (SO_BINDTODEVICE)")
	wan2Iface := fs.String("wan2-interface", "", "secondary WAN network interface (SO_BINDTODEVICE)")
	fs.StringVar(wan1, "source-ip", "", "primary WAN local source IP")
	fs.StringVar(wan1, "wan1-ip", "", "alias of --source-ip")
	fs.StringVar(wan1Iface, "wan1-interface", "", "alias of --source-interface")
	fs.StringVar(wan2, "wan2-ip", "", "alias of --wan2")
	fs.StringVar(wan2Iface, "wan2-iface", "", "alias of --wan2-interface")
	tunName := fs.String("tun", "mq0", "single L3 TUN interface, IP-addressed and route-based")
	groupCSV := fs.String("multicast-groups", "", "explicit IP multicast destinations, comma-separated, e.g. 224.0.0.251")
	multicastPPS := fs.Int("multicast-pps", 20, "per-client multicast pps upper bound")
	tunnelIP := fs.String("tunnel-ip", "", "TAP interface CIDR, e.g. 10.77.0.2/30 (required)")
	tunnelMTU := fs.Int("tunnel-mtu", 1100, "TAP L3 MTU; default is safe for IPv4 QUIC DATAGRAM test")
	caFile := fs.String("ca", "", "CA verifying the remote server")
	certFile := fs.String("cert", "", "client TLS certificate PEM")
	keyFile := fs.String("key", "", "client TLS key PEM")
	maxFrame := fs.Int("max-frame", 1160, "maximum Ethernet frame bytes, excluding FCS")
	if err := fs.Parse(args); err != nil { return err }
	if *maxFrame < 64 || *maxFrame > 65535 { return fmt.Errorf("invalid --max-frame %d", *maxFrame) }
	groups, err := p2mp.GroupList(*groupCSV)
	if err != nil { return err }
	if *multicastPPS < 1 || *multicastPPS > 1000 { return errors.New("--multicast-pps must be 1..1000") }
	if *wan1 == "" && *wan1Iface == "" { return errors.New("primary WAN requires --source-ip and/or --source-interface") }
	if *wan2 != "" && *wan1 == *wan2 { return errors.New("WAN source IPs must be different") }
	if *wan2Iface != "" && *wan2Iface == *wan1Iface { return errors.New("primary and secondary WAN interfaces must be different") }
	u, err := url.Parse(*urlFlag)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.User != nil || u.Fragment != "" {
		return errors.New("--url must be an absolute https://host:port/path URL")
	}
	pool, err := certPool(*caFile)
	if err != nil { return err }
	cert, err := keyPair(*certFile, *keyFile)
	if err != nil { return err }
	serverAddr, err := net.ResolveUDPAddr("udp", u.Host)
	if err != nil { return fmt.Errorf("resolve QUIC peer: %w", err) }
	if err := tun.Configure(*tunName, *tunnelIP, *tunnelMTU, *maxFrame); err != nil { return fmt.Errorf("configure L3 TUN interface: %w", err) }
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
		ServerName: u.Hostname(),
		NextProtos: []string{http3.NextProtoH3},
		RootCAs: pool,
		Certificates: []tls.Certificate{cert},
	}
	conn, err := tr.Dial(ctx, serverAddr, tlsConf, qconf)
	if err != nil { _ = tr.Close(); return fmt.Errorf("QUIC dial: %w", err) }
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

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, u.String(), nil)
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
	logger.Info("CONNECT-ETHERNET accepted", "remote", u.Host)

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
	logger.Info("L3 route-based TUN forwarding started", "tun", *tunName, "cidr", *tunnelIP, "groups", *groupCSV)
	err = p2mp.ClientPump(ctx, dev, stream, *maxFrame, groups, *multicastPPS, logger)
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
