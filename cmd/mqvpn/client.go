package main

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
	"github.com/roseshot/mqvpn-ebpf/internal/forward"
	"github.com/roseshot/mqvpn-ebpf/internal/tap"
)

func runClient(ctx context.Context, args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	urlFlag := fs.String("url", "", "https URL of remote CONNECT-ETHERNET proxy")
	wan1 := fs.String("wan1", "", "source IPv4/IPv6 address for primary QUIC path (required)")
	wan2 := fs.String("wan2", "", "source address for secondary QUIC path (optional)")
	tapName := fs.String("tap", "mq0", "name of preconfigured persistent TAP")
	caFile := fs.String("ca", "", "CA verifying the remote server")
	certFile := fs.String("cert", "", "client TLS certificate PEM")
	keyFile := fs.String("key", "", "client TLS key PEM")
	maxFrame := fs.Int("max-frame", 1160, "maximum Ethernet frame bytes, excluding FCS")
	if err := fs.Parse(args); err != nil { return err }
	if *maxFrame < 14 || *maxFrame > 65535 { return fmt.Errorf("invalid --max-frame %d", *maxFrame) }
	if *wan1 == "" { return errors.New("--wan1 source IP is required") }
	if *wan2 != "" && *wan1 == *wan2 { return errors.New("--wan1 and --wan2 must be different source IPs") }
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
	base, err := listenSource(*wan1, serverAddr)
	if err != nil { return err }
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

	if *wan2 != "" {
		if !conn.ConnectionState().SupportsMultipath {
			return errors.New("peer did not negotiate IETF Multipath QUIC")
		}
		otherUDP, err := listenSource(*wan2, serverAddr)
		if err != nil { return err }
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
	dev, err := tap.Open(*tapName)
	if err != nil { return err }
	var counters forward.Counters
	done := make(chan struct{})
	go printCounters(done, &counters, logger)
	go printPaths(done, conn, logger)
	logger.Info("TAP bridging started", "tap", *tapName, "max_frame", *maxFrame)
	err = forward.Run(ctx, dev, stream, *maxFrame, &counters, logger)
	close(done)
	logger.Info("TAP bridging stopped", "stats", counters.Snapshot())
	return err
}

func listenSource(ipString string, peer *net.UDPAddr) (*net.UDPConn, error) {
	ip := net.ParseIP(ipString)
	if ip == nil { return nil, fmt.Errorf("invalid WAN source IP %q", ipString) }
	if (ip.To4() == nil) != (peer.IP.To4() == nil) {
		return nil, fmt.Errorf("WAN source %s has different IP family than peer %s", ip, peer.IP)
	}
	network := "udp4"
	if ip.To4() == nil { network = "udp6" }
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil { return nil, fmt.Errorf("bind WAN source %s: %w", ip, err) }
	return c, nil
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
