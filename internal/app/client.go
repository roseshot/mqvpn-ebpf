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
	"sync"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

func RunClient(ctx context.Context, args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	configPath := fs.String("config", "", "optional concise client YAML configuration")
	server := fs.String("server", "", "authenticated tenant DNS hostname[:port]")
	pathFlag := fs.String("path", "", "optional MASQUE CONNECT path (default /.well-known/masque/ethernet/)")
	connectIP := fs.String("connect-ip", "", "connect to server IP without DNS resolution")
	var wanCLI clientWANFlags
	fs.Var(&wanCLI, "wan", "WAN path SOURCE_IP@INTERFACE[=SERVER_IP] (repeat; first is handshake path)")
	useServerWANs := fs.Bool("use-server-wans", false, "use authenticated Server ADD_ADDRESS announcements for secondary WAN destinations")
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
	pathScheduler := fs.String("path-scheduler", pathSchedulerRoundRobin, "MPQUIC scheduling: round_robin (default) or low_latency")
	stickyVoIP := fs.Bool("sticky-voip", false, "strict SIP/DSCP-EF WAN affinity via separate single-path authenticated QUIC session")
	udpTimeout := fs.Duration("udp-dial-timeout", 5*time.Second, "QUIC connection timeout before auto mode tries TCP")
	tcpPort := fs.Int("tcp-port", 443, "TCP fallback server port (independent of QUIC URL port)")
	acceptRoutes := fs.Bool("accept-routes", true, "apply authenticated Server-pushed routes (default true)")
	acceptDNS := fs.Bool("accept-dns", true, "apply authenticated Server-pushed DNS (default true)")
	dnsRoutes := fs.Bool("dns-routes", true, "install per-DNS /32 or /128 routes via VPN TUN (default true)")
	reconnect := fs.Bool("reconnect", true, "automatically reconnect on session loss or initial connection failure (default true)")
	testKeyLog := fs.String("test-tls-keylog-file", "", "DANGEROUS: test-only TLS/QUIC secrets (requires explicit environment opt-in; never production)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	var configuredWANs []clientWAN
	if *configPath != "" {
		file, err := loadClientFile(*configPath)
		if err != nil {
			return err
		}
		configuredWANs = file.WANs
		if !explicit["use-server-wans"] && file.UseServerWANs != nil {
			*useServerWANs = *file.UseServerWANs
		}
		// Explicit CLI flags always override YAML. Unspecified settings
		// retain their existing defaults, including TCP and TCX policies.
		setString := func(name string, dst *string, value string) {
			if !explicit[name] && value != "" {
				*dst = value
			}
		}
		setInt := func(name string, dst *int, value int) {
			if !explicit[name] && value != 0 {
				*dst = value
			}
		}
		setString("server", server, file.Server)
		setString("path", pathFlag, file.Path)
		setString("connect-ip", connectIP, file.ConnectIP)
		setString("tun", tunName, file.TUN)
		setString("tun-address", tunAddress, file.Address)
		setInt("tun-mtu", tunMTU, file.MTU)
		setInt("max-frame", maxFrame, file.MaxFrame)
		setString("ca", caFile, file.CA)
		setString("cert", certFile, file.Cert)
		setString("key", keyFile, file.Key)
		setString("transport", transportMode, file.Transport)
		setString("path-scheduler", pathScheduler, file.PathScheduler)
		if !explicit["sticky-voip"] && file.StickyVoIP != nil {
			*stickyVoIP = *file.StickyVoIP
		}
		setInt("tcp-port", tcpPort, file.TCPPort)
		if !explicit["udp-dial-timeout"] && file.UDPDialTimeout != "" {
			timeout, err := time.ParseDuration(file.UDPDialTimeout)
			if err != nil {
				return fmt.Errorf("client udp_dial_timeout: %w", err)
			}
			*udpTimeout = timeout
		}
		if file.TC != nil {
			setString("tc-mode", tcMode, file.TC.Mode)
			setString("tc-object", tcObject, file.TC.Object)
			setString("mss-clamp", mssClamp, file.TC.MSSClamp)
			if !explicit["tc-stats"] && file.TC.Stats != nil {
				*tcStats = *file.TC.Stats
			}
		}
		if !explicit["accept-routes"] && file.AcceptRoutes != nil {
			*acceptRoutes = *file.AcceptRoutes
		}
		if !explicit["accept-dns"] && file.AcceptDNS != nil {
			*acceptDNS = *file.AcceptDNS
		}
		if !explicit["dns-routes"] && file.DNSRoutes != nil {
			*dnsRoutes = *file.DNSRoutes
		}
		if !explicit["reconnect"] && file.Reconnect != nil {
			*reconnect = *file.Reconnect
		}
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional client arguments")
	}
	if *maxFrame != 0 && (*maxFrame < 64 || *maxFrame > 65535) {
		return fmt.Errorf("invalid --max-frame %d", *maxFrame)
	}
	if err := validateClientAddressRequest(*tunName, *tunAddress, *tunMTU, *maxFrame); err != nil {
		return err
	}
	tcConfig, err := (tcebpf.Config{Mode: *tcMode, Object: *tcObject, MSSClamp: *mssClamp, Stats: *tcStats}).Normalize()
	if err != nil {
		return fmt.Errorf("TUN TC eBPF config: %w", err)
	}
	normalizedScheduler, err := normalizePathScheduler(*pathScheduler)
	if err != nil {
		return err
	}
	if *stickyVoIP && *transportMode == "tcp" {
		return errors.New("sticky_voip requires QUIC; TCP fallback cannot preserve per-WAN affinity")
	}
	if *transportMode != "auto" && *transportMode != "quic" && *transportMode != "tcp" {
		return fmt.Errorf("invalid --transport %q (auto|quic|tcp)", *transportMode)
	}
	if *udpTimeout <= 0 {
		return errors.New("--udp-dial-timeout must be positive")
	}
	if *tcpPort < 1 || *tcpPort > 65535 {
		return fmt.Errorf("invalid --tcp-port %d", *tcpPort)
	}
	// Without a WAN selector, use kernel source and route selection.
	wans, err := planClientWANs(configuredWANs, wanCLI)
	if err != nil {
		return err
	}
	endpoint, err := planClientEndpoint(*server, *pathFlag, *connectIP)
	if err != nil {
		return err
	}
	logger = logger.With("tun", *tunName, "path_scheduler", normalizedScheduler)
	logger.InfoContext(ctx, "VPN endpoint configured", "destination", endpoint.dialAddress, "tls_server_name", endpoint.serverName, "transport", *transportMode)
	tcpOptions := clientTCPOptions{
		endpoint: endpoint, wanIP: wans[0].SourceIP, wanInterface: wans[0].Interface, tunName: *tunName, tcpPort: *tcpPort,
		caFile: *caFile, certFile: *certFile, keyFile: *keyFile, maxFrame: *maxFrame,
		tunAddress: *tunAddress, tunMTU: *tunMTU, tcConfig: tcConfig, acceptRoutes: *acceptRoutes, acceptDNS: *acceptDNS, dnsRoutes: *dnsRoutes,
	}
	if *transportMode == "tcp" && len(wans) > 1 {
		return errors.New("TCP fallback only supports one WAN; remove additional wans")
	}
	// Configuration and identity-file failures are not transient network
	// outages. Validate them once before starting the retry supervisor.
	if _, err := certPool(*caFile); err != nil {
		return err
	}
	if _, err := keyPair(*certFile, *keyFile); err != nil {
		return err
	}
	keyLog, err := openTestTLSKeyLog(*testKeyLog)
	if err != nil {
		return err
	}
	if keyLog != nil {
		defer keyLog.Close()
		tcpOptions.tlsKeyLog = keyLog
		logger.WarnContext(ctx, "UNSAFE TEST TLS secrets logging enabled; never use outside isolated test environment")
	}
	options := clientSessionOptions{
		tcp: tcpOptions, transport: *transportMode, udpDialTimeout: *udpTimeout,
		wans: wans, useServerWANs: *useServerWANs, pathScheduler: normalizedScheduler, stickyVoIP: *stickyVoIP,
	}
	return runClientSupervisor(ctx, *reconnect, logger, func(sessionCtx context.Context) error {
		return runClientSession(sessionCtx, options, logger)
	})
}

type clientSessionOptions struct {
	tcp            clientTCPOptions
	transport      string
	udpDialTimeout time.Duration
	wans           []clientWAN
	useServerWANs  bool
	pathScheduler  string
	stickyVoIP     bool
}

// runClientSession owns exactly one transport and TUN session. On every
// return its defers close the transport, TUN/TCX attachment and session
// routes before the reconnect supervisor starts another attempt.
func runClientSession(ctx context.Context, o clientSessionOptions, logger *slog.Logger) (result error) {
	if o.transport == "tcp" {
		return runTCPFallback(ctx, o.tcp, logger)
	}
	endpoint := o.tcp.endpoint
	pool, err := certPool(o.tcp.caFile)
	if err != nil {
		return err
	}
	cert, err := keyPair(o.tcp.certFile, o.tcp.keyFile)
	if err != nil {
		return err
	}
	serverAddr, err := net.ResolveUDPAddr("udp", endpoint.dialAddress)
	if err != nil {
		return fmt.Errorf("resolve QUIC peer: %w", err)
	}
	base, selectedIP, err := wan.Listen(ctx, o.tcp.wanIP, o.tcp.wanInterface, serverAddr)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "primary WAN bound", "source_ip", selectedIP, "interface", o.tcp.wanInterface, "local", base.LocalAddr())
	// Multiple *remote* Server addresses require a single packet reader
	// spanning all Client source sockets, so QUIC CIDs stay in one
	// connection registry. Legacy same-destination WAN sockets continue
	// to use SO_BINDTODEVICE via independent WAN transports.
	remoteSpecific := o.useServerWANs
	for _, link := range o.wans {
		if link.ServerIP != "" {
			remoteSpecific = true
		}
	}
	var multiSockets *quic.MultiSocketManager
	var selectedSources []net.IP
	var packetConn net.PacketConn = base
	if remoteSpecific && len(o.wans) > 1 {
		extraIPs := make([]net.IP, 0, len(o.wans)-1)
		selectedSources = append(selectedSources, selectedIP)
		for i, link := range o.wans[1:] {
			ip, err := wan.ResolveSource(link.SourceIP, link.Interface, serverAddr)
			if err != nil {
				_ = base.Close()
				return fmt.Errorf("resolve WAN %d source: %w", i+2, err)
			}
			selectedSources = append(selectedSources, ip)
			extraIPs = append(extraIPs, ip)
		}
		manager, err := quic.NewMultiSocketManager(quic.MultiSocketManagerConfig{
			BaseConn: base, LocalAddrs: extraIPs,
		})
		if err != nil {
			_ = base.Close()
			return fmt.Errorf("open Client multi-WAN UDP sockets: %w", err)
		}
		multiSockets = manager
		packetConn = manager
		logger.InfoContext(ctx, "MPQUIC multi-address socket manager ready", "wan_count", len(o.wans))
	}
	tr := &quic.Transport{Conn: packetConn}
	qconf := &quic.Config{
		EnableDatagrams:            true,
		EnableAddressAdvertisement: true,
		MaxPaths:                   max(2, len(o.wans)),
		MultipathController:        quic.NewDefaultMultipathController(newPathScheduler(o.pathScheduler)),
		KeepAlivePeriod:            10 * time.Second,
		MaxIdleTimeout:             30 * time.Second,
	}
	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   endpoint.serverName,
		NextProtos:   []string{http3.NextProtoH3},
		KeyLogWriter: o.tcp.tlsKeyLog,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, o.udpDialTimeout)
	conn, err := tr.Dial(dialCtx, serverAddr, tlsConf, qconf)
	fallbackAllowed := eligibleTCPFallback(ctx, dialCtx, err)
	cancelDial()
	if err != nil {
		_ = tr.Close()
		if multiSockets != nil {
			_ = multiSockets.Close()
		}
		if o.transport == "auto" && fallbackAllowed && !o.stickyVoIP {
			logger.WarnContext(ctx, "QUIC UDP handshake timed out; trying authenticated TCP fallback", "timeout", o.udpDialTimeout)
			if len(o.wans) > 1 {
				logger.WarnContext(ctx, "TCP fallback uses primary WAN only; additional WAN paths unavailable over TCP")
			}
			if tcpErr := runTCPFallback(ctx, o.tcp, logger); tcpErr != nil {
				return errors.Join(fmt.Errorf("QUIC dial: %w", err), fmt.Errorf("TCP fallback: %w", tcpErr))
			}
			return nil
		}
		return fmt.Errorf("QUIC dial: %w", err)
	}
	var extraTransports []*quic.Transport
	// Keep every socket until the QUIC connection has closed, including
	// when adding or probing any later path fails.
	defer func() {
		_ = conn.CloseWithError(0, "shutdown")
		for _, transport := range extraTransports {
			_ = transport.Close()
		}
		_ = tr.Close()
		if multiSockets != nil {
			_ = multiSockets.Close()
		}
	}()
	underlaySources := []struct {
		ip    net.IP
		iface string
	}{{ip: selectedIP, iface: o.tcp.wanInterface}}

	h3 := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h3.ReceivedSettings():
	}
	settings := h3.Settings()
	if !settings.EnableExtendedConnect || !settings.EnableDatagrams {
		return errors.New("peer does not support HTTP/3 Extended CONNECT and DATAGRAM")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, endpoint.requestURL, nil)
	if err != nil {
		return err
	}
	// mp-quic-go's HTTP/3 request writer maps req.Proto to the :protocol pseudo-header.
	request.Proto = "connect-ethernet"
	request.Header.Set("Capsule-Protocol", "?1")
	request.Header.Set(framingHeader, framingValue)
	if o.stickyVoIP {
		request.Header.Set(stickySessionHeader, "sticky-v1")
	}
	compressionOffered := localCompressionAvailable()
	if compressionOffered {
		request.Header.Set(compressionHeader, compressionZstd)
	}
	if dynamicAddressRequested(o.tcp.tunAddress) {
		request.Header.Set(tunnelAddressHeader, "auto")
	}
	stream, err := h3.OpenRequestStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err = stream.SendRequestHeader(request); err != nil {
		return fmt.Errorf("CONNECT headers: %w", err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return fmt.Errorf("CONNECT response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("CONNECT-ETHERNET rejected: %s", response.Status)
	}
	if response.Header.Get("Capsule-Protocol") != "?1" {
		return errors.New("missing successful Capsule-Protocol response")
	}
	if o.stickyVoIP && response.Header.Get(stickySessionHeader) != "sticky-v1" {
		return errors.New("Server did not negotiate strict sticky realtime companion support")
	}
	effectiveAddress, err := resolveClientTunnelAddress(o.tcp.tunAddress, response.Header.Get(tunnelAddressHeader))
	if err != nil {
		return fmt.Errorf("CONNECT-ETHERNET tunnel IP negotiation: %w", err)
	}
	compression, err := negotiatedCompression(response.Header.Get(compressionHeader), compressionOffered)
	if err != nil {
		return err
	}
	fragmentation, err := negotiatedFraming(response.Header.Get(framingHeader), true)
	if err != nil {
		return err
	}
	// Go 1.27 promoted keyed fields and generic methods keep authenticated
	// route/DNS decoding identical for QUIC and TCP without losing context.
	headers := authenticatedHeaders{Header: response.Header, transport: "CONNECT-ETHERNET"}
	var pushedRoutes []netip.Prefix
	if o.tcp.acceptRoutes {
		pushedRoutes, err = headers.Decode("routes", routepush.Header, routepush.Decode)
		if err != nil {
			return err
		}
	}
	var pushedDNS []netip.Addr
	if o.tcp.acceptDNS {
		pushedDNS, err = headers.Decode("DNS", dnspush.Header, dnspush.Decode)
		if err != nil {
			return err
		}
	}
	// DNS host routes are independent from ordinary route acceptance, and
	// are protected by the same underlay guard and owned-route cleanup.
	pushedRoutes = routepush.WithDNSHostRoutes(pushedRoutes, pushedDNS, o.tcp.dnsRoutes)
	logger.InfoContext(ctx, "CONNECT-ETHERNET accepted", "remote", endpoint.dialAddress, "tenant", endpoint.serverName, "tunnel_address", effectiveAddress)

	if len(o.wans) > 1 && !conn.ConnectionState().SupportsMultipath {
		return errors.New("peer did not negotiate IETF Multipath QUIC")
	}
	var destinations []*net.UDPAddr
	if remoteSpecific {
		destinations, err = getServerTargets(ctx, conn, serverAddr, o.wans, o.useServerWANs)
		if err != nil {
			return err
		}
		for i, destination := range destinations {
			logger.InfoContext(ctx, "MPQUIC Server destination selected",
				"wan_index", i+1, "server_address", destination)
		}
	}
	for index, link := range o.wans[1:] {
		var path *quic.Path
		var selectedSource net.IP
		var localAddress net.Addr
		if multiSockets != nil {
			// The MultiSocketManager chooses each source socket by the
			// local IP in packetinfo. Linux source policy routing must
			// still deliver packets via the configured WAN interface.
			selectedSource = selectedSources[index+1]
			localAddress = &net.UDPAddr{IP: selectedSource}
			path, err = conn.AddPathFromAddr(localAddress, destinations[index+1])
			if err != nil {
				return fmt.Errorf("add WAN %d path to %s: %w", index+2, destinations[index+1], err)
			}
		} else {
			otherUDP, ip, bindErr := wan.Listen(ctx, link.SourceIP, link.Interface, serverAddr)
			if bindErr != nil {
				return fmt.Errorf("open WAN %d: %w", index+2, bindErr)
			}
			selectedSource = ip
			localAddress = otherUDP.LocalAddr()
			transport := &quic.Transport{Conn: otherUDP}
			extraTransports = append(extraTransports, transport)
			path, err = conn.AddPath(transport)
			if err != nil {
				return fmt.Errorf("add WAN %d path: %w", index+2, err)
			}
		}
		logger.InfoContext(ctx, "additional WAN bound", "wan_index", index+2,
			"source_ip", selectedSource, "interface", link.Interface,
			"local", localAddress, "remote", func() net.Addr {
				if destinations != nil {
					return destinations[index+1]
				}
				return serverAddr
			}())
		probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err = path.Probe(probeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("validate WAN %d path: %w", index+2, err)
		}
		pathID, _ := path.ID()
		logger.InfoContext(ctx, "QUIC WAN path validated", "wan_index", index+2,
			"path_id", pathID, "source", selectedSource,
			"server_address", func() net.Addr {
				if destinations != nil {
					return destinations[index+1]
				}
				return serverAddr
			}())
		underlaySources = append(underlaySources, struct {
			ip    net.IP
			iface string
		}{ip: selectedSource, iface: link.Interface})
	}
	// Calculate the auto MTU from every validated underlay, so no slower
	// or smaller WAN can silently exceed the shared TUN frame budget.
	var underlays []mtu.Underlay
	if o.tcp.tunMTU == 0 {
		for index, source := range underlaySources {
			underlay, err := wan.SourceUnderlay(source.ip, source.iface)
			if err != nil {
				return fmt.Errorf("WAN %d MTU: %w", index+1, err)
			}
			underlays = append(underlays, underlay)
		}
	}
	budget, err := mtu.Plan(o.tcp.tunName, effectiveAddress, o.tcp.tunMTU, o.tcp.maxFrame, underlays)
	if err != nil {
		return err
	}
	guard, err := routepush.ProtectServer(serverAddr.IP, selectedIP, o.tcp.wanInterface, o.tcp.tunName, pushedRoutes, len(o.wans) > 1)
	if err != nil {
		return fmt.Errorf("protect VPN server underlay route: %w", err)
	}
	defer func() {
		if err := guard.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("%w: cleanup pushed routes: %v", errUnsafeReconnect, err))
			logger.ErrorContext(ctx, "unsafe reconnect: route cleanup failed", "error", err)
		}
	}()
	logger.InfoContext(ctx, "effective VPN TUN MTU", "mtu", budget.TUNMTU, "max_frame", budget.MaxFrame,
		"auto", budget.Auto, "wan_links", underlays)
	pumpDevice, err := openClientNetworkSession(ctx, guard, o.tcp, effectiveAddress, budget, pushedRoutes, pushedDNS, logger)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	var monitors sync.WaitGroup
	monitors.Go(func() { printPaths(ctx, done, conn, logger) })
	logger.InfoContext(ctx, "L3 route-based TUN forwarding started", "address", effectiveAddress, "mtu", budget.TUNMTU)
	var pumpStream p2mp.Stream = stream
	if o.stickyVoIP {
		// The ordinary VPN session keeps all N MPQUIC WANs for TCP/UDP
		// aggregation. Realtime uses a separate *single-path* QUIC
		// connection, so no scheduler can rotate SIP/RTP/RTCP packets.
		if destinations == nil {
			destinations = make([]*net.UDPAddr, len(o.wans))
			for i := range destinations {
				destinations[i] = serverAddr
			}
		}
		sticky := newStickyClientStream(ctx, stream, logger)
		sticky.wg.Add(1)
		go sticky.runStickyCompanions(o, destinations, tlsConf, compression, fragmentation)
		defer sticky.close()
		pumpStream = sticky
		logger.InfoContext(ctx, "strict sticky VoIP enabled", "wan_count", len(o.wans))
	}
	err = p2mp.ClientPumpWithFeatures(ctx, pumpDevice, pumpStream, budget.MaxFrame, compression, fragmentation, logger)
	close(done)
	monitors.Wait()
	return classifyClientCleanup(err)
}

func printPaths(ctx context.Context, done <-chan struct{}, conn *quic.Conn, logger *slog.Logger) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			for _, p := range conn.Paths() {
				logger.InfoContext(ctx, "QUIC path", "id", p.ID, "state", p.State, "local", p.LocalAddr, "remote", p.RemoteAddr)
			}
		}
	}
}
