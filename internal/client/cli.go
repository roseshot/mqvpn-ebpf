package client

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

func Run(ctx context.Context, args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	configPath := fs.String("config", "", "optional concise client YAML configuration")
	server := fs.String("server", "", "authenticated tenant DNS hostname[:port]")
	pathFlag := fs.String("path", "", "optional MASQUE CONNECT path (default /.well-known/masque/ethernet/)")
	connectIP := fs.String("connect-ip", "", "connect to server IP without DNS resolution")
	var wanCLI wanFlags
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
	pathScheduler := fs.String("path-scheduler", vpnwire.SchedulerRoundRobin, "MPQUIC scheduling: round_robin (default) or low_latency")
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
	// A compileable CLI is not permission to establish a VPN. Until each
	// native platform implements protected underlay, TUN, routes and DNS,
	// fail before opening sockets or entering the reconnect supervisor.
	if err := clientPlatformPreflight(); err != nil {
		return err
	}
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	var configuredWANs []wanPath
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
	if err := vpnwire.ValidateClientAddressRequest(*tunName, *tunAddress, *tunMTU, *maxFrame); err != nil {
		return err
	}
	tcConfig, err := (tcebpf.Config{Mode: *tcMode, Object: *tcObject, MSSClamp: *mssClamp, Stats: *tcStats}).Normalize()
	if err != nil {
		return fmt.Errorf("TUN TC eBPF config: %w", err)
	}
	normalizedScheduler, err := vpnwire.NormalizePathScheduler(*pathScheduler)
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
	tcpOptions := tcpOptions{
		platform: defaultClientPlatform(),
		endpoint: endpoint, wanIP: wans[0].SourceIP, wanInterface: wans[0].Interface, tunName: *tunName, tcpPort: *tcpPort,
		caFile: *caFile, certFile: *certFile, keyFile: *keyFile, maxFrame: *maxFrame,
		tunAddress: *tunAddress, tunMTU: *tunMTU, tcConfig: tcConfig, acceptRoutes: *acceptRoutes, acceptDNS: *acceptDNS, dnsRoutes: *dnsRoutes,
	}
	if *transportMode == "tcp" && len(wans) > 1 {
		return errors.New("TCP fallback only supports one WAN; remove additional wans")
	}
	// Configuration and identity-file failures are not transient network
	// outages. Validate them once before starting the retry supervisor.
	if _, err := vpnwire.CertPool(*caFile); err != nil {
		return err
	}
	if _, err := vpnwire.KeyPair(*certFile, *keyFile); err != nil {
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
	options := sessionOptions{
		tcp: tcpOptions, transport: *transportMode, udpDialTimeout: *udpTimeout,
		wans: wans, useServerWANs: *useServerWANs, pathScheduler: normalizedScheduler, stickyVoIP: *stickyVoIP,
	}
	return runClientSupervisor(ctx, *reconnect, logger, func(sessionCtx context.Context) error {
		return runClientSession(sessionCtx, options, logger)
	})
}
