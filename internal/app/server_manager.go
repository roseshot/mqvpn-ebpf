package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
	"github.com/roseshot/mqvpn-ebpf/internal/xdp"
	"gopkg.in/yaml.v3"
)

type preparedInstance struct {
	spec       ServerInstance
	peers      *p2mp.Config
	pool       *p2mp.TunnelPool
	tlsConfig  *tls.Config
	peerHash   [32]byte
	staticHash [32]byte
}

type preparedServer struct {
	listen        string
	pathScheduler string
	wans          []serverWAN
	tcpEnabled    bool
	tcpListen     string
	readinessListen string
	instances     map[string]preparedInstance
	xdp           xdp.Config
	fingerprint   [32]byte
}

func hashRecord(h hash.Hash, data []byte) {
	fmt.Fprintf(h, "%016x", len(data))
	_, _ = h.Write(data)
}

// All instance YAML files, certificates and peer maps are validated before
// touching live hubs. Interface creation/IP/MTU/UP is performed by tun.Open
// on startup and changed instances only. No route, iprule, VRF, multicast,
// forwarding or firewall management is performed by the daemon.
func prepareServer(config ServerConfig) (preparedServer, error) {
	if err := config.Validate(); err != nil {
		return preparedServer{}, err
	}
	next := preparedServer{
		listen:        config.Listen,
		pathScheduler: config.PathScheduler,
		wans:          append([]serverWAN(nil), config.WANs...),
		tcpEnabled:    config.TCPFallback.Enabled,
		tcpListen:     config.TCPFallback.Listen,
		readinessListen: config.HA.ReadinessListen,
		instances:     make(map[string]preparedInstance, len(config.Instances)),
	}
	// Resolve the default TUN budget once for the whole shared listener.
	// The smallest selected WAN budget applies to all tenants and both
	// directions. Explicit per-instance MTU values bypass discovery.
	var underlays []mtu.Underlay
	for _, spec := range config.Instances {
		if spec.MTU == 0 {
			var err error
			names := append([]string(nil), config.WANInterfaces...)
			for _, link := range config.WANs {
				names = append(names, link.Interface)
			}
			underlays, err = wan.ServerUnderlays(config.Listen, names)
			if err != nil {
				return preparedServer{}, fmt.Errorf("discover server WAN MTU: %w", err)
			}
			break
		}
	}
	digest := sha256.New()
	hashRecord(digest, []byte(config.Listen))
	hashRecord(digest, []byte(config.PathScheduler))
	for _, link := range config.WANs {
		hashRecord(digest, []byte(link.Interface+"@"+link.IP))
	}
	hashRecord(digest, []byte(fmt.Sprintf("tcp:%t:%s", config.TCPFallback.Enabled, config.TCPFallback.Listen)))
	hashRecord(digest, []byte("ha-readiness:"+config.HA.ReadinessListen))
	if config.XDP != nil {
		next.xdp = *config.XDP
		if len(next.xdp.Interfaces) > 0 && next.xdp.Object != "" {
			object, err := os.ReadFile(next.xdp.Object)
			if err != nil {
				return preparedServer{}, fmt.Errorf("read XDP ELF: %w", err)
			}
			next.xdp.ObjectChecksum = sha256.Sum256(object)
			hashRecord(digest, object)
		}
		fields, err := yaml.Marshal(next.xdp)
		if err != nil {
			return preparedServer{}, err
		}
		hashRecord(digest, fields)
	}
	for _, rawSpec := range config.Instances {
		spec := rawSpec
		if err := resolveServerInstanceMTU(&spec, underlays); err != nil {
			return preparedServer{}, fmt.Errorf("instance %s MTU: %w", spec.Name, err)
		}
		raw, err := os.ReadFile(spec.Peers)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s peer YAML: %w", spec.Name, err)
		}
		var file p2mp.FileConfig
		if err := configfile.Decode(spec.Peers, raw, &file); err != nil {
			return preparedServer{}, fmt.Errorf("instance %s peer YAML: %w", spec.Name, err)
		}
		peers, err := p2mp.Parse(file)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s peers: %w", spec.Name, err)
		}
		pool, err := p2mp.NewTunnelPool(spec.TunnelPool, spec.Address, peers)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s dynamic tunnel IP: %w", spec.Name, err)
		}
		if pool == nil {
			for _, peer := range peers.Peers {
				if peer.DynamicTunnelIP {
					return preparedServer{}, fmt.Errorf("instance %s peer %s requires tunnel_pool", spec.Name, peer.ID)
				}
			}
		}
		cert, err := keyPair(spec.Cert, spec.Key)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s: %w", spec.Name, err)
		}
		ca, err := certPool(spec.ClientCA)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s: %w", spec.Name, err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s parse TLS leaf: %w", spec.Name, err)
		}
		if err := leaf.VerifyHostname(spec.ServerName); err != nil {
			return preparedServer{}, fmt.Errorf("instance %s TLS certificate must have SAN %q: %w", spec.Name, spec.ServerName, err)
		}
		// Config returned from TLS GetConfigForClient MUST have HTTP/3 ALPN.
		perInstanceTLS := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{http3.NextProtoH3},
			Certificates: []tls.Certificate{cert},
			ClientCAs:    ca,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		hash := sha256.New()
		specBytes, err := yaml.Marshal(spec)
		if err != nil {
			return preparedServer{}, err
		}
		hashRecord(hash, specBytes)
		// An embedded TC ELF is immutable for this process. Hash only
		// explicit external overrides to detect changes on hot reload.
		if spec.TC != nil && spec.TC.Enabled() && spec.TC.Object != "" {
			object, err := os.ReadFile(spec.TC.Object)
			if err != nil {
				if spec.TC.Mode == "required" {
					return preparedServer{}, fmt.Errorf("instance %s TC ELF: %w", spec.Name, err)
				}
				// Auto tolerates missing ELF; future installation changes digest.
			} else {
				hashRecord(hash, object)
			}
		}
		for _, path := range []string{spec.Cert, spec.Key, spec.ClientCA} {
			b, err := os.ReadFile(path)
			if err != nil {
				return preparedServer{}, fmt.Errorf("instance %s TLS file %q: %w", spec.Name, path, err)
			}
			hashRecord(hash, b)
		}
		var static [32]byte
		copy(static[:], hash.Sum(nil))
		next.instances[spec.Name] = preparedInstance{
			spec: spec, peers: peers, pool: pool, tlsConfig: perInstanceTLS,
			peerHash: sha256.Sum256(raw), staticHash: static,
		}
	}
	names := make([]string, 0, len(next.instances))
	for n := range next.instances {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		p := next.instances[name]
		hashRecord(digest, []byte(name))
		hashRecord(digest, p.staticHash[:])
		hashRecord(digest, p.peerHash[:])
	}
	copy(next.fingerprint[:], digest.Sum(nil))
	return next, nil
}

func prepareConfigFile(path string) (preparedServer, error) {
	cfg, err := loadServerConfig(path)
	if err != nil {
		return preparedServer{}, err
	}
	return prepareServer(cfg)
}

// A live instance owns a single TUN and its independent P2MP map.
// All instances share the same outer QUIC listener.
type liveInstance struct {
	// Prepared holds immutable SNI/TLS/static identity while the instance
	// is published. Peer-map generations are tracked separately so hot
	// reload never races with concurrent HTTP/3 TLS/CONNECT handlers.
	prepared   preparedInstance
	peerHash   [32]byte
	peerConfig *p2mp.Config
	hub        *p2mp.Hub
	tc         *tcebpf.Attachment
	logger     *slog.Logger
	cancel     context.CancelFunc
	done       chan struct{}
	err        error
}

type serverManager struct {
	ctx           context.Context
	logger        *slog.Logger
	listen        string
	pathScheduler string
	wans          []serverWAN
	tcpEnabled    bool
	tcpListen     string
	readinessListen string
	healthServer   *http.Server
	healthListener net.Listener
	healthDone     chan struct{}
	healthErr      error
	ready          atomic.Bool
	tcpServer     *http.Server
	tcpListener   net.Listener
	tcpDone       chan struct{}
	tcpErr        error
	xdp           *xdp.Controller
	mux           *serverMux
	instances     map[string]*liveInstance
	exits         chan *liveInstance
	server        *http3.Server
	packetConn    net.PacketConn
	listenerDone  chan struct{}
	listenerErr   error
}

func newServerManager(ctx context.Context, logger *slog.Logger) *serverManager {
	return &serverManager{
		ctx: ctx, logger: logging.Ensure(logger), xdp: xdp.NewController(),
		mux:       newServerMux(),
		instances: make(map[string]*liveInstance),
		exits:     make(chan *liveInstance, 256),
	}
}

func (m *serverManager) start(p preparedInstance) error {
	openTUN := tun.Open
	if p.pool != nil {
		openTUN = tun.OpenRouted
	}
	device, err := openTUN(p.spec.TUN, p.spec.Address, p.spec.MTU)
	if err != nil {
		return fmt.Errorf("instance %s TUN: %w", p.spec.Name, err)
	}
	logger := m.logger.With("instance", p.spec.Name, "tun", p.spec.TUN)
	hub, err := p2mp.New(device, p.peers, p.spec.MaxFrame, logger)
	if err != nil {
		_ = device.Close()
		return err
	}
	if err := hub.SetTunnelPool(p.pool); err != nil {
		_ = device.Close()
		return fmt.Errorf("instance %s tunnel pool: %w", p.spec.Name, err)
	}
	policy := tcebpf.DefaultConfig()
	if p.spec.TC != nil {
		policy = *p.spec.TC
	}
	tc, err := attachConfiguredTC(m.ctx, p.spec.TUN, policy, p.spec.MTU, logger)
	if err != nil {
		_ = device.Close()
		return fmt.Errorf("instance %s TUN TC eBPF: %w", p.spec.Name, err)
	}
	ctx, cancel := context.WithCancel(m.ctx)
	live := &liveInstance{
		prepared: p, peerHash: p.peerHash, peerConfig: p.peers, hub: hub, logger: logger,
		cancel: cancel, done: make(chan struct{}), tc: tc,
	}
	m.instances[p.spec.Name] = live
	go func() {
		live.err = hub.Run(ctx)
		close(live.done)
		select {
		case m.exits <- live:
		case <-m.ctx.Done():
		}
	}()
	logger.InfoContext(m.ctx, "VPN instance attached", "server_name", p.spec.ServerName,
		"address", p.spec.Address, "mtu", p.spec.MTU, "peers", len(p.peers.Peers))
	return nil
}

func (m *serverManager) stop(name string) {
	live := m.instances[name]
	if live == nil {
		return
	}
	delete(m.instances, name)
	live.hub.CloseSessions()
	live.cancel()
	<-live.done
	if live.tc != nil {
		if counters, err := live.tc.Snapshot(); err == nil {
			live.logger.InfoContext(m.ctx, "TUN TC eBPF counters", "ingress", counters.Ingress, "egress", counters.Egress)
		} else {
			live.logger.WarnContext(m.ctx, "read TUN TC eBPF counters", "error", err)
		}
		if err := live.tc.Close(); err != nil {
			live.logger.WarnContext(m.ctx, "detach TUN TC eBPF", "error", err)
		}
	}
	live.logger.InfoContext(m.ctx, "VPN instance detached")
}

func (m *serverManager) close() {
	m.ready.Store(false)
	if m.healthServer != nil {
		_ = m.healthServer.Close()
	}
	if m.healthListener != nil {
		_ = m.healthListener.Close()
	}
	if m.healthDone != nil {
		<-m.healthDone
	}
	if m.tcpServer != nil {
		_ = m.tcpServer.Close()
	}
	if m.tcpListener != nil {
		_ = m.tcpListener.Close()
	}
	if m.tcpDone != nil {
		<-m.tcpDone
	}
	if m.server != nil {
		_ = m.server.Close()
	}
	if m.packetConn != nil {
		_ = m.packetConn.Close()
	}
	if m.listenerDone != nil {
		<-m.listenerDone
	}
	m.mux.Publish(map[string]*liveInstance{})
	for name := range m.instances {
		m.stop(name)
	}
	if m.xdp != nil {
		counters, err := m.xdp.Snapshots()
		if err != nil {
			m.logger.WarnContext(m.ctx, "WAN XDP counters could not be read", "error", err)
		}
		if len(counters) > 0 {
			m.logger.InfoContext(m.ctx, "WAN XDP ingress counters", "interfaces", counters)
		}
		_ = m.xdp.Close()
	}
}

// The single shared UDP socket is bound exactly once for the daemon lifetime.
// Adding/removing instances does NOT create or rebind any QUIC listener.
func (m *serverManager) startListener() error {
	conn, err := net.ListenPacket("udp", m.listen)
	if err != nil {
		return fmt.Errorf("bind shared HTTP/3 UDP %s: %w", m.listen, err)
	}
	m.packetConn = conn
	m.server = newSharedHTTP3ServerWithScheduler(m.mux, m.pathScheduler, m.wans...)
	m.listenerDone = make(chan struct{})
	go func() { m.listenerErr = m.server.Serve(conn); close(m.listenerDone) }()
	m.logger.InfoContext(m.ctx, "shared HTTP/3 listener ready", "listen", conn.LocalAddr(), "instances", len(m.instances))
	return nil
}

func (m *serverManager) apply(next preparedServer) error {
	if m.listen != "" && m.listen != next.listen {
		return fmt.Errorf("shared listen address change %q -> %q requires daemon restart", m.listen, next.listen)
	}
	if m.listen != "" && m.pathScheduler != next.pathScheduler {
		return errors.New("Server MPQUIC path_scheduler changes require daemon restart")
	}
	if m.listen != "" && !slices.Equal(m.wans, next.wans) {
		return errors.New("server WAN address changes require daemon restart to preserve active QUIC sessions")
	}
	if m.listen != "" && (m.tcpEnabled != next.tcpEnabled || m.tcpListen != next.tcpListen) {
		return errors.New("TCP fallback enabled/listen changes require daemon restart")
	}
	if m.listen != "" && m.readinessListen != next.readinessListen {
		return errors.New("HA readiness listener changes require daemon restart")
	}
	ports, err := xdp.ListenersToPorts([]string{next.listen})
	if err != nil {
		return err
	}
	if err := m.xdp.Reconcile(next.xdp, ports); err != nil {
		return fmt.Errorf("reconcile shared XDP port %v: %w", ports, err)
	}
	// Published SNI routing always reflects the active instance set even
	// if an OS-level resource failure stops an individual reload.
	defer m.mux.Publish(m.instances)
	m.listen = next.listen
	m.pathScheduler = next.pathScheduler
	m.wans = append(m.wans[:0], next.wans...)
	m.tcpEnabled = next.tcpEnabled
	m.tcpListen = next.tcpListen
	m.readinessListen = next.readinessListen
	names := make([]string, 0, len(m.instances))
	for n := range m.instances {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		old := m.instances[name]
		newCfg, exists := next.instances[name]
		if !exists {
			m.stop(name)
			continue
		}
		if old.prepared.staticHash != newCfg.staticHash {
			previous := old.prepared
			previous.peers = old.peerConfig
			previous.peerHash = old.peerHash
			m.stop(name)
			if err := m.start(newCfg); err != nil {
				if restoreErr := m.start(previous); restoreErr != nil {
					return errors.Join(fmt.Errorf("replace instance %s: %w", name, err), fmt.Errorf("rollback instance %s: %w", name, restoreErr))
				}
				return fmt.Errorf("instance %s restored old config after reload failure: %w", name, err)
			}
			continue
		}
		if old.peerHash != newCfg.peerHash {
			if err := old.hub.ReplaceConfigWithPool(newCfg.peers, newCfg.pool); err != nil {
				return err
			}
			old.peerHash = newCfg.peerHash
			old.peerConfig = newCfg.peers
			old.logger.InfoContext(m.ctx, "P2MP peer map hot-reloaded", "peers", len(newCfg.peers.Peers))
		}
	}
	names = names[:0]
	for name := range next.instances {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := m.instances[name]; ok {
			continue
		}
		if err := m.start(next.instances[name]); err != nil {
			return err
		}
	}
	return nil
}

// The shared listener survives all reloads except an explicit change to
// the global UDP bind address. SIGHUP / polling reload peer and TLS files.
func runManagedServer(ctx context.Context, load func() (preparedServer, error), interval time.Duration, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	if interval < 0 {
		return errors.New("--reload-interval cannot be negative")
	}
	initial, err := load()
	if err != nil {
		return err
	}
	manager := newServerManager(ctx, logger)
	defer manager.close()
	if err := manager.apply(initial); err != nil {
		return err
	}
	if err := manager.startListener(); err != nil {
		return err
	}
	if manager.tcpEnabled {
		if err := manager.startTCPListener(); err != nil {
			return err
		}
	}
	if manager.readinessListen != "" {
		if err := manager.startHealthListener(); err != nil {
			return err
		}
	}
	manager.ready.Store(true)
	applied := initial.fingerprint

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	var tick <-chan time.Time
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		tick = ticker.C
	}
	reload := func() {
		next, err := load()
		if err != nil {
			logger.WarnContext(ctx, "YAML reload rejected; active instances preserved", "error", err)
			return
		}
		if next.fingerprint == applied {
			logger.DebugContext(ctx, "YAML configuration unchanged")
			return
		}
		if err := manager.apply(next); err != nil {
			logger.ErrorContext(ctx, "YAML reload failed; check active instance state", "error", err)
			return
		}
		applied = next.fingerprint
		logger.InfoContext(ctx, "VPN instance hot reload applied", "instances", len(next.instances), "shared_listen", next.listen)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-manager.listenerDone:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("shared QUIC listener terminated unexpectedly: %w", manager.listenerErr)
		case <-manager.tcpDone:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("TCP fallback listener terminated unexpectedly: %w", manager.tcpErr)
		case <-manager.healthDone:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("HA readiness listener terminated unexpectedly: %w", manager.healthErr)
		case live := <-manager.exits:
			if active := manager.instances[live.prepared.spec.Name]; active == live {
				return fmt.Errorf("VPN instance %s terminated: %w", live.prepared.spec.Name, live.err)
			}
		case <-signals:
			reload()
		case <-tick:
			reload()
		}
	}
}

// resolveServerInstanceMTU is the single point at which omitted YAML MTU
// and max_frame values become runtime effective TUN settings. The YAML
// source remains zero/omitted, so reloads can see changed WAN link MTUs.
// A changed effective MTU restarts only that VPN instance, never the
// shared UDP/TCP listener. No Linux route is written by discovery.
func resolveServerInstanceMTU(spec *ServerInstance, links []mtu.Underlay) error {
	result, err := mtu.Plan(spec.TUN, spec.Address, spec.MTU, spec.MaxFrame, links)
	if err != nil {
		return err
	}
	spec.MTU = result.TUNMTU
	spec.MaxFrame = result.MaxFrame
	return nil
}
