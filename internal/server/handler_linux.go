//go:build linux

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"

	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
)

// Run requires one YAML config with a shared UDP listener.
// The command accepts only the current multi-instance YAML contract.
func Run(ctx context.Context, args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	if len(args) > 0 {
		switch args[0] {
		case "validate":
			return validateServerCLI(args[1:], logger)
		case "reload":
			return reloadServerCLI(args[1:], logger)
		case "instance":
			return runInstanceCLI(args[1:], logger)
		}
	}
	fs := flag.NewFlagSet("mqvpn-server", flag.ContinueOnError)
	config := fs.String("config", "", "YAML Server config with shared UDP listen and multiple instances")
	reload := fs.Duration("reload-interval", 2*time.Second, "YAML and certificate/peer file poll interval (0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *config == "" || fs.NArg() != 0 {
		return errors.New("usage: mqvpn-server --config server.yaml [--reload-interval 2s]")
	}
	return runManagedServer(ctx, func() (preparedServer, error) { return prepareConfigFile(*config) }, *reload, logger)
}

func validateServerCLI(args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("config", "", "YAML config to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("usage: mqvpn-server validate --config server.yaml")
	}
	prepared, err := prepareConfigFile(*path)
	if err != nil {
		return err
	}
	logger.Info("YAML configuration valid", "config", *path, "listen", prepared.listen, "instances", len(prepared.instances))
	return nil
}

func reloadServerCLI(args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "PID of the running server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pid <= 1 || fs.NArg() != 0 {
		return errors.New("usage: mqvpn-server reload --pid <daemon-pid>")
	}
	if err := syscall.Kill(*pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("request config reload of PID %d: %w", *pid, err)
	}
	logger.Info("reload signal delivered (result will be logged by daemon)", "pid", *pid)
	return nil
}

// mux owns one HTTP/3 listener for multiple isolated P2MP hubs.
// SNI selects both the mTLS identity during handshake and the traffic
// forwarding domain for CONNECT-ETHERNET. It never examines inner VPN policy.
type mux struct {
	mu    sync.RWMutex
	bySNI map[string]*liveInstance
}

func newMux() *mux {
	return &mux{bySNI: make(map[string]*liveInstance)}
}

func (m *mux) Publish(instances map[string]*liveInstance) {
	next := make(map[string]*liveInstance, len(instances))
	for _, instance := range instances {
		next[instance.prepared.spec.ServerName] = instance
	}
	m.mu.Lock()
	m.bySNI = next
	m.mu.Unlock()
}

func (m *mux) Lookup(name string) *liveInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bySNI[strings.ToLower(name)]
}

// selectTenant only permits an absent SNI for a sole IP-identity tenant.
// DNS tenants and multi-tenant listeners still require an exact SNI match.
func (m *mux) selectTenant(name string) *liveInstance {
	if name != "" {
		return m.Lookup(name)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.bySNI) != 1 {
		return nil
	}
	for _, inst := range m.bySNI {
		if net.ParseIP(inst.prepared.spec.ServerName) != nil {
			return inst
		}
	}
	return nil
}

func (m *mux) TLSConfigFor(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	instance := m.selectTenant(hello.ServerName)
	if instance == nil {
		return nil, fmt.Errorf("unknown VPN SNI %q", hello.ServerName)
	}
	// ServerName, client root CAs and client auth are INSTANCE-LOCAL.
	return instance.prepared.tlsConfig, nil
}

func requestAuthorityMatchesSNI(host, serverName string) bool {
	// Extended CONNECT :authority may include the shared UDP port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Strip IPv6 address brackets only when net.SplitHostPort was not
	// applicable (authority without an explicit port).
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return strings.EqualFold(strings.TrimSuffix(host, "."), serverName)
}

func (m *mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS connection required", http.StatusMisdirectedRequest)
		return
	}
	instance := m.selectTenant(r.TLS.ServerName)
	if instance == nil || !requestAuthorityMatchesSNI(r.Host, instance.prepared.spec.ServerName) {
		http.Error(w, "unknown VPN virtual host", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodConnect || r.Proto != "connect-ethernet" ||
		r.URL.Path != instance.prepared.spec.Path {
		http.Error(w, "CONNECT-ETHERNET required", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Capsule-Protocol") != "?1" {
		http.Error(w, "Capsule-Protocol: ?1 required", http.StatusBadRequest)
		return
	}
	if err := verifyCertificate(r.TLS, instance.prepared.tlsConfig.ClientCAs, instance.prepared.revocation); err != nil {
		instance.logger.WarnContext(r.Context(), "client TLS verification rejected", "error", err)
		http.Error(w, "client certificate not authorized", http.StatusForbidden)
		return
	}
	rule, err := instance.hub.Authorize(r.TLS.PeerCertificates[0].Raw)
	if err != nil {
		instance.logger.WarnContext(r.Context(), "unauthorized client", "remote", r.RemoteAddr)
		http.Error(w, "unauthorized site", http.StatusForbidden)
		return
	}
	peerLogger := instance.logger.With("peer", rule.ID)
	setter, ok := w.(interface {
		ReceivedSettings() <-chan struct{}
		Settings() *http3.Settings
	})
	if !ok {
		http.Error(w, "HTTP/3 required", http.StatusHTTPVersionNotSupported)
		return
	}
	select {
	case <-r.Context().Done():
		return
	case <-setter.ReceivedSettings():
	}
	if !setter.Settings().EnableDatagrams {
		http.Error(w, "HTTP/3 DATAGRAM required", http.StatusBadRequest)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "HTTP/3 stream unavailable", http.StatusInternalServerError)
		return
	}
	// Realtime companion sessions require the same mTLS-authenticated peer
	// and an already attached sticky-enabled primary session. This role
	// never allocates a second tunnel lease or replaces the P2MP route.
	stickyValue := r.Header.Get(vpnwire.StickySessionHeader)
	roleValue := r.Header.Get(vpnwire.TrafficRoleHeader)
	if stickyValue != "" && stickyValue != "sticky-v1" {
		http.Error(w, "unsupported sticky transport capability", http.StatusBadRequest)
		return
	}
	if roleValue != "" && roleValue != "realtime" {
		http.Error(w, "unsupported VPN traffic role", http.StatusBadRequest)
		return
	}
	realtime := roleValue == "realtime"
	if realtime && stickyValue != "sticky-v1" {
		http.Error(w, "realtime role requires sticky-v1 negotiation", http.StatusBadRequest)
		return
	}
	// Attach before sending HTTP 200 so duplicate sessions can get HTTP 409.
	requestDynamic, err := vpnwire.WantsTunnelIP(r.Header.Get(vpnwire.TunnelAddressHeader))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	compression := vpnwire.AcceptCompression(r.Header.Get(vpnwire.CompressionHeader))
	fragmentation := vpnwire.AcceptFraming(r.Header.Get(vpnwire.FramingHeader))
	// HTTPStreamer.HTTPStream flushes the response immediately. Attaching
	// with it before configuring the CONNECT response sent a bare 200,
	// hiding Capsule-Protocol and authenticated tunnel negotiation headers.
	// A pending stream keeps sender goroutines parked until the complete
	// HTTP response is committed, without sending 200 for rejected peers.
	pending := &pendingHTTP3Stream{ctx: r.Context(), ready: make(chan struct{})}
	session, err := instance.hub.AttachWithTrafficRole(r.Context(), rule, pending, requestDynamic, compression, fragmentation, stickyValue == "sticky-v1", realtime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer instance.hub.Detach(session)
	if assigned := session.TunnelAddress(); assigned != "" {
		w.Header().Set(vpnwire.TunnelAddressHeader, assigned)
	}
	if routes := p2mp.EffectivePush(instance.prepared.spec.PushRoutes, rule.PushRoutes); len(routes) > 0 {
		w.Header().Set(routepush.Header, strings.Join(routes, ","))
	}
	if dns := p2mp.EffectivePush(instance.prepared.spec.PushDNS, rule.PushDNS); len(dns) > 0 {
		w.Header().Set(dnspush.Header, strings.Join(dns, ","))
	}
	if compression {
		w.Header().Set(vpnwire.CompressionHeader, vpnwire.CompressionZstd)
	}
	if fragmentation {
		w.Header().Set(vpnwire.FramingHeader, vpnwire.FramingValue)
	}
	if stickyValue == "sticky-v1" {
		w.Header().Set(vpnwire.StickySessionHeader, "sticky-v1")
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	pending.release(streamer.HTTPStream())
	peerLogger.InfoContext(r.Context(), "peer connected", "remote", r.RemoteAddr)
	if err := instance.hub.Receive(r.Context(), session); err != nil {
		peerLogger.WarnContext(r.Context(), "peer receive ended", "error", err)
	}
	peerLogger.InfoContext(r.Context(), "peer disconnected")
}

func newSharedHTTP3Server(mux *mux, wans ...wanPath) *http3.Server {
	return newSharedHTTP3ServerWithScheduler(mux, vpnwire.SchedulerRoundRobin, wans...)
}

func newSharedHTTP3ServerWithScheduler(mux *mux, policy string, wans ...wanPath) *http3.Server {
	advertised := make([]net.IP, 0, len(wans))
	for _, link := range wans {
		advertised = append(advertised, net.ParseIP(link.IP))
	}
	return &http3.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			GetConfigForClient: mux.TLSConfigFor,
		},
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams:            true,
			MaxPaths:                   int(^uint(0) >> 1), // QUIC library caps active paths (64 in v0.3.1).
			EnableAddressAdvertisement: true,
			MultipathAutoAdvertise:     len(advertised) != 0,
			MultipathAutoAddrs:         advertised,
			MultipathControllerFactory: func() quic.MultipathController {
				return quic.NewDefaultMultipathController(vpnwire.NewPathScheduler(policy))
			},
			KeepAlivePeriod: 10 * time.Second,
			MaxIdleTimeout:  30 * time.Second,
		},
	}
}
