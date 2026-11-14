package app

import (
	"context"
	"crypto/x509"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"

	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
)

// RunServer requires one YAML config with a shared UDP listener.
// The command accepts only the current multi-instance YAML contract.
func RunServer(ctx context.Context, args []string, logger *slog.Logger) error {
	if logger == nil { logger = slog.Default() }
	if len(args) > 0 {
		switch args[0] {
		case "validate": return validateServerCLI(args[1:], logger)
		case "reload": return reloadServerCLI(args[1:], logger)
		case "instance": return runInstanceCLI(args[1:], logger)
		}
	}
	fs := flag.NewFlagSet("mqvpn-server", flag.ContinueOnError)
	config := fs.String("config", "", "YAML Server config with shared UDP listen and multiple instances")
	reload := fs.Duration("reload-interval", 2*time.Second, "YAML and certificate/peer file poll interval (0 disables)")
	if err := fs.Parse(args); err != nil { return err }
	if *config == "" || fs.NArg() != 0 { return errors.New("usage: mqvpn-server --config server.yaml [--reload-interval 2s]") }
	return runManagedServer(ctx, func() (preparedServer, error) { return prepareConfigFile(*config) }, *reload, logger)
}

func validateServerCLI(args []string, logger *slog.Logger) error {
	if logger == nil { logger = slog.Default() }
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("config", "", "YAML config to validate")
	if err := fs.Parse(args); err != nil { return err }
	if *path == "" || fs.NArg() != 0 { return errors.New("usage: mqvpn-server validate --config server.yaml") }
	prepared, err := prepareConfigFile(*path)
	if err != nil { return err }
	logger.Info("YAML configuration valid", "config", *path, "listen", prepared.listen, "instances", len(prepared.instances))
	return nil
}

func reloadServerCLI(args []string, logger *slog.Logger) error {
	if logger == nil { logger = slog.Default() }
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "PID of the running server")
	if err := fs.Parse(args); err != nil { return err }
	if *pid <= 1 || fs.NArg() != 0 { return errors.New("usage: mqvpn-server reload --pid <daemon-pid>") }
	if err := syscall.Kill(*pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("request config reload of PID %d: %w", *pid, err)
	}
	logger.Info("reload signal delivered (result will be logged by daemon)", "pid", *pid)
	return nil
}

// serverMux owns one HTTP/3 listener for multiple isolated P2MP hubs.
// SNI selects both the mTLS identity during handshake and the traffic
// forwarding domain for CONNECT-ETHERNET. It never examines inner VPN policy.
type serverMux struct {
	mu sync.RWMutex
	bySNI map[string]*liveInstance
}

func newServerMux() *serverMux {
	return &serverMux{bySNI: make(map[string]*liveInstance)}
}

func (m *serverMux) Publish(instances map[string]*liveInstance) {
	next := make(map[string]*liveInstance, len(instances))
	for _, instance := range instances {
		next[instance.prepared.spec.ServerName] = instance
	}
	m.mu.Lock()
	m.bySNI = next
	m.mu.Unlock()
}

func (m *serverMux) Lookup(name string) *liveInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bySNI[strings.ToLower(name)]
}

// selectTenant only permits an absent SNI for a sole IP-identity tenant.
// DNS tenants and multi-tenant listeners still require an exact SNI match.
func (m *serverMux) selectTenant(name string)*liveInstance{
	if name!="" {return m.Lookup(name)}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.bySNI)!=1{return nil}
	for _,inst:=range m.bySNI{
		if net.ParseIP(inst.prepared.spec.ServerName)!=nil{return inst}
	}
	return nil
}

func (m *serverMux) TLSConfigFor(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	instance := m.selectTenant(hello.ServerName)
	if instance == nil {
		return nil, fmt.Errorf("unknown VPN SNI %q", hello.ServerName)
	}
	// ServerName, client root CAs and client auth are INSTANCE-LOCAL.
	return instance.prepared.tlsConfig, nil
}

func requestAuthorityMatchesSNI(host,serverName string)bool{
	// Extended CONNECT :authority may include the shared UDP port.
	if h,_,err:=net.SplitHostPort(host);err==nil{host=h}
	// Strip IPv6 address brackets only when net.SplitHostPort was not
	// applicable (authority without an explicit port).
	host=strings.TrimPrefix(strings.TrimSuffix(host,"]"),"[")
	return strings.EqualFold(strings.TrimSuffix(host,"."),serverName)
}

func (m *serverMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "verified client certificate required", http.StatusForbidden)
		return
	}
	// Revalidate against the current SNI tenant CA after a hot reload.
	// An old HTTP/3 connection must not retain permissions after CA rotation.
	intermediates := x509.NewCertPool()
	for _, cert := range r.TLS.PeerCertificates[1:] { intermediates.AddCert(cert) }
	if _, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: instance.prepared.tlsConfig.ClientCAs,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		http.Error(w, "client CA no longer authorized for this instance", http.StatusForbidden)
		return
	}
	rule, err := instance.hub.Authorize(r.TLS.PeerCertificates[0].Raw)
	if err != nil {
		instance.logger.Warn("unauthorized client", "remote", r.RemoteAddr)
		http.Error(w, "unauthorized site", http.StatusForbidden)
		return
	}
	setter, ok := w.(interface{
		ReceivedSettings() <-chan struct{}
		Settings() *http3.Settings
	})
	if !ok { http.Error(w, "HTTP/3 required", http.StatusHTTPVersionNotSupported); return }
	select {
	case <-r.Context().Done(): return
	case <-setter.ReceivedSettings():
	}
	if !setter.Settings().EnableDatagrams {
		http.Error(w, "HTTP/3 DATAGRAM required", http.StatusBadRequest)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok { http.Error(w, "HTTP/3 stream unavailable", http.StatusInternalServerError); return }
	// Attach before sending HTTP 200 so duplicate sessions can get HTTP 409.
	requestDynamic,err:=wantsTunnelIP(r.Header.Get(tunnelAddressHeader))
	if err!=nil{http.Error(w,err.Error(),http.StatusBadRequest);return}
	session, err := instance.hub.AttachWithTunnelIP(r.Context(), rule, streamer.HTTPStream(),requestDynamic)
	if err != nil { http.Error(w, err.Error(), http.StatusConflict); return }
	defer instance.hub.Detach(session)
	if assigned:=session.TunnelAddress();assigned!=""{w.Header().Set(tunnelAddressHeader,assigned)}
	if len(instance.prepared.spec.PushRoutes)>0 {
		w.Header().Set(routepush.Header,strings.Join(instance.prepared.spec.PushRoutes,","))
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	instance.logger.Info("peer connected", "site", rule.ID, "remote", r.RemoteAddr)
	if err := instance.hub.Receive(r.Context(), session); err != nil {
		instance.logger.Warn("peer receive ended", "site", rule.ID, "error", err)
	}
	instance.logger.Info("peer disconnected", "site", rule.ID)
}

func newSharedHTTP3Server(mux *serverMux) *http3.Server {
	return &http3.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetConfigForClient: mux.TLSConfigFor,
		},
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			MaxPaths: 2,
			MultipathControllerFactory: func() quic.MultipathController {
				return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
			},
			KeepAlivePeriod: 10*time.Second,
			MaxIdleTimeout: 30*time.Second,
		},
	}
}
