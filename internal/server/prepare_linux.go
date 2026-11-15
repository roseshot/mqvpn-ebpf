//go:build linux

package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"os"
	"sort"
	"time"

	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
	"github.com/roseshot/mqvpn-ebpf/internal/xdp"
)

type preparedInstance struct {
	spec       Instance
	peers      *p2mp.Config
	pool       *p2mp.TunnelPool
	tlsConfig  *tls.Config
	revocation *crlPolicy
	peerHash   [32]byte
	staticHash [32]byte
}

type preparedServer struct {
	listen          string
	pathScheduler   string
	wans            []wanPath
	tcpEnabled      bool
	tcpListen       string
	readinessListen string
	instances       map[string]preparedInstance
	xdp             xdp.Config
	fingerprint     [32]byte
}

func hashRecord(h hash.Hash, data []byte) {
	fmt.Fprintf(h, "%016x", len(data))
	_, _ = h.Write(data)
}

// All instance YAML files, certificates and peer maps are validated before
// touching live hubs. Interface creation/IP/MTU/UP is performed by tun.Open
// on startup and changed instances only. No route, iprule, VRF, multicast,
// forwarding or firewall management is performed by the daemon.
func prepareServer(config Config) (preparedServer, error) {
	if err := config.Validate(); err != nil {
		return preparedServer{}, err
	}
	next := preparedServer{
		listen:          config.Listen,
		pathScheduler:   config.PathScheduler,
		wans:            append([]wanPath(nil), config.WANs...),
		tcpEnabled:      config.TCPFallback.Enabled,
		tcpListen:       config.TCPFallback.Listen,
		readinessListen: config.HA.ReadinessListen,
		instances:       make(map[string]preparedInstance, len(config.Instances)),
	}
	// Resolve the default TUN budget once for the whole shared listener.
	// The smallest selected WAN budget applies to all tenants and both
	// directions. Explicit per-instance MTU values bypass discovery.
	var underlays []mtu.Underlay
	for _, spec := range config.Instances {
		if spec.MTU == 0 {
			var err error
			names := make([]string, 0, len(config.WANs))
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
		cert, err := vpnwire.KeyPair(spec.Cert, spec.Key)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s: %w", spec.Name, err)
		}
		ca, err := vpnwire.CertPool(spec.ClientCA)
		if err != nil {
			return preparedServer{}, fmt.Errorf("instance %s: %w", spec.Name, err)
		}
		policy, err := loadCRL(spec.ClientRevocation)
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
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 {
					return errors.New("missing verified Client certificate chain")
				}
				return policy.verify(state.VerifiedChains, time.Now())
			},
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
		certificateFiles := []string{spec.Cert, spec.Key, spec.ClientCA}
		if spec.ClientRevocation != nil && spec.ClientRevocation.Mode == "crl" {
			certificateFiles = append(certificateFiles, spec.ClientRevocation.CRLFile)
		}
		for _, path := range certificateFiles {
			b, err := os.ReadFile(path)
			if err != nil {
				return preparedServer{}, fmt.Errorf("instance %s TLS file %q: %w", spec.Name, path, err)
			}
			hashRecord(hash, b)
		}
		var static [32]byte
		copy(static[:], hash.Sum(nil))
		next.instances[spec.Name] = preparedInstance{
			spec: spec, peers: peers, pool: pool, tlsConfig: perInstanceTLS, revocation: policy,
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
