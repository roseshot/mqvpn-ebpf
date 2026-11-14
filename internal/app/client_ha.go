package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

const (
	clientHAActiveActive  = "active_active"
	clientHAActiveStandby = "active_standby"
	clientHAExternal      = "external"
	clientHANative        = "client"
)

// clientHAConfig controls a pool of independently authenticated VPN Servers.
// All backends must present the SAME configured server DNS/IP SAN and authorize
// the same Client certificate. This is not QUIC connection migration or a
// shared-session protocol between distinct Server processes.
type clientHAConfig struct {
	Mode       string   `yaml:"mode,omitempty"`
	Controller string   `yaml:"controller,omitempty"`
	Backends   []string `yaml:"backends,omitempty"`
}

type clientHABackendFlags []string

func (f *clientHABackendFlags) String() string { return strings.Join(*f, ",") }

func (f *clientHABackendFlags) Set(value string) error {
	if value == "" {
		return errors.New("--ha-backend expects a literal Server IP address")
	}
	*f = append(*f, value)
	return nil
}

type clientHAPlan struct {
	mode       string
	controller string
	endpoints  []clientEndpoint
}

// planClientHA validates all targets BEFORE networking or reconnect retries.
// The logical TLS identity remains fixed for every selected physical IP.
func planClientHA(server, path, pinnedIP string, config *clientHAConfig) (*clientHAPlan, error) {
	if config == nil {
		return nil, nil
	}
	mode := strings.ToLower(strings.NewReplacer("/", "_", "-", "_").Replace(config.Mode))
	if mode != clientHAActiveActive && mode != clientHAActiveStandby {
		return nil, fmt.Errorf("ha.mode must be active_active or active_standby, got %q", config.Mode)
	}
	controller := strings.ToLower(config.Controller)
	if controller == "" {
		controller = clientHANative
	}
	if controller == "haproxy" {
		controller = clientHAExternal
	}
	if controller != clientHANative && controller != clientHAExternal {
		return nil, fmt.Errorf("ha.controller must be client, haproxy or external, got %q", config.Controller)
	}
	base, err := planClientEndpoint(server, path, pinnedIP)
	if err != nil {
		return nil, err
	}
	plan := &clientHAPlan{mode: mode, controller: controller}
	if controller == clientHAExternal {
		if len(config.Backends) != 0 {
			return nil, errors.New("ha.backends is not allowed with external/haproxy controller; configure backends at the load balancer")
		}
		plan.endpoints = []clientEndpoint{base}
		return plan, nil
	}
	if pinnedIP != "" {
		return nil, errors.New("client-managed ha.backends cannot be combined with connect_ip; each backend supplies the physical destination")
	}
	if len(config.Backends) < 2 || len(config.Backends) > 16 {
		return nil, errors.New("client-managed HA requires between 2 and 16 backend IP addresses")
	}
	seen := make(map[netip.Addr]bool, len(config.Backends))
	for _, target := range config.Backends {
		ip, err := netip.ParseAddr(target)
		if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || ip.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("invalid ha.backend %q: expected unicast IP literal without zone", target)
		}
		if seen[ip.Unmap()] {
			return nil, fmt.Errorf("duplicate ha.backend %s", target)
		}
		seen[ip.Unmap()] = true
		endpoint, err := planClientEndpoint(server, path, ip.String())
		if err != nil {
			return nil, err
		}
		if endpoint.serverName != base.serverName || endpoint.requestURL != base.requestURL {
			return nil, errors.New("HA endpoints must retain the same authenticated Server identity and CONNECT path")
		}
		plan.endpoints = append(plan.endpoints, endpoint)
	}
	return plan, nil
}

// A Client in active/active selects one Server according to its certificate
// fingerprint. Across independently identified Clients, the pool is active
// on multiple backends. Each Client has ONE owned TUN/session at a time:
// concurrent duplicate sessions would race for routes, DNS and leases.
type clientHASelector struct {
	plan  *clientHAPlan
	index int
}

func newClientHASelector(plan *clientHAPlan, clientDER []byte) *clientHASelector {
	s := &clientHASelector{plan: plan}
	if plan.mode == clientHAActiveActive && len(plan.endpoints) > 1 {
		digest := sha256.Sum256(clientDER)
		// No external hashing library or random seed: stable across restarts.
		value := uint64(0)
		for _, b := range digest[:8] {
			value = (value << 8) | uint64(b)
		}
		s.index = int(value % uint64(len(plan.endpoints)))
	}
	return s
}

func (s *clientHASelector) selected() (int, clientEndpoint) {
	return s.index, s.plan.endpoints[s.index]
}

func (s *clientHASelector) complete(index int, err error, lifetime time.Duration) {
	if s.plan.controller == clientHAExternal {
		return
	}
	switch s.plan.mode {
	case clientHAActiveActive:
		s.index = (index + 1) % len(s.plan.endpoints)
	case clientHAActiveStandby:
		if err == nil || (index != 0 && lifetime >= reconnectStableAfter) {
			// A healthy standby is never preempted. After it eventually
			// disconnects, reattempt primary. A failed primary MUST advance
			// to standby even if it had been healthy for hours beforehand.
			s.index = 0
		} else {
			s.index = (index + 1) % len(s.plan.endpoints)
		}
	}
}

var (
	// errClientPeerDenied is used on both QUIC and TCP CONNECT rejections.
	// An authorization denial must never be bypassed by trying a weaker peer.
	errClientPeerDenied = errors.New("CONNECT-ETHERNET rejected")
	errHAFatal          = errors.New("HA endpoint authentication or authorization failed")
)

func fatalHAAttempt(err error) bool {
	if errors.Is(err, errClientPeerDenied) {
		return true
	}
	var verify *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verify) || errors.As(err, &unknown) ||
		errors.As(err, &host) || errors.As(err, &invalid)
}

// This supervisor is connection-level HA, not packet replication. It reuses
// the existing serial session lifecycle and stops on unsafe route/TUN cleanup.
func runClientHASupervisor(ctx context.Context, plan *clientHAPlan, clientDER []byte, logger *slog.Logger, attempt func(context.Context, clientEndpoint) error) error {
	return runClientHASupervisorWithWait(ctx, plan, clientDER, logger, attempt, waitReconnect)
}

func runClientHASupervisorWithWait(ctx context.Context, plan *clientHAPlan, clientDER []byte, logger *slog.Logger, attempt func(context.Context, clientEndpoint) error, wait func(context.Context, time.Duration) error) error {
	selector := newClientHASelector(plan, clientDER)
	return runClientSupervisorWithWait(ctx, true, logger, func(sessionCtx context.Context) error {
		index, endpoint := selector.selected()
		logger.InfoContext(sessionCtx, "HA backend selected", "mode", plan.mode,
			"controller", plan.controller, "backend", endpoint.dialAddress,
			"backend_index", index+1)
		started := time.Now()
		err := attempt(sessionCtx, endpoint)
		if sessionCtx.Err() != nil || errors.Is(err, errUnsafeReconnect) {
			return err
		}
		if fatalHAAttempt(err) {
			return errors.Join(errHAFatal, err)
		}
		selector.complete(index, err, time.Since(started))
		return err
	}, wait)
}
