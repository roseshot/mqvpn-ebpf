//go:build linux

package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"
)

// newServerHAHealthHandler only advertises local process readiness, not
// a shared encrypted QUIC session, routing convergence, or VRRP leadership.
// It is exclusively served on loopback and contains no tenant metadata.
func newServerHAHealthHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, r *http.Request, healthy bool) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, true)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, ready.Load())
	})
	return mux
}

// startHealthListener is called only after all required instance hubs and
// their QUIC/TCP listeners successfully bind. Only the run loop controls the
// readiness atomic flag; concurrent health HTTP handlers read it safely.
func (m *manager) startHealthListener() error {
	listener, err := net.Listen("tcp", m.readinessListen)
	if err != nil {
		return fmt.Errorf("bind local HA readiness %s: %w", m.readinessListen, err)
	}
	m.healthListener = listener
	m.healthServer = &http.Server{
		Handler:           newServerHAHealthHandler(&m.ready),
		ReadHeaderTimeout: 2 * time.Second, // local health checks must not hang
	}
	m.healthDone = make(chan struct{})
	go func() {
		m.healthErr = m.healthServer.Serve(listener)
		close(m.healthDone)
	}()
	m.logger.InfoContext(m.ctx, "local Server HA readiness listener ready", "listen", listener.Addr())
	return nil
}

// probeLocalTUN inspects this Server's kernel state only. This does not
// synchronize peer statistics, lease ownership, routes or any other
// node's health. For a routed dynamic pool, Linux exposes the local
// address as a host route; compare the host IP, not the original mask.
func probeLocalTUN(name, address string, mtu int) error {
	expected, err := netip.ParsePrefix(address)
	if err != nil {
		return fmt.Errorf("invalid configured TUN address %q: %w", address, err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("local TUN %q missing: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("local TUN %q is DOWN", name)
	}
	if iface.MTU != mtu {
		return fmt.Errorf("local TUN %q MTU %d, expected %d", name, iface.MTU, mtu)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("inspect local TUN %q addresses: %w", name, err)
	}
	for _, value := range addrs {
		ipNet, ok := value.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if ok && ip.Unmap() == expected.Addr().Unmap() {
			return nil
		}
	}
	return fmt.Errorf("local TUN %q missing configured host IP %s", name, expected.Addr())
}

// localReadinessError inspects only this Server's runtime resources. It is
// called by the manager run loop, not the HTTP handler. There is no cluster
// membership or quorum dependency in standalone local health.
func (m *manager) localReadinessError() error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if m.packetConn == nil || m.server == nil {
		return fmt.Errorf("shared QUIC/UDP listener is not initialized")
	}
	if m.tcpEnabled && m.tcpListener == nil {
		return fmt.Errorf("configured TCP fallback listener is not initialized")
	}
	if len(m.instances) == 0 {
		return fmt.Errorf("no active VPN instances")
	}
	for name, live := range m.instances {
		if live == nil || live.hub == nil || live.done == nil {
			return fmt.Errorf("VPN instance %s is not initialized", name)
		}
		select {
		case <-live.done:
			return fmt.Errorf("VPN instance %s has stopped", name)
		default:
		}
		spec := live.prepared.spec
		if err := probeLocalTUN(spec.TUN, spec.Address, spec.MTU); err != nil {
			return fmt.Errorf("VPN instance %s: %w", name, err)
		}
	}
	return m.ctx.Err()
}

// refreshLocalReadiness runs on the Server manager's event loop. /readyz
// serves one cached atomic bit without syscalls or network requests; a
// single WAN link failure does not mark a multi-WAN node down. Cluster
// policy admission and peer fencing remain separate security decisions.
func (m *manager) refreshLocalReadiness() {
	if m.readinessListen == "" {
		return
	}
	m.updateLocalReady(m.localReadinessError())
}

func (m *manager) updateLocalReady(err error) {
	ready := err == nil
	previous := m.ready.Swap(ready)
	if previous == ready {
		return
	}
	if !ready {
		m.logger.WarnContext(m.ctx, "local Server HA readiness lost", "error", err)
		return
	}
	m.logger.InfoContext(m.ctx, "local Server HA readiness restored")
}
