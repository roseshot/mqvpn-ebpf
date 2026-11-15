package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/cluster"
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
func (m *serverManager) startHealthListener() error {
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

// refreshLocalReadiness is called only on the Server manager's event loop.
// HTTP handlers read m.ready atomically and do not perform syscalls or
// contact the quorum store. Required TUNs and enabled listeners are checked;
// loss of a *single* WAN link is not a global failure when MPQUIC has an
// alternative path. Cluster admission/fencing remains a separate gate.
func (m *serverManager) refreshLocalReadiness() {
	if m.readinessListen == "" {
		return
	}
	probes := []cluster.LocalProbe{{
		Name:  "udp-listener",
		Check: func(context.Context) error {
			if m.packetConn == nil || m.server == nil {
				return errors.New("shared QUIC/UDP listener is not initialized")
			}
			return nil
		},
	}}
	if m.tcpEnabled {
		probes = append(probes, cluster.LocalProbe{
			Name:  "tcp-listener",
			Check: func(context.Context) error {
				if m.tcpListener == nil {
					return errors.New("configured TCP fallback listener is not initialized")
				}
				return nil
			},
		})
	}
	if len(m.instances) == 0 {
		m.updateLocalReady(errors.New("no active VPN instances"))
		return
	}
	i := 0
	for _, instance := range m.instances {
		live := instance
		probeName := "tun-" + strconv.Itoa(i)
		i++
		probes = append(probes, cluster.LocalProbe{
			Name:  probeName,
			Check: func(context.Context) error {
				if live == nil || live.hub == nil || live.done == nil {
					return errors.New("VPN instance is not initialized")
				}
				select {
				case <-live.done:
					return fmt.Errorf("VPN instance %s has stopped", live.prepared.spec.Name)
				default:
				}
				spec := live.prepared.spec
				return probeLocalTUN(spec.TUN, spec.Address, spec.MTU)
			},
		})
	}
	m.updateLocalReady(cluster.CheckNodeLocal(m.ctx, probes))
}

func (m *serverManager) updateLocalReady(err error) {
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
