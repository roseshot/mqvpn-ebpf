//go:build linux

package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
)

func localLoopbackForHealthTest(t *testing.T) *net.Interface {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil || iface.Flags&net.FlagUp == 0 {
		t.Skipf("Linux loopback interface unavailable or down: %v", err)
	}
	return iface
}

func TestServerHALocalTUNProbe(t *testing.T) {
	iface := localLoopbackForHealthTest(t)
	if err := probeLocalTUN("lo", "127.0.0.1/8", iface.MTU); err != nil {
		t.Fatalf("node-local interface readiness rejected: %v", err)
	}
	for _, tc := range []struct {
		name, address string
		mtu           int
	}{
		{"not-a-real-local-device", "127.0.0.1/8", iface.MTU},
		{"lo", "192.0.2.100/24", iface.MTU},
		{"lo", "127.0.0.1/8", iface.MTU + 1},
		{"lo", "not-a-cidr", iface.MTU},
	} {
		if err := probeLocalTUN(tc.name, tc.address, tc.mtu); err == nil {
			t.Fatalf("invalid local probe unexpectedly passed: %+v", tc)
		}
	}
}

func TestServerHAReadinessProbesLiveResourcesAndRecovers(t *testing.T) {
	iface := localLoopbackForHealthTest(t)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	live := &liveInstance{
		prepared: preparedInstance{spec: Instance{
			Name: "edge-a", TUN: "lo", Address: "127.0.0.1/8", MTU: iface.MTU,
		}},
		hub:  &p2mp.Hub{},
		done: make(chan struct{}),
	}
	m := &manager{
		ctx: context.Background(), logger: logger,
		readinessListen: "127.0.0.1:9090",
		server:          &http3.Server{},
		packetConn:      conn,
		instances:       map[string]*liveInstance{"edge-a": live},
	}
	handler := newServerHAHealthHandler(&m.ready)
	status := func() int {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}
	m.refreshLocalReadiness()
	if got := status(); got != http.StatusOK {
		t.Fatalf("healthy local TUN should make /readyz 200, got %d", got)
	}
	live.prepared.spec.Address = "192.0.2.100/24"
	m.refreshLocalReadiness()
	if got := status(); got != http.StatusServiceUnavailable {
		t.Fatalf("removed local TUN address should make /readyz 503, got %d", got)
	}
	live.prepared.spec.Address = "127.0.0.1/8"
	m.refreshLocalReadiness()
	if got := status(); got != http.StatusOK {
		t.Fatalf("restored local TUN should make /readyz 200, got %d", got)
	}
	m.tcpEnabled = true
	m.refreshLocalReadiness()
	if got := status(); got != http.StatusServiceUnavailable {
		t.Fatalf("missing configured TCP listener should make /readyz 503, got %d", got)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	m.tcpListener = tcp
	m.refreshLocalReadiness()
	if got := status(); got != http.StatusOK {
		t.Fatalf("restored configured TCP listener should make /readyz 200, got %d", got)
	}
	close(live.done)
	m.refreshLocalReadiness()
	if got := status(); got != http.StatusServiceUnavailable {
		t.Fatalf("retired local instance should make /readyz 503, got %d", got)
	}
	alive := httptest.NewRecorder()
	handler.ServeHTTP(alive, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if alive.Code != http.StatusOK {
		t.Fatalf("/livez must remain independent of local readiness, got %d", alive.Code)
	}
}

func TestServerHAReadinessNoInstancesOrQUICListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &manager{
		ctx: context.Background(), logger: logger,
		readinessListen: "127.0.0.1:9090",
	}
	m.refreshLocalReadiness()
	if m.ready.Load() {
		t.Fatal("empty Server unexpectedly ready")
	}
}
