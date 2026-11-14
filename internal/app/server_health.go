package app

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

// newServerHAHealthHandler only advertises local process readiness, not
// a shared encrypted QUIC session, routing convergence, or VRRP leadership.
// It is exclusively served on loopback and contains no tenant metadata.
func newServerHAHealthHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, r *http.Request, healthy bool) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
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
		ReadHeaderTimeout: 2e9, // 2s; local health checks should not hang
	}
	m.healthDone = make(chan struct{})
	go func() {
		m.healthErr = m.healthServer.Serve(listener)
		close(m.healthDone)
	}()
	m.logger.InfoContext(m.ctx, "local Server HA readiness listener ready", "listen", listener.Addr())
	return nil
}
