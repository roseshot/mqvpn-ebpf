//go:build linux

package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/capsule"
	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
)

// authorizeTCPRequest uses the SAME tenant SNI, current client CA, and peer
// certificate identity and CRL policy as the HTTP/3 CONNECT handler.
func (m *serverMux) authorizeTCPRequest(r *http.Request) (*liveInstance, *p2mp.Rule, int, error) {
	if r.TLS == nil {
		return nil, nil, http.StatusMisdirectedRequest, errors.New("TLS connection required")
	}
	inst := m.selectTenant(r.TLS.ServerName)
	if inst == nil || !requestAuthorityMatchesSNI(r.Host, inst.prepared.spec.ServerName) {
		return nil, nil, http.StatusMisdirectedRequest, errors.New("unknown VPN tenant")
	}
	if err := verifyClientCertificate(r.TLS, inst.prepared.tlsConfig.ClientCAs, inst.prepared.revocation); err != nil {
		return nil, nil, http.StatusForbidden, fmt.Errorf("tenant client identity or CRL: %w", err)
	}
	rule, err := inst.hub.Authorize(r.TLS.PeerCertificates[0].Raw)
	if err != nil {
		return nil, nil, http.StatusForbidden, err
	}
	return inst, rule, 0, nil
}

func hasHeaderToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// delayedCapsule prevents the active hub egress goroutine from writing a
// DATAGRAM capsule before the HTTP/1.1 101 response is fully flushed.
type delayedCapsule struct {
	stream *capsule.Stream
	ready  <-chan struct{}
	ctx    context.Context
}

func (s *delayedCapsule) SendDatagram(p []byte) error {
	select {
	case <-s.ready:
		return s.stream.SendDatagram(p)
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *delayedCapsule) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.stream.ReceiveDatagram(ctx)
}

func (m *serverMux) ServeTCP(w http.ResponseWriter, r *http.Request) {
	// CONNECT-ETHERNET over HTTP/1.1 uses GET + Upgrade per draft -18,
	// whereas QUIC uses HTTP/3 Extended CONNECT.
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.Method != http.MethodGet ||
		!hasHeaderToken(r.Header.Get("Connection"), "Upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "connect-ethernet") ||
		r.Header.Get("Capsule-Protocol") != "?1" {
		http.Error(w, "CONNECT-ETHERNET HTTP/1.1 Upgrade required", http.StatusBadRequest)
		return
	}
	inst, rule, status, err := m.authorizeTCPRequest(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	peerLogger := inst.logger.With("peer", rule.ID)
	if r.URL.Path != inst.prepared.spec.Path {
		http.Error(w, "unknown CONNECT-ETHERNET path", http.StatusNotFound)
		return
	}
	requestDynamic, err := wantsTunnelIP(r.Header.Get(tunnelAddressHeader))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP/1.1 Upgrade unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		peerLogger.WarnContext(r.Context(), "TCP hijack failed", "error", err)
		return
	}
	defer conn.Close()
	stream, err := capsule.New(conn, rw.Reader, inst.prepared.spec.MaxFrame)
	if err != nil {
		return
	}
	ready := make(chan struct{})
	delayed := &delayedCapsule{stream: stream, ready: ready, ctx: r.Context()}
	compression := acceptCompression(r.Header.Get(compressionHeader))
	fragmentation := acceptFraming(r.Header.Get(framingHeader))
	session, err := inst.hub.AttachWithTrafficRole(r.Context(), rule, delayed, requestDynamic, compression, fragmentation, false, false)
	if err != nil {
		_, _ = rw.Writer.WriteString("HTTP/1.1 409 Conflict\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		_ = rw.Writer.Flush()
		return
	}
	defer inst.hub.Detach(session)
	responseHeaders := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ethernet\r\nCapsule-Protocol: ?1\r\n"
	if compression {
		responseHeaders += compressionHeader + ": " + compressionZstd + "\r\n"
	}
	if fragmentation {
		responseHeaders += framingHeader + ": " + framingValue + "\r\n"
	}
	if assigned := session.TunnelAddress(); assigned != "" {
		responseHeaders += tunnelAddressHeader + ": " + assigned + "\r\n"
	}
	if routes := p2mp.EffectivePush(inst.prepared.spec.PushRoutes, rule.PushRoutes); len(routes) > 0 {
		responseHeaders += routepush.Header + ": " + strings.Join(routes, ",") + "\r\n"
	}
	if dns := p2mp.EffectivePush(inst.prepared.spec.PushDNS, rule.PushDNS); len(dns) > 0 {
		responseHeaders += dnspush.Header + ": " + strings.Join(dns, ",") + "\r\n"
	}
	_, err = rw.Writer.WriteString(responseHeaders + "\r\n")
	if err != nil {
		return
	}
	if err = rw.Writer.Flush(); err != nil {
		return
	}
	close(ready)
	peerLogger.InfoContext(r.Context(), "TCP fallback CONNECT-ETHERNET accepted", "remote", r.RemoteAddr)
	if err := inst.hub.Receive(r.Context(), session); err != nil {
		peerLogger.WarnContext(r.Context(), "TCP fallback peer disconnected", "error", err)
	}
}

func (m *serverManager) startTCPListener() error {
	ln, err := net.Listen("tcp", m.tcpListen)
	if err != nil {
		return fmt.Errorf("bind TCP fallback %s: %w", m.tcpListen, err)
	}
	m.tcpListener = ln
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			cfg, err := m.mux.TLSConfigFor(hello)
			if err != nil {
				return nil, err
			}
			tenant := cfg.Clone()
			tenant.NextProtos = []string{"http/1.1"}
			return tenant, nil
		},
	}
	m.tcpServer = &http.Server{
		Handler:           http.HandlerFunc(m.mux.ServeTCP),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(m.logger.Handler(), slog.LevelWarn),
	}
	m.tcpDone = make(chan struct{})
	go func() {
		m.tcpErr = m.tcpServer.Serve(tls.NewListener(ln, tlsConfig))
		close(m.tcpDone)
	}()
	m.logger.InfoContext(m.ctx, "TCP fallback listener ready", "listen", ln.Addr())
	return nil
}
