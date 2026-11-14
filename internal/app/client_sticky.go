package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/wan"
)

var errStickyUnavailable = errors.New("sticky realtime WAN unavailable; priority packet not sent on bulk MPQUIC paths")

// stickyClientStream demultiplexes received packets from two independent
// authenticated CONNECT-ETHERNET sessions. The ordinary session keeps
// MPQUIC aggregation. The realtime companion is a separate single-path
// QUIC connection pinned to exactly one physical WAN at a time.
//
// SendRealtimeDatagram never falls back to SendDatagram: fallback would
// silently violate strict flow affinity and reintroduce out-of-order
// RTP under WAN failure.
type stickyClientStream struct {
	base    p2mp.Stream
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex
	active  p2mp.Stream
	inbound chan []byte
	failure chan error
	wg      sync.WaitGroup
	logger  *slog.Logger
}

func newStickyClientStream(ctx context.Context, base p2mp.Stream, logger *slog.Logger) *stickyClientStream {
	lifetime, cancel := context.WithCancel(ctx)
	m := &stickyClientStream{
		base: base, ctx: lifetime, cancel: cancel, logger: logger,
		inbound: make(chan []byte, 256), failure: make(chan error, 1),
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.recvLoop(base, true)
	}()
	return m
}

func (m *stickyClientStream) SendDatagram(b []byte) error {
	return m.base.SendDatagram(b)
}

func (m *stickyClientStream) SendRealtimeDatagram(b []byte) error {
	m.mu.RLock()
	active := m.active
	m.mu.RUnlock()
	if active == nil {
		return errStickyUnavailable
	}
	return active.SendDatagram(b)
}

func (m *stickyClientStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.ctx.Done():
		return nil, m.ctx.Err()
	case err := <-m.failure:
		return nil, err
	case b := <-m.inbound:
		return b, nil
	}
}

func (m *stickyClientStream) recvLoop(stream p2mp.Stream, essential bool) {
	for {
		b, err := stream.ReceiveDatagram(m.ctx)
		if err != nil {
			if essential && m.ctx.Err() == nil {
				select {
				case m.failure <- err:
				default:
				}
			}
			return
		}
		select {
		case <-m.ctx.Done():
			return
		case m.inbound <- b:
		default:
			// Bound received datagrams instead of allowing WAN packet
			// bursts to grow memory without limit.
			m.logger.DebugContext(m.ctx, "sticky VPN inbound queue overflow")
		}
	}
}

func (m *stickyClientStream) install(stream p2mp.Stream) {
	m.mu.Lock()
	m.active = stream
	m.mu.Unlock()
}

func (m *stickyClientStream) uninstall(stream p2mp.Stream) {
	m.mu.Lock()
	if m.active == stream {
		m.active = nil
	}
	m.mu.Unlock()
}

func (m *stickyClientStream) close() {
	m.cancel()
	m.wg.Wait()
}

// runStickyCompanions chooses one configured physical WAN and keeps the
// realtime QUIC connection there for its entire lifetime. Only a lost
// session advances to the NEXT configured WAN; it never reacts to a
// transient RTT change or jumps back automatically after recovery.
func (m *stickyClientStream) runStickyCompanions(o clientSessionOptions, destinations []*net.UDPAddr, ca *tls.Config, compression, fragmentation bool) {
	defer m.wg.Done()
	if len(destinations) != len(o.wans) {
		m.logger.ErrorContext(m.ctx, "sticky WAN destination count mismatch", "destinations", len(destinations), "wans", len(o.wans))
		return
	}
	for next := 0; m.ctx.Err() == nil; next = (next + 1) % len(o.wans) {
		link := o.wans[next]
		remote := destinations[next]
		if err := m.runOneStickySession(next, link, remote, ca, o, compression, fragmentation); err != nil && m.ctx.Err() == nil {
			m.logger.WarnContext(m.ctx, "sticky realtime WAN lost; advancing to next WAN",
				"wan_index", next+1, "source_ip", link.SourceIP, "remote", remote, "error", err)
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(450 * time.Millisecond):
		}
	}
}

func (m *stickyClientStream) runOneStickySession(index int, link clientWAN, remote *net.UDPAddr, tlsTemplate *tls.Config, o clientSessionOptions, compression, fragmentation bool) error {
	packetConn, source, err := wan.Listen(m.ctx, link.SourceIP, link.Interface, remote)
	if err != nil {
		return fmt.Errorf("open pinned realtime WAN: %w", err)
	}
	tr := &quic.Transport{Conn: packetConn}
	defer tr.Close()

	// Deliberately no MultipathController: this connection has exactly
	// one QUIC path, so the library cannot rotate its DATAGRAM packets.
	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 2 * time.Second,
		MaxIdleTimeout: 8 * time.Second,
	}
	dialCtx, cancel := context.WithTimeout(m.ctx, 12*time.Second)
	conn, err := tr.Dial(dialCtx, remote, tlsTemplate.Clone(), quicConfig)
	cancel()
	if err != nil {
		return fmt.Errorf("realtime TLS/QUIC dial: %w", err)
	}
	defer conn.CloseWithError(0, "realtime WAN session ending")
	h3 := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	case <-h3.ReceivedSettings():
	}
	if setting := h3.Settings(); !setting.EnableExtendedConnect || !setting.EnableDatagrams {
		return errors.New("Server realtime QUIC session lacks CONNECT-ETHERNET DATAGRAM")
	}
	request, err := http.NewRequestWithContext(m.ctx, http.MethodConnect, o.tcp.endpoint.requestURL, nil)
	if err != nil {
		return err
	}
	request.Proto = "connect-ethernet"
	request.Header.Set("Capsule-Protocol", "?1")
	if fragmentation {
		request.Header.Set(framingHeader, framingValue)
	}
	request.Header.Set(stickySessionHeader, "sticky-v1")
	request.Header.Set(trafficRoleHeader, "realtime")
	if compression {
		request.Header.Set(compressionHeader, compressionZstd)
	}
	stream, err := h3.OpenRequestStream(m.ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := stream.SendRequestHeader(request); err != nil {
		return fmt.Errorf("realtime CONNECT header: %w", err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return fmt.Errorf("realtime CONNECT response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 ||
		response.Header.Get("Capsule-Protocol") != "?1" ||
		response.Header.Get(stickySessionHeader) != "sticky-v1" {
		return fmt.Errorf("Server rejected pinned realtime session: %s", response.Status)
	}
	if fragmentation && response.Header.Get(framingHeader) != framingValue {
		return errors.New("realtime companion did not negotiate frag-v1")
	}
	m.install(stream)
	defer m.uninstall(stream)
	m.logger.InfoContext(m.ctx, "sticky realtime established",
		"wan_index", index+1, "source_ip", source, "interface", link.Interface,
		"local", packetConn.LocalAddr(), "remote", remote)
	m.recvLoop(stream, false)
	if m.ctx.Err() != nil {
		return m.ctx.Err()
	}
	return errors.New("realtime QUIC path closed")
}
