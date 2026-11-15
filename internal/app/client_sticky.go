package app

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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
	base            p2mp.Stream
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	active          p2mp.Stream
	generation      uint64 // guarded by mu; fragment IDs are connection-local
	inbound         chan []byte
	realtimeInbound chan p2mp.RealtimeDatagram
	failure         chan error
	wg              sync.WaitGroup
	logger          *slog.Logger
}

func newStickyClientStream(ctx context.Context, base p2mp.Stream, logger *slog.Logger) *stickyClientStream {
	lifetime, cancel := context.WithCancel(ctx)
	m := &stickyClientStream{
		base: base, ctx: lifetime, cancel: cancel, logger: logger,
		inbound: make(chan []byte, 256), realtimeInbound: make(chan p2mp.RealtimeDatagram, 128), failure: make(chan error, 1),
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.recvLoop(base, true, nil, 0)
	}()
	return m
}

func (m *stickyClientStream) SendDatagram(b []byte) error {
	return m.base.SendDatagram(b)
}

func (m *stickyClientStream) SendRealtimeDatagram(b []byte) error {
	// Finish any in-flight QUIC send before uninstall revokes the session.
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return errStickyUnavailable
	}
	return m.active.SendDatagram(b)
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

// ReceiveRealtimeDatagram rejects packets from retired companions, even
// when they were queued before failover. The receiver resets fragment state
// on the tagged generation rather than mixing connection-local fragment IDs.
func (m *stickyClientStream) ReceiveRealtimeDatagram(ctx context.Context) (p2mp.RealtimeDatagram, error) {
	for {
		select {
		case <-ctx.Done():
			return p2mp.RealtimeDatagram{}, ctx.Err()
		case <-m.ctx.Done():
			return p2mp.RealtimeDatagram{}, m.ctx.Err()
		case packet := <-m.realtimeInbound:
			m.mu.RLock()
			valid := m.active != nil && m.generation == packet.Generation
			m.mu.RUnlock()
			if valid {
				return packet, nil
			}
		}
	}
}

func (m *stickyClientStream) recvLoop(stream p2mp.Stream, essential bool, acks chan<- uint64, generation uint64) {
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
		if !essential && p2mp.IsStickyHeartbeat(b) {
			// The heartbeat is a privileged transport-internal control
			// message, never a user IP frame. ACKs are tied to this
			// specific authenticated single-WAN session.
			if acks != nil {
				select {
				case acks <- binary.BigEndian.Uint64(b[1:]):
				default:
				}
			}
			continue
		}
		if essential {
			select {
			case <-m.ctx.Done():
				return
			case m.inbound <- b:
			default:
				m.logger.DebugContext(m.ctx, "bulk VPN inbound queue overflow")
			}
			continue
		}
		// An in-flight read can complete after revocation. Reject it here
		// and again at dequeue to fence packets already buffered.
		m.mu.RLock()
		valid := m.active == stream && m.generation == generation
		m.mu.RUnlock()
		if !valid {
			return
		}
		select {
		case <-m.ctx.Done():
			return
		case m.realtimeInbound <- p2mp.RealtimeDatagram{Payload: b, Generation: generation}:
		default:
			m.logger.DebugContext(m.ctx, "sticky VPN inbound queue overflow")
		}
	}
}

func (m *stickyClientStream) install(stream p2mp.Stream) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	m.active = stream
	return m.generation
}

func (m *stickyClientStream) uninstall(stream p2mp.Stream) {
	m.mu.Lock()
	if m.active == stream {
		m.active = nil
		m.generation++ // invalidate queued packets before the next dial
	}
	m.mu.Unlock()
}

// WithRealtimeGeneration prevents a frame that passed dequeue validation
// before a WAN failover from reaching TUN after that companion was revoked.
// The read lock spans the TUN write so uninstall cannot complete until any
// already-authorized write finishes. Never call back into this stream from
// write: the callback must only write the already-decoded packet.
func (m *stickyClientStream) WithRealtimeGeneration(generation uint64, write func()) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ctx.Err() != nil || m.active == nil || m.generation != generation {
		return false
	}
	write()
	return true
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
	if len(o.wans) == 0 || len(destinations) != len(o.wans) {
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
	packetConn, source, err := platformForClient(o.tcp.platform).ListenUDP(m.ctx, link.SourceIP, link.Interface, remote)
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
		MaxIdleTimeout:  8 * time.Second,
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
	acks := make(chan uint64, 8)
	recvDone := make(chan struct{})
	generation := m.install(stream)
	go func() {
		defer close(recvDone)
		m.recvLoop(stream, false, acks, generation)
	}()
	defer func() {
		m.uninstall(stream)
		// The active receive loop must stop before the next companion
		// starts, so old-path heartbeat ACKs cannot satisfy new probes.
		_ = conn.CloseWithError(0, "sticky WAN disconnected")
		select {
		case <-recvDone:
		case <-time.After(2 * time.Second):
		}
	}()
	m.logger.InfoContext(m.ctx, "sticky realtime established",
		"wan_index", index+1, "source_ip", source, "interface", link.Interface,
		"local", packetConn.LocalAddr(), "remote", remote)
	// QUIC keepalives alone don't establish two-way application reachability.
	// Probe periodically and fail only after a sustained absence of verified
	// round trips. A single lost DATAGRAM on a lossy WAN must not move calls
	// to the next physical interface.
	return runStickyHeartbeats(m.ctx, stream, recvDone, acks, 750*time.Millisecond, 2500*time.Millisecond)
}

// runStickyHeartbeats accepts only echoes of tokens sent on THIS authenticated
// QUIC companion. It tolerates isolated packet loss but tears down blackholed
// paths when no valid response arrives for timeout. Outstanding tokens are
// bounded by the timeout, so a blackhole cannot grow memory indefinitely.
func runStickyHeartbeats(ctx context.Context, stream p2mp.Stream, recvDone <-chan struct{}, acks <-chan uint64, period, timeout time.Duration) error {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	watchdog := time.NewTicker(min(period, timeout/4))
	defer watchdog.Stop()

	nextToken := uint64(time.Now().UnixNano())
	lastReply := time.Now()
	outstanding := make(map[uint64]time.Time)
	send := func() error {
		nextToken++
		ping := make([]byte, p2mp.StickyHeartbeatSize)
		ping[0] = p2mp.StickyHeartbeatMarker
		binary.BigEndian.PutUint64(ping[1:], nextToken)
		if err := stream.SendDatagram(ping); err != nil {
			return fmt.Errorf("pinned WAN heartbeat send: %w", err)
		}
		now := time.Now()
		outstanding[nextToken] = now
		for token, sent := range outstanding {
			if now.Sub(sent) >= timeout {
				delete(outstanding, token)
			}
		}
		return nil
	}
	if err := send(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-recvDone:
			return errors.New("pinned WAN QUIC receiver closed")
		case token := <-acks:
			if sent, ok := outstanding[token]; ok && time.Since(sent) < timeout {
				lastReply = time.Now()
				delete(outstanding, token)
			}
		case <-watchdog.C:
			if time.Since(lastReply) >= timeout {
				return errors.New("pinned WAN heartbeat timed out: no authenticated two-way reply")
			}
		case <-ticker.C:
			if time.Since(lastReply) >= timeout {
				return errors.New("pinned WAN heartbeat timed out: no authenticated two-way reply")
			}
			if err := send(); err != nil {
				return err
			}
		}
	}
}
