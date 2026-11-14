package p2mp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	"github.com/roseshot/mqvpn-ebpf/internal/qos"
)

// Stream is a CONNECT-ETHERNET HTTP/3 DATAGRAM stream.
type Stream interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type Session struct {
	rule        *Rule
	stream      Stream
	tx          chan []byte
	priorityTx  chan []byte
	codec       l3.Codec
	fragmenter  l3.Fragmenter
	reassembler l3.Reassembler
	voip        qos.VoIPMonitor
	done        chan struct{}
	txDone      chan struct{}
	// txMu serializes the nonblocking enqueue with session revocation,
	// so an already-detached peer cannot enqueue into an orphaned queue.
	txMu          sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	tunnelAddress netip.Prefix
}

func (s *Session) ID() string { return s.rule.ID }

// VoIPStats reports receive-side indicators for DSCP EF-marked RTP/RTCP.
func (s *Session) VoIPStats() qos.VoIPStats {
	return s.voip.Snapshot()
}

// stop is called only while holding Hub.mu and only after removing this
// session from Hub.peers. It fences new queue writes before canceling the
// packet sender. A SendDatagram already in progress is transport-owned.
func (s *Session) stop() {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	s.cancel()
	close(s.done)
}

// enqueue never blocks on a slow peer and cannot queue more datagrams once
// stop has finished. A full or retired queue is counted as a drop by Hub.
func (s *Session) enqueue(payload []byte, priority bool) bool {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
	}
	queue := s.tx
	if priority {
		queue = s.priorityTx
	}
	select {
	case queue <- payload:
		return true
	default:
		return false
	}
}
func (s *Session) TunnelAddress() string {
	if !s.tunnelAddress.IsValid() {
		return ""
	}
	return s.tunnelAddress.String()
}

type Hub struct {
	device     io.ReadWriteCloser
	cfg        *Config
	maxFrame   int
	log        *slog.Logger
	mu         sync.RWMutex
	peers      map[string]*Session
	tunnelPool *TunnelPool
	closed     bool
	writer     sync.Mutex
	txFrames   atomic.Uint64
	rxFrames   atomic.Uint64
	drops      atomic.Uint64
}

func New(device io.ReadWriteCloser, cfg *Config, maxFrame int, logger *slog.Logger) (*Hub, error) {
	if device == nil || cfg == nil || len(cfg.Peers) == 0 {
		return nil, errors.New("hub requires TUN and peer destinations")
	}
	if maxFrame < 64 || maxFrame > 65535 {
		return nil, fmt.Errorf("invalid maxFrame %d", maxFrame)
	}
	logger = logging.Ensure(logger)
	return &Hub{device: device, cfg: cfg, maxFrame: maxFrame, log: logger, peers: make(map[string]*Session)}, nil
}

// Authentication is applied only while establishing a tunnel session.
func (h *Hub) Authorize(certDER []byte) (*Rule, error) {
	if len(certDER) == 0 {
		return nil, errors.New("missing client certificate")
	}
	h.mu.RLock()
	rule := h.cfg.PeerByCertificate(certDER)
	h.mu.RUnlock()
	if rule == nil {
		return nil, errors.New("certificate not associated with a P2MP session")
	}
	return rule, nil
}

func (h *Hub) SetTunnelPool(pool *TunnelPool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.peers) > 0 {
		return errors.New("cannot replace tunnel pool with active sessions")
	}
	h.tunnelPool = pool
	return nil
}

// AttachWithTunnelIP allocates only after certificate authorization. The
// requested mode must match the authorized peer policy; a static client
// cannot enter dynamic mode or receive a different static address.
func (h *Hub) AttachWithTunnelIP(ctx context.Context, rule *Rule, stream Stream, requestDynamic bool) (*Session, error) {
	return h.AttachWithCompression(ctx, rule, stream, requestDynamic, false)
}

// AttachWithCompression uses a per-session codec negotiated in the authenticated
// HTTP CONNECT headers. Legacy peers keep the original CONNECT-ETHERNET format.
func (h *Hub) AttachWithCompression(ctx context.Context, rule *Rule, stream Stream, requestDynamic, compression bool) (*Session, error) {
	return h.AttachWithFeatures(ctx, rule, stream, requestDynamic, compression, false)
}

// AttachWithFeatures uses independent authenticated capability negotiation
// for zstd-v1 and frag-v1. Reassembly state is never shared across peers.
func (h *Hub) AttachWithFeatures(ctx context.Context, rule *Rule, stream Stream, requestDynamic, compression, fragmentation bool) (*Session, error) {
	if rule == nil || stream == nil {
		return nil, errors.New("peer and stream required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("attach canceled VPN peer: %w", err)
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("VPN instance is stopping")
	}
	if err := ctx.Err(); err != nil {
		h.mu.Unlock()
		return nil, fmt.Errorf("attach canceled VPN peer: %w", err)
	}
	// An authorization result may have been computed just before a reload.
	// Verify it against the live config while holding the same lock as reload.
	valid := false
	for _, current := range h.cfg.Peers {
		if current.ID == rule.ID && current.Fingerprint == rule.Fingerprint && current.DynamicTunnelIP == rule.DynamicTunnelIP {
			valid = true
			break
		}
	}
	if !valid {
		h.mu.Unlock()
		return nil, fmt.Errorf("peer %s authentication changed during reload", rule.ID)
	}
	if _, exists := h.peers[rule.ID]; exists {
		h.mu.Unlock()
		return nil, fmt.Errorf("peer %s already connected", rule.ID)
	}
	var lease netip.Prefix
	if requestDynamic {
		if !rule.DynamicTunnelIP || h.tunnelPool == nil {
			h.mu.Unlock()
			return nil, fmt.Errorf("peer %s not authorized for dynamic tunnel IP", rule.ID)
		}
		var err error
		lease, err = h.tunnelPool.allocate(h.peers)
		if err != nil {
			h.mu.Unlock()
			return nil, fmt.Errorf("peer %s tunnel pool: %w", rule.ID, err)
		}
	} else if rule.DynamicTunnelIP {
		h.mu.Unlock()
		return nil, fmt.Errorf("peer %s must request a dynamic tunnel IP", rule.ID)
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	s := &Session{rule: rule, stream: stream, tx: make(chan []byte, 192), priorityTx: make(chan []byte, 64), codec: l3.Codec{Compression: compression, MaxFrame: h.maxFrame}, fragmenter: l3.Fragmenter{Enabled: fragmentation}, reassembler: l3.Reassembler{Enabled: fragmentation, MaxFrame: h.maxFrame}, done: make(chan struct{}), txDone: make(chan struct{}), ctx: sessionCtx, cancel: sessionCancel, tunnelAddress: lease}
	h.peers[rule.ID] = s
	h.mu.Unlock()
	go func() {
		defer close(s.txDone)
		burst := 0
		for {
			// Priority takes precedence over bulk packets, with bounded
			// bursts to avoid starving normal traffic on a busy peer.
			packet, ok := qos.Next(s.ctx, s.priorityTx, s.tx, &burst)
			if !ok || s.ctx.Err() != nil {
				return
			}
			// Compress only after priority selection so costly bulk zstd
			// work cannot delay enqueuing a following RTP packet.
			payload, err := s.codec.Wrap(packet, qos.Priority(packet))
			if err != nil {
				h.drops.Add(1)
				continue
			}
			sent, reductions, err := sendEncodedFrame(s.ctx, s.stream, &s.fragmenter, payload)
			h.txFrames.Add(uint64(sent))
			if reductions > 0 {
				h.log.InfoContext(s.ctx, "peer DATAGRAM size budget reduced",
					"peer", s.ID(), "budget", s.fragmenter.Budget(), "reductions", reductions)
			}
			if err != nil {
				h.drops.Add(1)
				h.log.DebugContext(s.ctx, "QUIC DATAGRAM rejected", "peer", s.ID(), "error", err)
			}
		}
	}()

	return s, nil
}

func (h *Hub) Detach(s *Session) {
	if s == nil {
		return
	}
	h.mu.Lock()
	active := h.peers[s.ID()] == s
	if active {
		delete(h.peers, s.ID())
		s.stop()
	}
	h.mu.Unlock()
	if active {
		stats := s.VoIPStats()
		if stats.RTPPackets > 0 || stats.RTCPPackets > 0 {
			h.log.Info("peer VoIP receive summary", "peer", s.ID(), "stats", stats)
		}
	}
}

// PeerVoIPStats returns current receive-side indicators for active peers.
// It can be consumed by a future local diagnostics or metrics exporter.
func (h *Hub) PeerVoIPStats() map[string]qos.VoIPStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]qos.VoIPStats, len(h.peers))
	for id, peer := range h.peers {
		out[id] = peer.VoIPStats()
	}
	return out
}

func (h *Hub) Receive(ctx context.Context, s *Session) error {
	for {
		if s.ctx.Err() != nil || ctx.Err() != nil {
			return nil
		}
		payload, err := s.stream.ReceiveDatagram(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil || ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		// Some stream implementations can deliver a packet concurrently
		// with cancellation. Never inject that packet after revocation.
		if s.ctx.Err() != nil || ctx.Err() != nil {
			return nil
		}
		h.ingress(s, payload)
	}
}

// A single TUN reader handles packets the Linux routing stack emitted on
// the VPN interface. No daemon-managed routes, ACLs or multicast memberships.
func (h *Hub) Run(ctx context.Context) error {
	stopRead := context.AfterFunc(ctx, func() { _ = h.device.Close() })
	defer stopRead()
	defer h.device.Close()
	buf := make([]byte, 65535)
	for {
		n, err := h.device.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read TUN: %w", err)
		}
		h.egress(buf[:n])
	}
}

func (h *Hub) writeTUN(packet []byte) {
	h.writer.Lock()
	n, err := h.device.Write(packet)
	h.writer.Unlock()
	if err != nil || n != len(packet) {
		h.drops.Add(1)
		return
	}
	h.rxFrames.Add(1)
}

// Ingress never examines a peer's inner source or port. Network policy is
// owned by the Linux IP stack and firewall after writing to the TUN.
func (h *Hub) ingress(origin *Session, payload []byte) {
	// Forwarding is deliberately independent of the inner IP source.
	// Still enforce the authenticated *session* boundary: a stream
	// from a revoked peer must not inject packets into the shared TUN.
	if origin == nil || origin.ctx.Err() != nil {
		h.drops.Add(1)
		return
	}
	h.mu.RLock()
	active := h.peers[origin.ID()] == origin && !h.closed
	h.mu.RUnlock()
	if !active {
		h.drops.Add(1)
		return
	}
	frame, ready, err := origin.reassembler.Accept(payload)
	if err != nil {
		h.drops.Add(1)
		return
	}
	if !ready {
		return
	}
	packet, err := origin.codec.Unwrap(frame)
	if err != nil || len(packet)+l3.EthernetLen > h.maxFrame {
		h.drops.Add(1)
		return
	}
	_, dst, _, err := l3.Inspect(packet)
	if err != nil {
		h.drops.Add(1)
		return
	}
	origin.voip.Observe(packet)
	if dst.IsMulticast() || l3.IsBroadcastOrMulticastIP(dst) {
		// P2MP IP multicast/broadcast delivered to every other connected
		// tunnel endpoint, without group allowlists, TTL rewriting or PPS caps.
		h.fanout(origin, packet)
	}
	h.writeTUN(packet)
}

func (h *Hub) egress(packet []byte) {
	_, dst, _, err := l3.Inspect(packet)
	if err != nil || len(packet)+l3.EthernetLen > h.maxFrame {
		h.drops.Add(1)
		return
	}
	if dst.IsMulticast() || l3.IsBroadcastOrMulticastIP(dst) {
		h.fanout(nil, packet)
		return
	}
	h.mu.RLock()
	// Assigned host addresses take precedence over static LAN routes.
	// The pool validator rejects overlapping peer route prefixes.
	for _, leased := range h.peers {
		if leased.tunnelAddress.IsValid() && leased.tunnelAddress.Addr() == dst {
			h.mu.RUnlock()
			h.send(leased, packet)
			return
		}
	}
	rule := h.cfg.Destination(dst)
	if rule == nil {
		h.mu.RUnlock()
		// No remote session owns this destination; the daemon cannot
		// infer a next hop from an IP packet emitted by the shared TUN.
		h.drops.Add(1)
		h.log.Debug("no P2MP destination", "destination", dst)
		return
	}
	peer := h.peers[rule.ID]
	h.mu.RUnlock()
	if peer == nil {
		h.drops.Add(1)
		return
	}
	h.send(peer, packet)
}

// Replicate IP multicast/broadcast to peers in this VPN instance only.
// Physical LAN Ethernet frames cannot enter via a Layer-3 TUN.
func (h *Hub) fanout(origin *Session, packet []byte) {
	h.mu.RLock()
	targets := make([]*Session, 0, len(h.peers))
	for _, s := range h.peers {
		if s != origin {
			targets = append(targets, s)
		}
	}
	h.mu.RUnlock()
	for _, s := range targets {
		h.send(s, packet)
	}
}

func (h *Hub) send(s *Session, packet []byte) {
	priority := qos.Priority(packet)
	// TUN buffers are reused immediately after this callback returns.
	// Queue an owned packet; encode it on the sender goroutine instead.
	queued := append([]byte(nil), packet...)
	// A retired session cannot receive a late enqueue even when both its
	// closed done channel and buffered tx channel would be selectable.
	if !s.enqueue(queued, priority) {
		// Only bounded I/O queue pressure or retired-session cleanup
		// drops an otherwise valid packet. Not an inner IP traffic ACL.
		h.drops.Add(1)
	}
}
func (h *Hub) Counters() (tx, rx, drops uint64) {
	return h.txFrames.Load(), h.rxFrames.Load(), h.drops.Load()
}

// ReplaceConfig atomically swaps the peer-to-session destination map.
// Established connections with unchanged (peer ID, certificate fingerprint)
// remain up, including when their destination prefixes change. A revoked or
// rotated certificate cancels its old session. No Linux routes, addresses,
// multicast memberships, or TUN state are changed here.
func (h *Hub) ReplaceConfig(next *Config) error {
	return h.replaceConfig(next, nil, false)
}

// ReplaceConfigWithPool refreshes static host reservations atomically with
// peer routes. If a new reservation collides with an active lease, reload
// is rejected without evicting or silently reassigning a connected peer.
func (h *Hub) ReplaceConfigWithPool(next *Config, pool *TunnelPool) error {
	return h.replaceConfig(next, pool, true)
}

func (h *Hub) replaceConfig(next *Config, pool *TunnelPool, updatePool bool) error {
	if next == nil || len(next.Peers) == 0 {
		return errors.New("replacement peers configuration is empty")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if updatePool {
		for _, session := range h.peers {
			if !session.tunnelAddress.IsValid() {
				continue
			}
			addr := session.tunnelAddress.Addr()
			if pool == nil || !pool.usable(addr) {
				return fmt.Errorf("cannot reload peer routes: active tunnel lease %s would collide with new pool reservations", addr)
			}
		}
		h.tunnelPool = pool
	}
	accepted := make(map[string]*Rule, len(next.Peers))
	for _, rule := range next.Peers {
		accepted[rule.ID] = rule
	}
	for id, s := range h.peers {
		rule, ok := accepted[id]
		if !ok || rule.Fingerprint != s.rule.Fingerprint || rule.DynamicTunnelIP != s.rule.DynamicTunnelIP {
			delete(h.peers, id)
			s.stop()
			h.log.InfoContext(s.ctx, "peer session revoked by config reload", "peer", id)
		}
	}
	h.cfg = next
	h.log.Info("P2MP forwarding table reloaded", "peers", len(next.Peers))
	return nil
}

// CloseSessions prevents new attachment and cancels every active session.
// Requests from an old TLS configuration may still exist but cannot send
// further IP packets through a retired VPN instance.
func (h *Hub) CloseSessions() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, s := range h.peers {
		delete(h.peers, id)
		s.stop()
	}
}
