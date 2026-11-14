package p2mp

import (
	"context"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

func TestStickyRealtimeCompanionRoutesOnlyPriorityData(t *testing.T) {
	h, dev, a, old, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(a)
	h.Detach(old)

	// An independently authenticated realtime companion is not allowed
	// without a primary session that explicitly negotiated sticky-v1.
	unauthorized := &fakeStream{out: make(chan []byte, 8)}
	if _, err := h.AttachWithTrafficRole(context.Background(), old.rule, unauthorized, false, false, false, true, true); err == nil {
		t.Fatal("realtime companion attached without sticky primary")
	}
	h.Detach(old)
	normal := &fakeStream{out: make(chan []byte, 8)}
	primary, err := h.AttachWithTrafficRole(context.Background(), old.rule, normal, false, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(primary)
	realtime := &fakeStream{out: make(chan []byte, 8)}
	companion, err := h.AttachWithTrafficRole(context.Background(), old.rule, realtime, false, false, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(companion)
	// A later mTLS-authenticated realtime session must take over an
	// unreachable predecessor without waiting for its QUIC idle timeout.
	newRealtime := &fakeStream{out: make(chan []byte, 8)}
	takeover, err := h.AttachWithTrafficRole(context.Background(), old.rule, newRealtime, false, false, false, true, true)
	if err != nil {
		t.Fatalf("authenticated sticky failover should replace old companion: %v", err)
	}
	if companion.ctx.Err() == nil {
		t.Fatal("predecessor companion remained authorized after takeover")
	}
	companion = takeover
	realtime = newRealtime
	voice := ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 3})
	voice[1] = 46 << 2 // DSCP EF
	h.egress(voice)
	got, err := l3.Unwrap(waitFrame(t, realtime))
	if err != nil || string(got) != string(voice) {
		t.Fatalf("high priority flow was not delivered over sticky companion: %v", err)
	}
	if len(normal.out) != 0 {
		t.Fatal("high priority flow leaked into round-robin base session")
	}
	bulk := ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 3})
	h.egress(bulk)
	got, err = l3.Unwrap(waitFrame(t, normal))
	if err != nil || string(got) != string(bulk) {
		t.Fatalf("bulk flow failed on normal session: %v", err)
	}
	if len(realtime.out) != 0 {
		t.Fatal("ordinary bulk flow leaked to sticky WAN")
	}
	// Companion has its own authenticated ingress and fragment namespace.
	h.ingress(companion, mustFrame(t, voice))
	if dev.count() != 1 {
		t.Fatal("realtime companion could not receive and inject TUN datagrams")
	}
	h.Detach(companion)
	h.egress(voice)
	select {
	case <-normal.out:
		t.Fatal("realtime RTP rotated to bulk WAN during companion outage")
	case <-time.After(35 * time.Millisecond):
	}
	// A replacement companion is possible without tearing down the
	// authenticated primary session or its tunnel lease.
	next := &fakeStream{out: make(chan []byte, 8)}
	replacement, err := h.AttachWithTrafficRole(context.Background(), old.rule, next, false, false, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(replacement)
	h.egress(voice)
	if _, err := l3.Unwrap(waitFrame(t, next)); err != nil {
		t.Fatalf("sticky peer failed to resume after WAN rebind: %v", err)
	}
	h.Detach(primary)
	if replacement.ctx.Err() == nil {
		t.Fatal("revoking primary failed to cancel the companion")
	}
	h.ingress(replacement, mustFrame(t, voice))
	if dev.count() != 1 {
		t.Fatal("old realtime companion injected a TUN frame after primary revocation")
	}
}

type stickyEchoStream struct {
	input  chan []byte
	output chan []byte
}

func (s *stickyEchoStream) SendDatagram(b []byte) error {
	s.output <- append([]byte(nil), b...)
	return nil
}

func (s *stickyEchoStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b := <-s.input:
		return b, nil
	}
}

func TestStickyHeartbeatIsNotAnInnerIPPacket(t *testing.T) {
	h, dev, a, initial, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(a)
	h.Detach(initial)
	primary, err := h.AttachWithTrafficRole(context.Background(), initial.rule,
		&fakeStream{out: make(chan []byte, 8)}, false, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(primary)
	stream := &stickyEchoStream{input: make(chan []byte, 1), output: make(chan []byte, 1)}
	companion, err := h.AttachWithTrafficRole(context.Background(), initial.rule, stream,
		false, false, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(companion)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- h.Receive(ctx, companion) }()
	ping := []byte{StickyHeartbeatMarker, 1, 2, 3, 4, 5, 6, 7, 8}
	if !IsStickyHeartbeat(ping) {
		t.Fatal("heartbeat framing rejected")
	}
	stream.input <- ping
	select {
	case got := <-stream.output:
		if string(got) != string(ping) {
			t.Fatalf("bad heartbeat response %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated heartbeat was not echoed")
	}
	if got := dev.count(); got != 0 {
		t.Fatalf("heartbeat leaked %d inner IP packets into TUN", got)
	}
	stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat receive worker did not stop")
	}
}
