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
	if _, err := h.AttachWithTrafficRole(context.Background(), old.rule, &fakeStream{out: make(chan []byte, 1)}, false, false, false, true, true); err == nil {
		t.Fatal("second concurrent realtime companion must be rejected")
	}
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
