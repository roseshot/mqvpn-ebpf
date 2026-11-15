package p2mp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

func TestHubShutdownRevokesActiveSessions(t *testing.T) {
	h, _, a, b, _, _, cancel := prepare(t)
	defer cancel()
	h.CloseSessions()
	h.CloseSessions()
	for _, s := range []*Session{a, b} {
		select {
		case <-s.ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("session %s did not terminate", s.ID())
		}
	}
	if _, err := h.AttachWithTrafficRole(context.Background(), a.rule, &fakeStream{out: make(chan []byte, 1)}, false, false, false, false, false); err == nil {
		t.Fatal("a retired VPN instance accepted a new session")
	}
	h.Detach(a)
	h.Detach(b)
	for _, s := range []*Session{a, b} {
		select {
		case <-s.txDone:
		case <-time.After(time.Second):
			t.Fatalf("retired peer %s sender worker did not exit", s.ID())
		}
	}
}

type delayedCanceledPacketStream struct {
	entered chan struct{}
	release chan struct{}
	payload []byte
}

func (s *delayedCanceledPacketStream) SendDatagram([]byte) error { return nil }
func (s *delayedCanceledPacketStream) ReceiveDatagram(context.Context) ([]byte, error) {
	close(s.entered)
	<-s.release
	// Deliberately violates normal cancellation by returning a successful
	// frame after the peer was removed. The Hub must fail closed.
	return s.payload, nil
}

func TestRevokedPeerCannotInjectLateSuccessfulDatagram(t *testing.T) {
	h, device, a, b, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(b)
	payload := mustFrame(t, ip4([4]byte{198, 51, 100, 1}, [4]byte{10, 77, 0, 1}))
	late := &delayedCanceledPacketStream{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		payload: payload,
	}
	h.Detach(a)
	reactivated, err := h.AttachWithTrafficRole(context.Background(), a.rule, late, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	a = reactivated
	result := make(chan error, 1)
	go func() { result <- h.Receive(context.Background(), a) }()
	select {
	case <-late.entered:
	case <-time.After(time.Second):
		t.Fatal("receive did not start")
	}
	h.Detach(a)
	close(late.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("revoked receive returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("revoked stream kept receiving after cancellation")
	}
	// Also reject direct late ingress from an old handler and late queue
	// writes, even if the output queue still has available capacity.
	for range 100 {
		h.ingress(a, payload)
		h.send(a, ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 2}))
	}
	if got := device.count(); got != 0 {
		t.Fatalf("revoked peer injected %d late packets into shared TUN", got)
	}
	select {
	case <-a.txDone:
	case <-time.After(time.Second):
		t.Fatal("revoked sender worker did not exit")
	}
	if got := len(a.tx); got != 0 {
		t.Fatalf("revoked peer accumulated %d datagrams after shutdown", got)
	}
}

func TestOldSessionCannotInjectIntoReauthenticatedPeerSession(t *testing.T) {
	h, device, old, other, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(other)
	h.Detach(old)
	newStream := &fakeStream{out: make(chan []byte, 8)}
	current, err := h.AttachWithTrafficRole(context.Background(), old.rule, newStream, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(current)
	packet := ip4([4]byte{192, 0, 2, 100}, [4]byte{10, 77, 0, 1})
	frame, err := l3.Wrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	h.ingress(old, frame)
	h.ingress(current, frame)
	if got := device.count(); got != 1 {
		t.Fatalf("expected only new authorized session ingress, got %d packets", got)
	}
	h.egress(ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 2}))
	if _, err := l3.Unwrap(waitFrame(t, newStream)); err != nil {
		t.Fatalf("new peer session cannot receive routed packets: %v", err)
	}
	if len(old.tx) != 0 {
		t.Fatal("stale queue received packets from new session")
	}
}

func TestAttachRejectsAlreadyCanceledContext(t *testing.T) {
	h, _, a, b, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(a)
	defer h.Detach(b)
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := h.AttachWithTrafficRole(ctx, a.rule, &fakeStream{out: make(chan []byte, 1)}, false, false, false, false, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context accepted for new peer: %v", err)
	}
}

type blockedSendDatagramStream struct {
	entered chan struct{}
	release chan struct{}
}

func (s *blockedSendDatagramStream) SendDatagram([]byte) error {
	close(s.entered)
	<-s.release
	return nil
}

func (s *blockedSendDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPeerDetachNeverWaitsOnBlockedTransportSend(t *testing.T) {
	h, _, a, b, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(b)
	h.Detach(a)
	stream := &blockedSendDatagramStream{entered: make(chan struct{}), release: make(chan struct{})}
	current, err := h.AttachWithTrafficRole(context.Background(), a.rule, stream, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	h.egress(ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 2}))
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("stream send did not begin")
	}
	done := make(chan struct{})
	go func() {
		h.Detach(current)
		close(done)
	}()
	select {
	case <-done:
		// No transport-level deadlock during peer detachment or hot reload.
	case <-time.After(time.Second):
		close(stream.release)
		t.Fatal("detach blocked while sender was in SendDatagram")
	}
	close(stream.release)
	select {
	case <-current.txDone:
	case <-time.After(time.Second):
		t.Fatal("blocked send worker failed to exit after release")
	}
}
