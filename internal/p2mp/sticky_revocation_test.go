package p2mp

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// revocationGateTUN models a slow Linux TUN writer. It lets the test force
// Detach to race with an already authorized inbound QUIC datagram.
type revocationGateTUN struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	writes  atomic.Int32
}

func (d *revocationGateTUN) Read([]byte) (int, error) { return 0, io.EOF }
func (d *revocationGateTUN) Close() error             { return nil }
func (d *revocationGateTUN) Write(packet []byte) (int, error) {
	d.once.Do(func() { close(d.entered) })
	<-d.release
	d.writes.Add(1)
	return len(packet), nil
}

func TestServerRealtimeDetachWaitsForAuthorizedTUNWrite(t *testing.T) {
	h, _, other, old, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(other)
	h.Detach(old)

	primary, err := h.AttachWithTrafficRole(context.Background(), old.rule,
		&fakeStream{out: make(chan []byte, 8)}, false, false, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(primary)
	companion, err := h.AttachWithTrafficRole(context.Background(), old.rule,
		&fakeStream{out: make(chan []byte, 8)}, false, false, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(companion)

	device := &revocationGateTUN{entered: make(chan struct{}), release: make(chan struct{})}
	h.device = device
	voice := ip4([4]byte{10, 77, 0, 3}, [4]byte{10, 77, 0, 1})
	voice[1] = 46 << 2
	frame := mustFrame(t, voice)
	injected := make(chan struct{})
	go func() {
		h.ingress(companion, frame)
		close(injected)
	}()
	select {
	case <-device.entered:
	case <-time.After(time.Second):
		t.Fatal("authenticated companion never reached TUN writer")
	}

	detached := make(chan struct{})
	go func() {
		h.Detach(companion)
		close(detached)
	}()
	select {
	case <-detached:
		close(device.release)
		t.Fatal("companion detached before in-flight TUN write completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(device.release)
	select {
	case <-injected:
	case <-time.After(time.Second):
		t.Fatal("in-flight TUN write did not complete")
	}
	select {
	case <-detached:
	case <-time.After(time.Second):
		t.Fatal("companion revocation remained blocked after write finished")
	}
	if got := device.writes.Load(); got != 1 {
		t.Fatalf("expected one authorized TUN write, got %d", got)
	}
	// A datagram obtained by an old QUIC receiver must not inject after
	// revocation returns, even if its packet payload is otherwise valid.
	h.ingress(companion, frame)
	if got := device.writes.Load(); got != 1 {
		t.Fatalf("retired companion injected %d extra packets", got-1)
	}
}
