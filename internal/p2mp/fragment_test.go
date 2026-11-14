package p2mp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

func testLargeIP(src, dst [4]byte) []byte {
	pkt := make([]byte, 1500)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	for i := 20; i < len(pkt); i++ {
		pkt[i] = byte(i * 37)
	}
	return pkt
}

func waitOutput(t *testing.T, c <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-c:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("timed out receiving fragmented DATAGRAM")
		return nil
	}
}

func TestClientMTU1500FragmentedRoundTrip(t *testing.T) {
	device := newTestTun()
	stream := &testDatagrams{
		in:  make(chan []byte, 4),
		out: make(chan []byte, 4),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ClientPumpWithFeatures(ctx, device, stream, 1514, false, true,
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	pkt := testLargeIP([4]byte{10, 1, 0, 1}, [4]byte{10, 1, 0, 2})
	device.in <- pkt
	first := waitOutput(t, stream.out)
	second := waitOutput(t, stream.out)
	if len(first) > l3.FragmentPayloadBudget || len(second) > l3.FragmentPayloadBudget {
		t.Fatal("client sent oversized DATAGRAM fragment")
	}
	// Simulate MPQUIC out-of-order arrival.
	stream.in <- second
	stream.in <- first
	deadline := time.After(2 * time.Second)
	for {
		device.mu.Lock()
		matched := len(device.out) > 0 && bytes.Equal(device.out[0], pkt)
		device.mu.Unlock()
		if matched {
			break
		}
		select {
		case <-deadline:
			t.Fatal("fragmented client roundtrip lost IP payload")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("client shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client pump did not stop")
	}
}

func TestServerMTU1500FragmentedRoundTrip(t *testing.T) {
	h, device, a, b, _, _, cancel := prepare(t)
	// prepare uses the legacy 1160-byte fixture budget. Explicitly
	// enable the 1500-byte TUN budget before attaching the new session.
	h.maxFrame = 1514
	defer cancel()
	defer h.Detach(a)
	h.Detach(b)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stream := &fakeStream{out: make(chan []byte, 8)}
	enabled, err := h.AttachWithFeatures(ctx, h.cfg.Peers[1], stream, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(enabled)
	pkt := testLargeIP([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 3})
	h.egress(pkt)
	one := waitOutput(t, stream.out)
	two := waitOutput(t, stream.out)
	if len(one) > l3.FragmentPayloadBudget || len(two) > l3.FragmentPayloadBudget {
		t.Fatal("server sent oversized DATAGRAM fragment")
	}
	incoming := testLargeIP([4]byte{10, 77, 0, 3}, [4]byte{10, 77, 0, 1})
	frame, err := l3.Wrap(incoming)
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := (&l3.Fragmenter{Enabled: true}).Split(frame)
	if err != nil || len(fragments) != 2 {
		t.Fatalf("cannot build server ingress fragments: %v", err)
	}
	h.ingress(enabled, fragments[1])
	if device.count() != 0 {
		t.Fatal("incomplete fragment emitted into TUN")
	}
	h.ingress(enabled, fragments[0])
	if device.count() != 1 {
		t.Fatal("reassembled IP was not written to TUN")
	}
	device.mu.Lock()
	got := append([]byte(nil), device.out[0]...)
	device.mu.Unlock()
	if !bytes.Equal(got, incoming) {
		t.Fatal("server reassembled the wrong IP bytes")
	}
}
