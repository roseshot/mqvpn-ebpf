package p2mp

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

type dualClassStream struct {
	baseIn      chan []byte
	realtimeIn  chan RealtimeDatagram
	bulkOut     chan []byte
	realtimeOut chan []byte
}

func (s *dualClassStream) SendDatagram(b []byte) error {
	s.bulkOut <- append([]byte(nil), b...)
	return nil
}
func (s *dualClassStream) SendRealtimeDatagram(b []byte) error {
	s.realtimeOut <- append([]byte(nil), b...)
	return nil
}
func (s *dualClassStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b := <-s.baseIn:
		return b, nil
	}
}
func (s *dualClassStream) ReceiveRealtimeDatagram(ctx context.Context) (RealtimeDatagram, error) {
	select {
	case <-ctx.Done():
		return RealtimeDatagram{}, ctx.Err()
	case b := <-s.realtimeIn:
		return b, nil
	}
}

func TestClientPumpNeverRotatesEFOrSIPOntoBulkSession(t *testing.T) {
	device := newTestTun()
	stream := &dualClassStream{
		baseIn: make(chan []byte, 8), realtimeIn: make(chan RealtimeDatagram, 8),
		bulkOut: make(chan []byte, 8), realtimeOut: make(chan []byte, 8),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ClientPumpWithFeatures(ctx, device, stream, 1500, false, false, nil) }()
	pkt := ip4([4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1})
	pkt[1] = 46 << 2 // DSCP EF (RTP/RTCP)
	device.in <- pkt
	select {
	case frame := <-stream.realtimeOut:
		got, err := l3.Unwrap(frame)
		if err != nil || string(got) != string(pkt) {
			t.Fatalf("realtime EF packet corrupted: %v", err)
		}
		stream.realtimeIn <- RealtimeDatagram{Payload: frame, Generation: 1}
	case <-time.After(time.Second):
		t.Fatal("priority client packet never reached realtime companion")
	}
	select {
	case <-stream.bulkOut:
		t.Fatal("priority EF packet leaked onto bulk multipath session")
	default:
	}
	bulk := ip4([4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1})
	device.in <- bulk
	select {
	case frame := <-stream.bulkOut:
		got, err := l3.Unwrap(frame)
		if err != nil || string(got) != string(bulk) {
			t.Fatalf("bulk packet corrupted: %v", err)
		}
		stream.baseIn <- frame
	case <-time.After(time.Second):
		t.Fatal("normal packet did not reach bulk QUIC session")
	}
	deadline := time.After(time.Second)
	for {
		device.mu.Lock()
		count := len(device.out)
		device.mu.Unlock()
		if count >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("independent bulk/realtime receive paths failed to inject TUN")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dual receive pump did not shut down")
	}
}

// Keep the two read paths independent under simultaneous delivery. A
// production TUN must never see concurrent Write calls, even while
// both QUIC receivers are busy.
type serializeCheckDevice struct {
	*testTun
	mu         sync.Mutex
	busy       bool
	concurrent bool
}

func (d *serializeCheckDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	if d.busy {
		d.concurrent = true
	}
	d.busy = true
	d.mu.Unlock()
	time.Sleep(time.Millisecond)
	n, err := d.testTun.Write(p)
	d.mu.Lock()
	d.busy = false
	d.mu.Unlock()
	return n, err
}

func TestClientPumpRealtimeFragmentsNeverCrossCompanionGenerations(t *testing.T) {
	device := newTestTun()
	stream := &dualClassStream{
		baseIn: make(chan []byte, 8), realtimeIn: make(chan RealtimeDatagram, 8),
		bulkOut: make(chan []byte, 8), realtimeOut: make(chan []byte, 8),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ClientPumpWithFeatures(ctx, device, stream, 2048, false, true, nil) }()

	old := append(ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 2}), make([]byte, 1400)...)
	binary.BigEndian.PutUint16(old[2:4], uint16(len(old)))
	old[40] = 0x11
	current := append([]byte(nil), old...)
	current[40] = 0x22
	current[len(current)-1] = 0x33
	oldFrame, err := l3.Wrap(old)
	if err != nil {
		t.Fatal(err)
	}
	currentFrame, err := l3.Wrap(current)
	if err != nil {
		t.Fatal(err)
	}
	oldFragments, err := (&l3.Fragmenter{Enabled: true}).Split(oldFrame)
	if err != nil {
		t.Fatal(err)
	}
	currentFragments, err := (&l3.Fragmenter{Enabled: true}).Split(currentFrame)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldFragments) != 2 || len(currentFragments) != 2 {
		t.Fatal("test requires two fragments with colliding connection-local IDs")
	}
	// Without generation isolation, the first old fragment and second new
	// fragment can combine into a valid-looking but corrupted IP packet.
	stream.realtimeIn <- RealtimeDatagram{Payload: oldFragments[0], Generation: 10}
	stream.realtimeIn <- RealtimeDatagram{Payload: currentFragments[1], Generation: 11}
	stream.realtimeIn <- RealtimeDatagram{Payload: currentFragments[0], Generation: 11}

	deadline := time.After(2 * time.Second)
	for {
		device.mu.Lock()
		count := len(device.out)
		var got []byte
		if count > 0 {
			got = append([]byte(nil), device.out[0]...)
		}
		device.mu.Unlock()
		if count > 0 {
			if count != 1 || string(got) != string(current) {
				t.Fatalf("fragments crossed QUIC generations: writes=%d current=%t", count, string(got) == string(current))
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("new companion failed to reassemble a complete frame")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client pump blocked after generation change")
	}
}
