package p2mp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

type testTun struct {
	in   chan []byte
	stop chan struct{}
	once sync.Once
	mu   sync.Mutex
	out  [][]byte
}

func newTestTun() *testTun { return &testTun{in: make(chan []byte, 8), stop: make(chan struct{})} }
func (d *testTun) Read(buf []byte) (int, error) {
	select {
	case <-d.stop:
		return 0, io.EOF
	case packet := <-d.in:
		return copy(buf, packet), nil
	}
}
func (d *testTun) Write(packet []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.out = append(d.out, append([]byte(nil), packet...))
	return len(packet), nil
}
func (d *testTun) Close() error    { d.once.Do(func() { close(d.stop) }); return nil }
func (d *testTun) hasOutput() bool { d.mu.Lock(); defer d.mu.Unlock(); return len(d.out) > 0 }

type testDatagrams struct {
	in  chan []byte
	out chan []byte
}

func (s *testDatagrams) SendDatagram(p []byte) error {
	s.out <- append([]byte(nil), p...)
	return nil
}
func (s *testDatagrams) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data := <-s.in:
		return data, nil
	}
}

func TestClientForwardsMulticastWithoutFiltering(t *testing.T) {
	device := newTestTun()
	stream := &testDatagrams{in: make(chan []byte, 2), out: make(chan []byte, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ClientPumpWithFeatures(ctx, device, stream, 1160, false, false, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	// Deliberately not UDP/5353, not TTL 255: transport must not impose
	// an mDNS/port/TTL-specific policy on tunnel contents.
	multicast := ip4([4]byte{10, 77, 0, 2}, [4]byte{224, 0, 0, 251})
	multicast[8] = 3
	multicast[9] = 1
	device.in <- multicast
	var encoded []byte
	select {
	case encoded = <-stream.out:
	case <-time.After(time.Second):
		t.Fatal("client filtered outgoing multicast")
	}
	roundtrip, err := l3.Unwrap(encoded)
	if err != nil || string(roundtrip) != string(multicast) {
		t.Fatalf("packet changed %v", err)
	}
	stream.in <- encoded
	deadline := time.After(time.Second)
	for !device.hasOutput() {
		select {
		case <-deadline:
			t.Fatal("client filtered incoming multicast")
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
		t.Fatal("client shutdown stuck")
	}
}

type closeErrorTUN struct {
	*testTun
	closeErr error
}

func (d *closeErrorTUN) Close() error { _ = d.testTun.Close(); return d.closeErr }
func TestClientPumpReportsCleanupError(t *testing.T) {
	failure := errors.New("unable to restore TUN")
	device := &closeErrorTUN{testTun: newTestTun(), closeErr: failure}
	stream := &testDatagrams{in: make(chan []byte, 2), out: make(chan []byte, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ClientPumpWithFeatures(ctx, device, stream, 1160, false, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !errors.Is(err, failure) {
		t.Fatalf("ClientPump swallowed TUN Close failure: %v", err)
	}
}

type immediateEOFDatagrams struct{}

func (immediateEOFDatagrams) SendDatagram([]byte) error                       { return nil }
func (immediateEOFDatagrams) ReceiveDatagram(context.Context) ([]byte, error) { return nil, io.EOF }

type readCompletionTun struct {
	*testTun
	readDone chan struct{}
	onceRead sync.Once
}

func (d *readCompletionTun) Read(b []byte) (int, error) {
	n, err := d.testTun.Read(b)
	d.onceRead.Do(func() { close(d.readDone) })
	return n, err
}

func TestClientPumpRemoteEOFWaitsForBlockedTUNReader(t *testing.T) {
	for range 64 {
		device := &readCompletionTun{testTun: newTestTun(), readDone: make(chan struct{})}
		err := ClientPumpWithFeatures(context.Background(), device, immediateEOFDatagrams{}, 1160, false, false, nil)
		if err != nil {
			t.Fatalf("unexpected remote EOF: %v", err)
		}
		select {
		case <-device.readDone:
		default:
			t.Fatal("ClientPump returned before its TUN reader exited")
		}
		select {
		case <-device.stop:
		default:
			t.Fatal("ClientPump did not close TUN before returning")
		}
	}
}

func TestGo127GoroutineLeakProfileAfterRepeatedClientPumps(t *testing.T) {
	// Go 1.27 promotes goroutineleak from experiment to a standard pprof
	// profile. Detect any permanently blocked ClientPump worker that was
	// not joined before the next VPN session.
	for range 64 {
		device := newTestTun()
		stream := &testDatagrams{in: make(chan []byte, 2), out: make(chan []byte, 2)}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := ClientPumpWithFeatures(ctx, device, stream, 1160, false, false, nil); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	profile := pprof.Lookup("goroutineleak")
	if profile == nil {
		t.Fatal("Go 1.27 goroutineleak profile is unavailable")
	}
	var out bytes.Buffer
	if err := profile.WriteTo(&out, 1); err != nil {
		t.Fatalf("read goroutineleak profile: %v", err)
	}
	if strings.Contains(out.String(), "github.com/roseshot/mqvpn-ebpf/internal/p2mp.ClientPump.func") {
		t.Fatalf("ClientPump left permanently blocked worker:\n%s", out.String())
	}
}
