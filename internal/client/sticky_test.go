package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
)

type idleStickyTestStream struct{ index int }

func (idleStickyTestStream) SendDatagram([]byte) error { return nil }
func (idleStickyTestStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStickyClientStreamDiscardsRetiredCompanionQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newStickyClientStream(ctx, idleStickyTestStream{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.close()

	old := &idleStickyTestStream{index: 1}
	oldGeneration := m.install(old)
	m.realtimeInbound <- p2mp.RealtimeDatagram{Payload: []byte("retired"), Generation: oldGeneration}
	m.uninstall(old)
	if err := m.SendRealtimeDatagram([]byte("dropped")); err != errStickyUnavailable {
		t.Fatalf("unavailable companion unexpectedly accepted realtime traffic: %v", err)
	}

	// A newly authenticated companion must not inherit datagrams which
	// the old receiver queued before revocation.
	newSession := &idleStickyTestStream{index: 2}
	newGeneration := m.install(newSession)
	if newGeneration == oldGeneration {
		t.Fatal("companion generation was reused after failover")
	}
	m.realtimeInbound <- p2mp.RealtimeDatagram{Payload: []byte("current"), Generation: newGeneration}
	readCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	frame, err := m.ReceiveRealtimeDatagram(readCtx)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Generation != newGeneration || string(frame.Payload) != "current" {
		t.Fatalf("received retired companion payload: %+v", frame)
	}
	m.uninstall(newSession)
}

func TestStickyClientStreamRevocationFencesInFlightTUNWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newStickyClientStream(ctx, &idleStickyTestStream{index: 0}, nil)
	defer m.close()

	companion := &idleStickyTestStream{index: 3}
	generation := m.install(companion)
	entered := make(chan struct{})
	release := make(chan struct{})
	writeDone := make(chan bool, 1)
	go func() {
		writeDone <- m.WithRealtimeGeneration(generation, func() {
			close(entered)
			<-release // model an in-flight, potentially blocking TUN write
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("realtime write did not acquire generation fence")
	}
	uninstalled := make(chan struct{})
	go func() {
		m.uninstall(companion)
		close(uninstalled)
	}()
	// Uninstall must not succeed while a previously authorized TUN write
	// is still in progress; otherwise late writes could cross revocation.
	select {
	case <-uninstalled:
		close(release)
		t.Fatal("companion uninstalled before the in-flight write finished")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case ok := <-writeDone:
		if !ok {
			t.Fatal("in-flight write lost authorization before uninstall")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight write did not finish")
	}
	select {
	case <-uninstalled:
	case <-time.After(time.Second):
		t.Fatal("companion uninstall did not complete")
	}
	called := false
	if m.WithRealtimeGeneration(generation, func() { called = true }) || called {
		t.Fatal("retired companion could execute a TUN write after revocation")
	}
}

type heartbeatProbeStream struct {
	sent chan []byte
}

func (s *heartbeatProbeStream) SendDatagram(packet []byte) error {
	s.sent <- append([]byte(nil), packet...)
	return nil
}

func (s *heartbeatProbeStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStickyHeartbeatToleratesOneDroppedEcho(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &heartbeatProbeStream{sent: make(chan []byte, 32)}
	acks := make(chan uint64, 32)
	recvDone := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- runStickyHeartbeats(ctx, stream, recvDone, acks, 20*time.Millisecond, 250*time.Millisecond)
	}()

	// One lost heartbeat on a lossy WAN is expected. The next matching
	// authenticated reply must keep the connection on the same WAN.
	for i := 1; i <= 12; i++ {
		select {
		case packet := <-stream.sent:
			if !p2mp.IsStickyHeartbeat(packet) {
				t.Fatalf("invalid heartbeat %x", packet)
			}
			if i != 5 {
				acks <- binary.BigEndian.Uint64(packet[1:])
			}
		case err := <-finished:
			t.Fatalf("isolated heartbeat loss caused WAN failover: %v", err)
		case <-time.After(time.Second):
			t.Fatal("heartbeat sender stopped before recovery")
		}
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected heartbeat shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat sender failed to stop")
	}
}

func TestStickyHeartbeatBlackholeTimesOutDespiteStaleEchoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &heartbeatProbeStream{sent: make(chan []byte, 64)}
	acks := make(chan uint64, 64)
	recvDone := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- runStickyHeartbeats(ctx, stream, recvDone, acks, 25*time.Millisecond, 190*time.Millisecond)
	}()

	probes := 0
	for {
		select {
		case packet := <-stream.sent:
			probes++
			token := binary.BigEndian.Uint64(packet[1:])
			if probes <= 2 {
				acks <- token
			} else {
				// Old and never-sent tokens cannot create a false
				// impression of reachability after WAN blackhole.
				acks <- token - 1_000_000
			}
		case err := <-finished:
			if err == nil || !strings.Contains(err.Error(), "heartbeat timed out") {
				t.Fatalf("blackholed WAN was not detected: %v", err)
			}
			if probes < 4 {
				t.Fatalf("watchdog did not retry before failover: %d probes", probes)
			}
			return
		case <-time.After(2 * time.Second):
			t.Fatal("blackholed WAN did not trigger heartbeat timeout")
		}
	}
}
