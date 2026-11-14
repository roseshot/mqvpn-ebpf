package app

import (
	"context"
	"io"
	"log/slog"
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
