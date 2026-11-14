package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
)

type idleStickyTestStream struct{}

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

	old := idleStickyTestStream{}
	oldGeneration := m.install(old)
	m.realtimeInbound <- p2mp.RealtimeDatagram{Payload: []byte("retired"), Generation: oldGeneration}
	m.uninstall(old)
	if err := m.SendRealtimeDatagram([]byte("dropped")); err != errStickyUnavailable {
		t.Fatalf("unavailable companion unexpectedly accepted realtime traffic: %v", err)
	}

	// A newly authenticated companion must not inherit datagrams which
	// the old receiver queued before revocation.
	newSession := idleStickyTestStream{}
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
