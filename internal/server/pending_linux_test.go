//go:build linux

package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

type headerStreamStub struct {
	sent chan []byte
}

func (s *headerStreamStub) SendDatagram(p []byte) error {
	s.sent <- append([]byte(nil), p...)
	return nil
}
func (*headerStreamStub) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPendingHTTP3StreamWaitsForCommittedResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending := &pendingHTTP3Stream{ctx: ctx, ready: make(chan struct{})}
	stream := &headerStreamStub{sent: make(chan []byte, 1)}
	result := make(chan error, 1)
	go func() { result <- pending.SendDatagram([]byte("payload")) }()
	select {
	case err := <-result:
		t.Fatalf("DATAGRAM released before HTTP success response: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	pending.release(stream)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DATAGRAM sender did not resume after HTTP response")
	}
	select {
	case p := <-stream.sent:
		if string(p) != "payload" {
			t.Fatalf("wrong data %q", p)
		}
	default:
		t.Fatal("expected stream DATAGRAM not written")
	}
}

func TestPendingHTTP3StreamCancellationUnblocksSender(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pending := &pendingHTTP3Stream{ctx: ctx, ready: make(chan struct{})}
	cancel()
	if err := pending.SendDatagram([]byte("data")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled handshake should not block a sender: %v", err)
	}
	if _, err := pending.ReceiveDatagram(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled handshake should not block a receiver: %v", err)
	}
}
