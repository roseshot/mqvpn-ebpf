package p2mp

import (
	"context"
	"testing"
	"time"
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
	if _, err := h.AttachWithTunnelIP(context.Background(), a.rule, &fakeStream{out: make(chan []byte, 1)}, false); err == nil {
		t.Fatal("a retired VPN instance accepted a new session")
	}
	h.Detach(a)
	h.Detach(b)
}
