package p2mp

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func testRuleFile(t *testing.T, entries ...PeerConfig) *Config {
	t.Helper()
	cfg, err := Parse(FileConfig{Peers: entries})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPeerMapHotReloadKeepsValidConnection(t *testing.T) {
	before := testRuleFile(t, PeerConfig{
		ID: "A", Routes: []string{"10.77.0.2/32"},
	})
	h, err := New(&fakeDevice{}, before, 1160, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeStream{out: make(chan []byte, 8)}
	session, err := h.AttachWithTrafficRole(ctx, before.Peers[0], stream, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Detach(session)
	next := testRuleFile(t, PeerConfig{
		ID: "A", Routes: []string{"10.77.0.22/32"},
	})
	if err := h.ReplaceConfig(next); err != nil {
		t.Fatal(err)
	}
	if h.cfg.Destination(netip.MustParseAddr("10.77.0.22")).ID != "A" {
		t.Fatal("new destination mapping unavailable")
	}
	if h.cfg.Destination(netip.MustParseAddr("10.77.0.2")) != nil {
		t.Fatal("old destination still mapped")
	}
	select {
	case <-session.ctx.Done():
		t.Fatal("valid session was disconnected on route update")
	default:
	}
	// The active QUIC session is the same session object after the reload.
	h.mu.RLock()
	kept := h.peers["A"]
	h.mu.RUnlock()
	if kept != session {
		t.Fatal("existing session was replaced")
	}
}

func TestPeerRevocationStopsOldSession(t *testing.T) {
	before := testRuleFile(t, PeerConfig{ID: "A", Routes: []string{"10.77.0.2/32"}})
	h, err := New(&fakeDevice{}, before, 1160, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, err := h.AttachWithTrafficRole(ctx, before.Peers[0], &fakeStream{out: make(chan []byte, 8)}, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	next := testRuleFile(t, PeerConfig{ID: "A", CertificateCN: "rotated-site-cn", Routes: []string{"10.77.0.2/32"}})
	if err := h.ReplaceConfig(next); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("changed authorized CN did not revoke session")
	}
	if _, err := h.AttachWithTrafficRole(ctx, before.Peers[0], &fakeStream{out: make(chan []byte, 8)}, false, false, false, false, false); err == nil {
		t.Fatal("stale authorization must not attach after rotation")
	}
	if _, err := h.Authorize([]byte("unregistered")); err == nil {
		t.Fatal("unauthorized certificate accepted")
	}
	h.Detach(session) // safe after revocation; no double close
}

func TestReloadEmptyRejected(t *testing.T) {
	before := testRuleFile(t, PeerConfig{ID: "A", Routes: []string{"10.77.0.2/32"}})
	h, err := New(&fakeDevice{}, before, 1160, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ReplaceConfig(nil); err == nil {
		t.Fatal("nil peer map accepted")
	}
	if h.cfg != before {
		t.Fatal("configuration changed after rejected reload")
	}
}
