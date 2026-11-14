package app

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestTCPFallbackOnlyOnUDPHandshakeTimeout(t *testing.T) {
	parent := context.Background()
	ctx, cancel := context.WithDeadline(parent, time.Now().Add(-time.Millisecond))
	defer cancel()
	<-ctx.Done()
	if !eligibleTCPFallback(parent, ctx, context.DeadlineExceeded) {
		t.Fatal("UDP timeout should allow TCP fallback")
	}
	if eligibleTCPFallback(parent, ctx, nil) {
		t.Fatal("successful QUIC connection must not fall back")
	}
	if eligibleTCPFallback(parent, parent, x509.UnknownAuthorityError{}) {
		t.Fatal("TLS trust failure must never silently fall back")
	}
	if eligibleTCPFallback(parent, parent, errors.New("CONNECT rejected")) {
		t.Fatal("application rejection must never silently fall back")
	}
	canceled, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	if eligibleTCPFallback(canceled, ctx, context.DeadlineExceeded) {
		t.Fatal("user cancellation must not trigger fallback")
	}
}

func TestTCPPortIndependentOfUDPPort(t *testing.T) {
	ep, err := planClientEndpoint("tenant.example.com:54433", "", "198.51.100.77")
	if err != nil {
		t.Fatal(err)
	}
	dial, request, err := tcpTarget(clientTCPOptions{endpoint: ep, tcpPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if dial != "198.51.100.77:443" || request != "https://tenant.example.com:443/.well-known/masque/ethernet/" {
		t.Fatalf("wrong TCP default destination: %q %q", dial, request)
	}
	dial, request, err = tcpTarget(clientTCPOptions{endpoint: ep, tcpPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if dial != "198.51.100.77:8443" || request != "https://tenant.example.com:8443/.well-known/masque/ethernet/" {
		t.Fatalf("wrong custom TCP destination: %q %q", dial, request)
	}
}
