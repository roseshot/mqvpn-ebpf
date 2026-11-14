package p2mp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConfigDestinationAndAuthentication(t *testing.T) {
	a := sha256.Sum256([]byte("peer-a"))
	b := sha256.Sum256([]byte("peer-b"))
	c, err := Parse(FileConfig{Peers: []PeerConfig{
		{ID: "A", CertificateSHA256: hex.EncodeToString(a[:]), Routes: []string{"10.77.0.2/32", "192.168.20.0/24"}},
		{ID: "B", CertificateSHA256: hex.EncodeToString(b[:]), Routes: []string{"10.77.0.3/32", "192.168.30.0/24"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Destination(netip.MustParseAddr("10.77.0.3")).ID != "B" {
		t.Fatal("wrong session")
	}
	if c.Destination(netip.MustParseAddr("192.168.20.44")).ID != "A" {
		t.Fatal("wrong LAN prefix")
	}
	if c.PeerByCertificate([]byte("peer-a")) != c.Peers[0] {
		t.Fatal("peer A not authenticated")
	}
	if c.PeerByCertificate([]byte("unknown")) != nil {
		t.Fatal("unknown certificate accepted")
	}
	if c.Destination(netip.MustParseAddr("224.0.0.251")) != nil {
		t.Fatal("multicast must use replication")
	}
}
func TestAmbiguousPeerDestinationsRejected(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	_, err := Parse(FileConfig{Peers: []PeerConfig{
		{ID: "A", CertificateSHA256: a, Routes: []string{"10.77.0.0/24"}},
		{ID: "B", CertificateSHA256: b, Routes: []string{"10.77.0.3/32"}},
	}})
	if err == nil {
		t.Fatal("overlapping destinations ambiguous")
	}
}
func TestDefaultRouteIsValidSessionDestination(t *testing.T) {
	_, err := Parse(FileConfig{Peers: []PeerConfig{
		{ID: "all", CertificateSHA256: strings.Repeat("a", 64), Routes: []string{"0.0.0.0/0"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func testClientCertificateCN(t *testing.T, cn string) []byte {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPeerCNAuthorizationWithoutFingerprint(t *testing.T) {
	cfg, err := Parse(FileConfig{Peers: []PeerConfig{
		{ID: "site-a", CertificateCN: "vpn-client-a", Routes: []string{"10.77.0.2/32"},
			PushRoutes: []string{"10.16.0.0/16"}, PushDNS: []string{}},
		{ID: "vpn-client-b", Routes: []string{"10.77.0.3/32"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cn, want string }{
		{"vpn-client-a", "site-a"}, {"vpn-client-b", "vpn-client-b"},
	} {
		got := cfg.PeerByCertificate(testClientCertificateCN(t, tc.cn))
		if got == nil || got.ID != tc.want {
			t.Fatalf("CN %q matched %v, want %q", tc.cn, got, tc.want)
		}
	}
	if cfg.PeerByCertificate(testClientCertificateCN(t, "unlisted")) != nil ||
		cfg.PeerByCertificate([]byte("not a certificate")) != nil {
		t.Fatal("unlisted or invalid certificate incorrectly mapped to a peer")
	}
	if cfg.Peers[0].PushDNS == nil || len(cfg.Peers[0].PushDNS) != 0 ||
		cfg.Peers[1].PushDNS != nil {
		t.Fatal("explicit empty DNS overrides must differ from inherited defaults")
	}
	if got := EffectivePush([]string{"192.0.2.0/24"}, cfg.Peers[0].PushRoutes); len(got) != 1 || got[0] != "10.16.0.0/16" {
		t.Fatalf("peer routes should override tenant defaults: %v", got)
	}
	if got := EffectivePush([]string{"192.0.2.1"}, cfg.Peers[0].PushDNS); len(got) != 0 {
		t.Fatalf("explicit empty DNS should suppress inherited DNS: %v", got)
	}
	if got := EffectivePush([]string{"192.0.2.1"}, cfg.Peers[1].PushDNS); len(got) != 1 {
		t.Fatalf("omitted peer policy should inherit instance defaults: %v", got)
	}
}

func TestRejectAmbiguousOrInvalidCNAndPeerOverrides(t *testing.T) {
	for _, tc := range []struct {
		name  string
		peers []PeerConfig
	}{
		{"duplicate cn", []PeerConfig{
			{ID: "a", CertificateCN: "duplicated", Routes: []string{"10.77.0.2/32"}},
			{ID: "b", CertificateCN: "duplicated", Routes: []string{"10.77.0.3/32"}},
		}},
		{"empty whitespace cn", []PeerConfig{{ID: "site", CertificateCN: " site ", Routes: []string{"10.77.0.2/32"}}}},
		{"mixed pin and cn", []PeerConfig{{ID: "site", CertificateCN: "site", CertificateSHA256: strings.Repeat("a", 64), Routes: []string{"10.77.0.2/32"}}}},
		{"invalid push routes", []PeerConfig{{ID: "site", Routes: []string{"10.77.0.2/32"}, PushRoutes: []string{"broken-cidr"}}}},
		{"invalid push dns", []PeerConfig{{ID: "site", Routes: []string{"10.77.0.2/32"}, PushDNS: []string{"not-a-dns-IP"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if cfg, err := Parse(FileConfig{Peers: tc.peers}); err == nil {
				t.Fatalf("unsafe peer configuration accepted: %+v", cfg)
			}
		})
	}
}

func TestCredentialIdentityPreservedAcrossCNReload(t *testing.T) {
	old, err := Parse(FileConfig{Peers: []PeerConfig{{ID: "site-1", Routes: []string{"10.77.0.2/32"}}}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := Parse(FileConfig{Peers: []PeerConfig{{ID: "site-1", Routes: []string{"192.168.10.0/24"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !old.Peers[0].SameIdentity(updated.Peers[0]) {
		t.Fatal("a route-only reload must not invalidate the same authorized CN")
	}
	other, err := Parse(FileConfig{Peers: []PeerConfig{{ID: "site-1", CertificateCN: "different-cn", Routes: []string{"10.77.0.2/32"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if old.Peers[0].SameIdentity(other.Peers[0]) {
		t.Fatal("changing the authorized certificate CN must revoke the old session")
	}
}
