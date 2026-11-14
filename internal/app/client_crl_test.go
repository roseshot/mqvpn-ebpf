package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTenantCRLIdentity(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client-ca"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "site-1"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ca, caKey, leaf, pool
}

func testSignedClientCRL(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, revoked bool) string {
	t.Helper()
	list := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: time.Now().Add(-time.Minute)},
		}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "clients.crl")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTenantClientCRLValidRevokedAndExpired(t *testing.T) {
	ca, key, leaf, roots := testTenantCRLIdentity(t)
	chain := [][]*x509.Certificate{{leaf, ca}}
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca}, VerifiedChains: chain,
	}
	for _, tc := range []struct {
		name, mode  string
		revoked     bool
		wantFailure bool
	}{
		{"off requires valid mTLS but does not check revocation", "off", true, false},
		{"fresh nonrevoked", "crl", false, false},
		{"revoked serial", "crl", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := loadClientCRL(&ClientRevocationConfig{Mode: tc.mode, CRLFile: ""})
			if tc.mode == "crl" {
				policy, err = loadClientCRL(&ClientRevocationConfig{Mode: tc.mode, CRLFile: testSignedClientCRL(t, ca, key, tc.revoked)})
			}
			if err != nil {
				t.Fatal(err)
			}
			err = verifyClientCertificate(state, roots, policy)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("unexpected CRL policy decision: %v", err)
			}
			if tc.mode == "crl" && !tc.revoked {
				if err := policy.verify(chain, time.Now().Add(2*time.Hour)); err == nil {
					t.Fatal("expired CRL unexpectedly accepted")
				}
				if err := policy.verify(nil, time.Now()); err == nil {
					t.Fatal("CRL not bound to a verified issuer")
				}
			}
		})
	}
	if err := verifyClientCertificate(state, x509.NewCertPool(), nil); err == nil {
		t.Fatal("revocation-off must not bypass Client CA verification")
	}
	if err := verifyClientCertificate(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, roots, nil); err == nil {
		t.Fatal("missing verified chain must not authorize")
	}
}

func TestTenantCRLMustBeSignedByVerifiedIssuer(t *testing.T) {
	_, _, leaf, roots := testTenantCRLIdentity(t)
	otherCA, otherKey, _, _ := testTenantCRLIdentity(t)
	path := testSignedClientCRL(t, otherCA, otherKey, false)
	policy, err := loadClientCRL(&ClientRevocationConfig{Mode: "crl", CRLFile: path})
	if err != nil {
		t.Fatal(err)
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if err := verifyClientCertificate(state, roots, policy); err == nil || !strings.Contains(err.Error(), "no valid direct-issuer CRL") {
		t.Fatalf("wrong issuer CRL authorized: %v", err)
	}
}

func TestClientRevocationConfigStrictModesAndFiles(t *testing.T) {
	for _, tc := range []struct {
		config    ClientRevocationConfig
		wantError bool
	}{
		{ClientRevocationConfig{Mode: "off"}, false},
		{ClientRevocationConfig{Mode: ""}, false},
		{ClientRevocationConfig{Mode: "crl", CRLFile: "clients.crl"}, false},
		{ClientRevocationConfig{Mode: "crl"}, true},
		{ClientRevocationConfig{Mode: "off", CRLFile: "ignored.crl"}, true},
		{ClientRevocationConfig{Mode: "insecure"}, true},
	} {
		inst := sampleInstance("vpn", "vpn.example.test", "mq0")
		inst.ClientRevocation = &tc.config
		cfg := ServerConfig{Instances: []ServerInstance{inst}}
		err := cfg.Validate()
		if (err != nil) != tc.wantError {
			t.Fatalf("config %+v unexpected result: %v", tc.config, err)
		}
	}
	if _, err := loadClientCRL(&ClientRevocationConfig{Mode: "crl", CRLFile: "/missing/this-file.crl"}); err == nil {
		t.Fatal("missing configured CRL accepted")
	}
}
