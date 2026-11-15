package app

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// clientCRLPolicy validates a direct, complete CRL issued by the verified
// Client leaf's signing CA. No network fetches, indirect/delta CRLs, or
// fail-open behavior are used. Nil policy means revocation checking disabled,
// never that ordinary Client certificate verification is disabled.
type clientCRLPolicy struct {
	list *x509.RevocationList
}

func loadClientCRL(config *ClientRevocationConfig) (*clientCRLPolicy, error) {
	if config == nil || config.Mode == "off" || config.Mode == "" {
		return nil, nil
	}
	if config.Mode != "crl" {
		return nil, fmt.Errorf("invalid revocation policy %q", config.Mode)
	}
	raw, err := os.ReadFile(config.CRLFile)
	if err != nil {
		return nil, fmt.Errorf("read client CRL: %w", err)
	}
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "X509 CRL" && block.Type != "CRL" {
			return nil, fmt.Errorf("unexpected CRL PEM block %q", block.Type)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("multiple CRL PEM blocks or extra content are not supported")
		}
		raw = block.Bytes
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, fmt.Errorf("parse complete Client CRL: %w", err)
	}
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() ||
		!crl.NextUpdate.After(crl.ThisUpdate) {
		return nil, errors.New("client CRL requires valid thisUpdate and nextUpdate")
	}
	// A delta CRL or scope-limited/indirect list cannot establish the
	// complete revocation status of a Client leaf. Unsupported extensions
	// must fail closed, not silently grant a certificate.
	deltaIndicator := asn1.ObjectIdentifier{2, 5, 29, 27}
	issuingDistributionPoint := asn1.ObjectIdentifier{2, 5, 29, 28}
	freshestCRL := asn1.ObjectIdentifier{2, 5, 29, 46}
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(deltaIndicator) || ext.Id.Equal(issuingDistributionPoint) ||
			ext.Id.Equal(freshestCRL) {
			return nil, fmt.Errorf("unsupported delta or restricted-scope Client CRL extension %s", ext.Id)
		}
		if ext.Critical {
			return nil, fmt.Errorf("unsupported critical Client CRL extension %s", ext.Id)
		}
	}
	return &clientCRLPolicy{list: crl}, nil
}

// verify fails closed when CRL mode is enabled and the direct issuer-signed,
// current complete CRL does not cover the certificate. No HTTP fetch occurs
// during VPN handshake, so an unavailable/stale CRL cannot silently pass.
func (p *clientCRLPolicy) verify(chains [][]*x509.Certificate, now time.Time) error {
	if p == nil {
		return nil
	}
	if now.Before(p.list.ThisUpdate) || !now.Before(p.list.NextUpdate) {
		return errors.New("client CRL is not currently valid; authentication denied")
	}
	var validIssuer bool
	for _, chain := range chains {
		if len(chain) < 2 {
			continue
		}
		leaf, issuer := chain[0], chain[1]
		if !bytes.Equal(p.list.RawIssuer, issuer.RawSubject) ||
			len(p.list.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 &&
				!bytes.Equal(p.list.AuthorityKeyId, issuer.SubjectKeyId) {
			continue
		}
		if err := p.list.CheckSignatureFrom(issuer); err != nil {
			continue
		}
		validIssuer = true
		for _, entry := range p.list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return fmt.Errorf("client certificate serial %s is revoked", leaf.SerialNumber)
			}
		}
	}
	if !validIssuer {
		return errors.New("no valid direct-issuer CRL covers verified Client certificate")
	}
	return nil
}

// verifyClientCertificate is shared by HTTP/3 and TLS/TCP CONNECT handlers.
// Re-verification uses the CURRENT per-tenant CA after a hot reload, preventing
// a long-lived TLS/QUIC connection from retaining privileges after CA changes.
func verifyClientCertificate(state *tls.ConnectionState, ca *x509.CertPool, policy *clientCRLPolicy) error {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return errors.New("verified Client TLS certificate required")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	chains, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: ca, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("Client certificate chain no longer trusted: %w", err)
	}
	return policy.verify(chains, time.Now())
}
