package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// eligibleTCPFallback is intentionally conservative. Authentication,
// authorization, SNI/CA errors, HTTP rejection and an established QUIC
// session must never trigger a silent transport downgrade. Only a QUIC
// connection attempt that exhausted its own UDP handshake deadline can
// automatically try the TLS 1.3 TCP transport.
func eligibleTCPFallback(parent, dial context.Context, err error) bool {
	if err == nil || parent.Err() != nil || !errors.Is(dial.Err(), context.DeadlineExceeded) {
		return false
	}
	var verify *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &verify) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return false
	}
	return true
}
