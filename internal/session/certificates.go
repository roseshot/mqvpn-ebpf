package session

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func CertPool(pemFile string) (*x509.CertPool, error) {
	if pemFile == "" {
		return nil, errors.New("a CA certificate file is required")
	}
	b, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", pemFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no PEM certificates in %s", pemFile)
	}
	return pool, nil
}

func KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("a TLS certificate and private key are required for every VPN instance")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS key pair: %w", err)
	}
	return cert, nil
}
