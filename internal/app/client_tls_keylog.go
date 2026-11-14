package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// openTestTLSKeyLog is an explicitly dangerous, CI-only diagnostic.
// Never enable it in production: anyone holding this file and a WAN
// capture can decrypt the application's TLS/QUIC traffic.
func openTestTLSKeyLog(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	if os.Getenv("MQVPN_UNSAFE_TEST_KEYLOG") != "I_ACKNOWLEDGE_TLS_SECRETS" {
		return nil, errors.New("test TLS key logging requires MQVPN_UNSAFE_TEST_KEYLOG=I_ACKNOWLEDGE_TLS_SECRETS; NEVER use in production")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("test TLS key log must use an absolute path in an isolated private test directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create test-only TLS secrets file exclusively: %w", err)
	}
	return file, nil
}
