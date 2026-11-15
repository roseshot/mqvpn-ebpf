package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTestTLSKeyLogIsDisabledWithoutExplicitConsent(t *testing.T) {
	t.Setenv("MQVPN_UNSAFE_TEST_KEYLOG", "")
	path := filepath.Join(t.TempDir(), "tls.keys")
	file, err := openTestTLSKeyLog(path)
	if err == nil || file != nil {
		t.Fatalf("unsafe TLS logging was allowed without environment gate: file=%v err=%v", file, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unexpected secret file without consent: %v", err)
	}
}

func TestTestTLSKeyLogRequiresExclusivePrivateAbsolutePath(t *testing.T) {
	t.Setenv("MQVPN_UNSAFE_TEST_KEYLOG", "I_ACKNOWLEDGE_TLS_SECRETS")
	if _, err := openTestTLSKeyLog("relative.keylog"); err == nil {
		t.Fatal("relative secret filename accepted")
	}
	path := filepath.Join(t.TempDir(), "tls.keys")
	file, err := openTestTLSKeyLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("TLS secret file mode = %o, want 0600", stat.Mode().Perm())
	}
	if _, err := openTestTLSKeyLog(path); err == nil {
		t.Fatal("existing secret file overwritten or reused")
	}
}
