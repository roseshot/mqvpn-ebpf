//go:build windows

package wintun

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateWintunName(t *testing.T) {
	for _, name := range []string{"mqvpn", "mqvpn-client-1", "Company VPN"} {
		if err := validateName(name); err != nil {
			t.Errorf("%q should be accepted: %v", name, err)
		}
	}
	for _, name := range []string{"", " leading", "trailing ", "a/b", "a\\b", "a\x00b", strings.Repeat("a", 121)} {
		if err := validateName(name); err == nil {
			t.Errorf("unsafe Wintun adapter name accepted: %q", name)
		}
	}
}

func TestWintunLibraryMustBeAbsolute(t *testing.T) {
	if _, err := openLibrary("mqvpn", "wintun.dll"); err == nil {
		t.Fatal("relative Wintun DLL path accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing-wintun.dll")
	if _, err := openLibrary("mqvpn", missing); err == nil || !strings.Contains(err.Error(), "load Wintun") {
		t.Fatalf("missing official DLL should fail without adapter changes: %v", err)
	}
}

func TestWintunInvalidAdapterNameFailsBeforeDLLLoad(t *testing.T) {
	if _, err := openLibrary("../unsafe", "wintun.dll"); err == nil {
		t.Fatal("unsafe adapter name bypassed preflight")
	}
}
