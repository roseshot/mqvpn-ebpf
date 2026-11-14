//go:build linux

package xdp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedXDPCollectionSpec(t *testing.T) {
	if !bytes.HasPrefix(embeddedXDP, []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatal("XDP ELF is not embedded in Go binary")
	}
	spec, err := LoadSpec("")
	if err != nil {
		t.Fatalf("parse embedded XDP ELF: %v", err)
	}
	if err := validateXDPObject(spec); err != nil {
		t.Fatalf("embedded XDP schema invalid: %v", err)
	}
	path := filepath.Join(t.TempDir(), "override.o")
	if err := os.WriteFile(path, embeddedXDP, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSpec(path); err != nil {
		t.Fatalf("external override not loadable: %v", err)
	}
	if _, err := LoadSpec(path + ".missing"); err == nil {
		t.Fatal("invalid external override silently fell back to embedded program")
	}
}
