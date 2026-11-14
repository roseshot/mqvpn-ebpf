//go:build linux

package tcebpf

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

// Precompiled at build time and committed for reproducible, CGO-free
// builds. This object is available without a runtime filesystem dependency.
//
//go:embed objects/tun_tc.o
var embeddedTC []byte

// LoadSpec loads the bundled TC ELF unless an explicit path overrides it.
func LoadSpec(object string) (*ebpf.CollectionSpec, error) {
	if object != "" {
		spec, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			return nil, fmt.Errorf("external TCX ELF %q: %w", object, err)
		}
		return spec, nil
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedTC))
	if err != nil {
		return nil, fmt.Errorf("embedded TCX ELF: %w", err)
	}
	return spec, nil
}
