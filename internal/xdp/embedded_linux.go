//go:build linux

package xdp

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

// Compiled XDP classifier shipped inside the server executable.
//
//go:embed objects/xdp_mqvpn.o
var embeddedXDP []byte

// LoadSpec loads the bundled XDP ELF unless an explicit path overrides it.
func LoadSpec(object string) (*ebpf.CollectionSpec, error) {
	if object != "" {
		spec, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			return nil, fmt.Errorf("external XDP ELF %q: %w", object, err)
		}
		return spec, nil
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedXDP))
	if err != nil {
		return nil, fmt.Errorf("embedded XDP ELF: %w", err)
	}
	return spec, nil
}
