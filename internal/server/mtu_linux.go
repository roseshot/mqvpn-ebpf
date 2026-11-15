//go:build linux

package server

import (
	"github.com/roseshot/mqvpn-ebpf/internal/mtu"
)

func resolveServerInstanceMTU(spec *Instance, links []mtu.Underlay) error {
	result, err := mtu.Plan(spec.TUN, spec.Address, spec.MTU, spec.MaxFrame, links)
	if err != nil {
		return err
	}
	spec.MTU = result.TUNMTU
	spec.MaxFrame = result.MaxFrame
	return nil
}
